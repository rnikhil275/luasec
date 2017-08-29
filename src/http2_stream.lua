package.path =  package.path .. ';/vagrant/luasec/src/?.lua'

local inspect = require("inspect")
local codec = require("codec")
local h2_error = require('http2_error')
local band = require "http.bit".band
local bor = require "http.bit".bor

-- local new_fifo = require "fifo"

local spack = string.pack or require "compat53.string".pack 
local sunpack = string.unpack or require "compat53.string".unpack 
local unpack = table.unpack or unpack 

local math = require('math')
local socket = require("socket")
local url = require("socket.url")
local ltn12 = require("ltn12")
local mime = require("mime")
local string = require("string")
local headers = require("socket.headers")
local table = require("table")
local ssl = require("ssl")
local basexx = require('basexx')
local try = socket.try

local base = _G
local reqt = {
  url = 'http://nghttp2.org',
  redirect = true,
  target = {},
}
reqt.create = function(reqt) return socket.tcp() end

local default_settings = {
	["HEADER_TABLE_SIZE"] = 4096;
	["ENABLE_PUSH"] = 1;
	["MAX_CONCURRENT_STREAMS"] = 100; -- initial value is unlimited
	["INITIAL_WINDOW_SIZE"] = 65535;
	["MAX_FRAME_SIZE"] = 16384;
	["MAX_HEADER_LIST_SIZE"] = 1000000000;
}

local valid_states = {
	["idle"] = 1; -- initial
	["open"] = 2; -- have sent or received headers; haven't sent body yet
	["reserved (local)"] = 2; -- have sent a PUSH_PROMISE
	["reserved (remote)"] = 2; -- have received a PUSH_PROMISE
	["half closed (local)"] = 3; -- have sent whole body
	["half closed (remote)"] = 3; -- have received whole body
	["closed"] = 4; -- complete
}

local frame_types = {
	[0x0] = "DATA";
	[0x1] = "HEADERS";
	[0x2] = "PRIORITY";
	[0x3] = "RST_STREAM";
	[0x4] = "SETTING";
	[0x5] = "PUSH_PROMISE";
	[0x6] = "PING";
	[0x7] = "GOAWAY";
	[0x8] = "WINDOW_UPDATE";
	[0x9] = "CONTINUATION";
}
for i=0x0, 0x9 do
	frame_types[frame_types[i]] = i
end
-- initialize the module

local _M = {
	USERAGENT = socket._VERSION,
	_VERSION   = "0.6",
	_COPYRIGHT = "LuaSec 0.6 - Copyright (C) 2009-2017 PUC-Rio",
	known_settings = known_settings,
	frame_types = frame_types,

}
-- __index points to emtpy table
local metat = { __index = {} }


-- open a socket

function _M.open(reqt)
	-- create socket with user connect function
	local c = socket.try(reqt:create())   -- method call, passing reqt table as self!
	local h = base.setmetatable({ c = c }, metat)
	-- create finalized try
	h.try = socket.newtry(function() h:close() end)
	-- set timeout before connecting
	h.try(c:settimeout(_M.TIMEOUT))
	h.try(c:connect(reqt.host, reqt.port))
	-- here everything worked
	return h
end

-- adjust headers adding a upgrade request

local function adjustheaders(reqt, encoding)
    -- default headers
    local host = string.gsub(reqt.authority, "^.-@", "")
    local lower = {
        ["User-Agent"] = _M.USERAGENT,
        ["Host"] = host,
        ["Connection"] = "Upgrade, HTTP2-Settings",
        ["Upgrade"] = "h2c",
        ["Http2-Settings"] = encoding
    }
    return lower
end

local function adjustrequest(reqt, encoding)
	-- parse url if provided
	local nreqt = reqt.url and url.parse(reqt.url, default) or {}
	-- explicit components override url
	for i,v in base.pairs(reqt) do nreqt[i] = v end
	nreqt.port = 80
	-- for now, adjust headers for upgrade
	nreqt.headers = adjustheaders(nreqt, encoding)
	return nreqt
end

-- pack the settings table

local function pack_settings_payload(settings)
	local i = 0
	local a = {}
	local function append(k, v)
		a[i*2+1] = k
		a[i*2+2] = v
		i = i + 1
	end

	local HEADER_TABLE_SIZE = settings[0x1]
	if HEADER_TABLE_SIZE == nil then
		HEADER_TABLE_SIZE = settings.HEADER_TABLE_SIZE
	end
	if HEADER_TABLE_SIZE ~= nil then
		append(0x1, HEADER_TABLE_SIZE)
	end
	local ENABLE_PUSH = settings[0x2]
	if ENABLE_PUSH == nil then
		ENABLE_PUSH = settings.ENABLE_PUSH
	end
	if ENABLE_PUSH ~= nil then
		if type(ENABLE_PUSH) == "boolean" then
			ENABLE_PUSH = ENABLE_PUSH and 1 or 0
		end
		append(0x2, ENABLE_PUSH)
		ENABLE_PUSH = ENABLE_PUSH ~= 0
	end
	local MAX_CONCURRENT_STREAMS = settings[0x3]
	if MAX_CONCURRENT_STREAMS == nil then
		MAX_CONCURRENT_STREAMS = settings.MAX_CONCURRENT_STREAMS
	end
	if MAX_CONCURRENT_STREAMS ~= nil then
		append(0x3, MAX_CONCURRENT_STREAMS)
	end
	local INITIAL_WINDOW_SIZE = settings[0x4]
	if INITIAL_WINDOW_SIZE == nil then
		INITIAL_WINDOW_SIZE = settings.INITIAL_WINDOW_SIZE
	end
	if INITIAL_WINDOW_SIZE ~= nil then
		if INITIAL_WINDOW_SIZE >= 2^31 then
			h2_errors.FLOW_CONTROL_ERROR("SETTINGS_INITIAL_WINDOW_SIZE must be less than 2^31")
		end
		append(0x4, INITIAL_WINDOW_SIZE)
	end
	local MAX_FRAME_SIZE = settings[0x5]
	if MAX_FRAME_SIZE == nil then
		MAX_FRAME_SIZE = settings.MAX_FRAME_SIZE
	end
	if MAX_FRAME_SIZE ~= nil then
		if MAX_FRAME_SIZE < 16384 then
			h2_errors.PROTOCOL_ERROR("SETTINGS_MAX_FRAME_SIZE must be greater than or equal to 16384")
		elseif MAX_FRAME_SIZE >= 2^24 then
			h2_errors.PROTOCOL_ERROR("SETTINGS_MAX_FRAME_SIZE must be less than 2^24")
		end
		append(0x5, MAX_FRAME_SIZE)
	end
	local MAX_HEADER_LIST_SIZE = settings[0x6]
	if MAX_HEADER_LIST_SIZE == nil then
		MAX_HEADER_LIST_SIZE = settings.MAX_HEADER_LIST_SIZE
	end
	if MAX_HEADER_LIST_SIZE ~= nil then
		append(0x6, MAX_HEADER_LIST_SIZE)
	end
	local settings_to_merge = {
		HEADER_TABLE_SIZE;
		ENABLE_PUSH;
		MAX_CONCURRENT_STREAMS;
		INITIAL_WINDOW_SIZE;
		MAX_FRAME_SIZE;
		MAX_HEADER_LIST_SIZE;
	}
	return spack(">" .. ("I2 I4"):rep(i), unpack(a, 1, i*2)), settings_to_merge
end

function metat.__index:sendupgraderequest()
	local reqline = string.format("GET / HTTP/1.1\r\n")
	return self.try(self.c:send(reqline))
end

function metat.__index:sendconnectionpreface()
	local reqline = string.format("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	return self.try(self.c:send(reqline))
end


function metat.__index:write_http2_frame(stream_id,frame_types, flags, payload)


	local header = spack(">I3 B B I4", #payload, frame_types, flags, stream_id)
	local test, a, b = self.try(self.c:send(header, 1 , #header))
	--socketsendpayload
	local test, a, b = self.try(self.c:send(payload, 1 , #payload))

    return 1
end

function metat.__index:send_settings_frame(ACK, settings)

	-- flags is for setting the ack bit
	if ACK then 
		if settigns ~= nil then
			return nil, "ack cannot have new setttings"
		end
		local flags = 0x1
		local payload = ""
		local stream_id = 0
		self:write_http2_frame(stream_id, frame_types.SETTING, flags, payload)

	else
		flags = 0
		local payload = pack_settings_payload(default_settings)
		local stream_id = 0
		self:write_http2_frame(stream_id, frame_types.SETTING, flags, payload)
	end	
	


end

function metat.___index:send_window_update_frame()
	local flags = 0
	
	if inc >= 0x80000000 or inc <= 0 then
		h2_errors.PROTOCOL_ERROR("invalid window update increment", true)
	end
	local payload = spack(">I4", inc)
	return self:write_http2_frame(frame_types.WINDOW_UPDATE, flags, payload)
end

function write_window_update(inc, timeout)
	while inc >= 0x80000000 do
		local ok, err, errno = self:write_window_update_frame(0x7fffffff, 0, "f")
		if not ok then
			return nil, err, errno
		end
		inc = inc - 0x7fffffff
	end
	return self:write_window_update_frame(inc, timeout)
end

function metat.___index:set_state(new)
	local new_order = assert(valid_states[new])
	local old = self.state
	if new_order <= valid_states[old] then
		error("invalid state progression ('"..old.."' to '"..new.."')")
	end
	if new ~= "closed" then
		assert(self.id)
	end
	self.state = new
	if new == "closed" or new == "half closed (remote)" then
		self.recv_headers_cond:signal()
		self.chunk_cond:signal()
	end
	if old == "idle" then
		if self.id % 2 == 0 then
			if self.id > self.connection.highest_even_non_idle_stream then
				self.connection.highest_even_non_idle_stream = self.id
			end
		else
			if self.id > self.connection.highest_odd_non_idle_stream then
				self.connection.highest_odd_non_idle_stream = self.id
			end
		end
	end
	if old == "idle" and new ~= "closed" then
		self.connection.n_active_streams = self.connection.n_active_streams + 1
	elseif old ~= "idle" and new == "closed" then
		local n_active_streams = self.connection.n_active_streams - 1
		self.connection.n_active_streams = n_active_streams
		if n_active_streams == 0 then
			self.connection:onidle()(self.connection)
		end
	end
end

function metat.___index:send_goaway_frame()
	if self.id ~= 0 then
		h2_errors.PROTOCOL_ERROR("'GOAWAY' frames MUST be on stream 0")
	end
	if self.connection.send_goaway_lowest and last_streamid > self.connection.send_goaway_lowest then
		h2_errors.PROTOCOL_ERROR("Endpoints MUST NOT increase the value they send in the last stream identifier")
	end
	local flags = 0
	local payload = spack(">I4 I4", last_streamid, err_code)
	if debug_msg then
		payload = payload .. debug_msg
	end
	local ok, err, errno = self:write_http2_frame(frame_types.GOAWAY, flags, payload)
	if not ok then
		return nil, err, errno
	end
	self.connection.send_goaway_lowest = last_streamid
	if flush ~= "f" then
		return self.connection:flush(timeout)
	else
		return true
	end

end
function metat.___index:send_data_frame()
	if self.id == 0 then
		h2_errors.PROTOCOL_ERROR("'DATA' frames MUST be associated with a stream")
	end
	if self.state ~= "open" and self.state ~= "half closed (remote)" then
		h2_errors.STREAM_CLOSED("'DATA' frame not allowed in '" .. self.state .. "' state")
	end
	local pad_len, padding = "", ""
	local flags = 0
	if end_stream then
		flags = bor(flags, 0x1)
	end
	if padded then
		flags = bor(flags, 0x8)
		pad_len = spack("> B", padded)
		padding = ("\0"):rep(padded)
	end
	payload = pad_len .. payload .. padding
	-- The entire DATA frame payload is included in flow control,
	-- including Pad Length and Padding fields if present
	local new_stream_peer_flow_credits = self.peer_flow_credits - #payload
	local new_connection_peer_flow_credits = self.connection.peer_flow_credits - #payload
	if new_stream_peer_flow_credits < 0 or new_connection_peer_flow_credits < 0 then
		h2_errors.FLOW_CONTROL_ERROR("not enough flow credits")
	end
	local ok, err, errno = self:write_http2_frame(frame_types.DATA, flags, payload)
	if not ok then return nil, err, errno end
	self.peer_flow_credits = new_stream_peer_flow_credits
	self.connection.peer_flow_credits = new_connection_peer_flow_credits
	self.stats_sent = self.stats_sent + #payload
	if end_stream then
		if self.state == "half closed (remote)" then
			self:set_state("closed")
		else
			self:set_state("half closed (local)")
		end
	end
	return ok
end
function metat.___index:send_headers_frame()
	self.state ~= "closed" and self.state ~= "half closed (local)"
	if self.id == nil then
		self:pick_id()
	end
	local pad_len, pri, padding = "", "", ""
	local flags = 0
	if end_stream then
		flags = bor(flags, 0x1)
	end
	if end_headers then
		flags = bor(flags, 0x4)
	end
	if padded then
		flags = bor(flags, 0x8)
		pad_len = spack("> B", padded)
		padding = ("\0"):rep(padded)
	end
	if weight or stream_dep then
		flags = bor(flags, 0x20)
		assert(stream_dep < 0x80000000)
		local tmp = stream_dep
		if exclusive then
			tmp = bor(tmp, 0x80000000)
		end
		weight = weight and weight - 1 or 0
		pri = spack("> I4 B", tmp, weight)
	end
	payload = pad_len .. pri .. payload .. padding
	local ok, err, errno = self:write_http2_frame(frame_types.HEADERS, flags, payload)
	if ok == nil then
		return nil, err, errno
	end
	self.stats_sent_headers = self.stats_sent_headers + 1
	if end_headers then
		if end_stream then
			if self.state == "half closed (remote)" or self.state == "reserved (local)" then
				self:set_state("closed")
			else
				self:set_state("half closed (local)")
			end
		else
			if self.state == "idle" then
				self:set_state("open")
			elseif self.state == "reserved (local)" then
				self:set_state("half closed (remote)")
			end
		end
	else
		self.end_stream_after_continuation = end_stream
	end
	return ok
end
function metat.___index:send_rst_stream_frame()
	if self.id == 0 then
		h2_errors.PROTOCOL_ERROR("'RST_STREAM' frames MUST be associated with a stream")
	end
	if self.state == "idle" then
		h2_errors.PROTOCOL_ERROR([['RST_STREAM' frames MUST NOT be sent for a stream in the "idle" state]])
	end
	local flags = 0
	local payload = spack(">I4", err_code)
	local ok, err, errno = self:write_http2_frame(frame_types.RST_STREAM, flags, payload)
	if not ok then return nil, err, errno end
	if self.state ~= "closed" then
		self:set_state("closed")
	end
	self:shutdown()
	return ok
end
function metat.___index:send_push_promise_frame()
end

function metat.___index:send_ping_frame()
	if self.id ~= 0 then
		return nil, "'PING' frames must be on stream id 0"
	end
	if #payload ~= 8 then
		return nil, "'PING' frames must have 8 byte payload"
	end
	local flags = ACK and 0x1 or 0
	return self:write_http2_frame(frame_types.PING, flags, payload)
end

function metat.___index:send_continuation_frame()
	self.state ~= "closed" and self.state ~= "half closed (local)"
	local flags = 0
	if end_headers then
		flags = bor(flags, 0x4)
	end
	local ok, err, errno = self:write_http2_frame(frame_types.CONTINUATION, flags, payload)
	if ok == nil then
		return nil, err, errno
	end
	if end_headers then
		if self.end_stream_after_continuation then
			if self.state == "half closed (remote)" or self.state == "reserved (local)" then
				self:set_state("closed")
			else
				self:set_state("half closed (local)")
			end
		else
			if self.state == "idle" then
				self:set_state("open")
			elseif self.state == "reserved (local)" then
				self:set_state("half closed (remote)")
			end
		end
	else
		self.end_stream_after_continuation = nil
	end
	return ok
end
function metat.___index:send_priority_frame()
	stream_dep < 0x80000000
	if self.id == nil then
		self:pick_id()
	end
	local tmp = stream_dep
	if exclusive then
		tmp = bor(tmp, 0x80000000)
	end
	weight = weight and weight - 1 or 0
	local payload = spack("> I4 B", tmp, weight)
	return self:write_http2_frame(frame_types.PRIORITY, 0, payload)
end



function metat.__index:receiveline()
    local status = self.try(self.c:receive(5))
    
    if status ~= "HTTP/" then return nil, status end
    -- otherwise proceed reading a status line
    -- first line is read here
    status = self.try(self.c:receive("*l", status))
    local code = socket.skip(2, string.find(status, "HTTP/%d*%.%d* (%d%d%d)"))
    return self.try(base.tonumber(code), status)
end

function  metat.__index:receiveheader()
	self.try(self.c:receive(51)) -- clears up the previous unread part
	local header, err = self.try(self.c:receive(9)) -- read the first 9 bytes for header info
	local size, typ, flags, streamid = sunpack(">I3 B B I4", header)

	streamid = band(streamid, 0x7fffffff)
	-- parse the size and then read more to give the payload out
	print(size, typ, flags, streamid)
	local payload , endrr = self.try(self.c:receive(size))
	-- print(payload)

	-- ignore the reserved bit 

	return typ, flags, streamid, payload
end

function metat.__index:sendupgradeheaders(tosend)
    local canonic = headers.canonic
    local h = "\r\n"
    for f, v in base.pairs(tosend) do
        h = (canonic[f] or f) .. ": " .. v .. "\r\n" .. h
    end
    -- print(h)
    self.try(self.c:send(h))
    return 1
end
function metat.__index:close()
	return self.c:close()
end


-- local payload1, settings_to_merge = pack_settings_payload(default_settings)
-- print(payload1, inspect(settings_to_merge))

function trequest(reqt,settings)
	if settings == nil then settings = default_settings end
	local payload = pack_settings_payload(settings)
	local encoding = basexx.to_url64(payload)
	local adjustedreqt = adjustrequest(reqt, encoding)
	-- print(inspect(adjustedreqt))
	local h = _M.open(adjustedreqt)	

	-- this sends the upgrade request and send encoding of the settings payload as part of the upgrade request

	h:sendupgraderequest()
	h:sendupgradeheaders(adjustedreqt.headers)

	-- this receives the 101 switching reply
	local code, status = h:receiveline()
	-- print(code)
	if code == 101 then 
		print('protocol switched')
		-- send connection preface first
		-- while true do
		-- 	local size, typ, flags, streamid = h:receiveframe()
		-- 	-- interpret the settings here 

		-- 	-- use copas dispatcher here
		-- end
		-- print(h:receiveheader())
		h:sendconnectionpreface()
		h:receiveheader()

		-- send settings frame
		h:send_settings_frame(false, default_settings)
		

		-- acknowledge the settings data here
		h:send_settings_frame(true)


	end

	h:close()
	return 1, code, headers, status
end


trequest(reqt)
_M.request = trequest


return 	_M
