package.path =  package.path .. ';/vagrant/luasec/src/?.lua'

local inspect = require("inspect")
local codec = require("codec")

-- local band = require "http.bit".band
-- local bor = require "http.bit".bor

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


function metat.__index:send_http2_frame(stream_id,frame_types, flags, payload)
	-- flags is a table you get
	-- second type of frame - 8
	-- fourth reserved bit( 1 bit length)
	-- stream id -31
	-- frame payload - payload length as above
	
	print(stream_id,frame_types, flags, payload)
	--send this first

	local header = spack(">I3 B B I4", #payload, frame_types, flags, stream_id)
	local test, a, b = self.try(self.c:send(header, 1 , #header))
	-- print(test, a, b)
	--socketsendpayload
	local test, a, b = self.try(self.c:send(payload, 1 , #payload))

    -- local canonic = headers.canonic
    -- local h = "\r\n"
    -- for f, v in base.pairs(tosend) do
    --     h = (canonic[f] or f) .. ": " .. v .. "\r\n" .. h
    -- end
    -- self.try(self.c:send(h))
    return 1
end
function metat.__index:send_settings_frame(ACK, settings)

	-- print(inspect(self))

	-- flags is for setting the ack bit
	if ACK then 
		if settigns ~= nil then
			return nil, "ack cannot have new setttings"
		end
		local flags = 0x1
		local payload = ""
		local stream_id = 0
		self:send_http2_frame(stream_id, frame_types.SETTING, flags, payload)

	else
		flags = 0
		local payload = pack_settings_payload(default_settings)
		local stream_id = 0
		self:send_http2_frame(stream_id, frame_types.SETTING, flags, payload)
	end	
	


end

function metat.__index:receiveline()
    -- identify HTTP/0.9 responses, which do not contain a status line
    -- this is just a heuristic, but is what the RFC recommends
    if status ~= "HTTP/" then return nil, status end
    -- otherwise proceed reading a status line
    status = self.try(self.c:receive("*l", status))
    -- print(status)
    local code = socket.skip(2, string.find(status, "HTTP/%d*%.%d* (%d%d%d)"))
    -- print(code)
    return self.try(base.tonumber(code), status)
end

function  metat.__index:receiveframe()
	local header, err = self.try(self.c:receive(72)) -- read 9 octets
	local size, typ, flags, streamid = sunpack(">I3 B B I4", headers)

	-- parse the size and then read more to give the payload out

	return size, typ, flags, streamid 
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

function trequest(reqt, default_settings)
	local payload = pack_settings_payload(default_settings)
	local encoding = basexx.to_url64(payload)
	local adjustedreqt = adjustrequest(reqt, encoding)
	-- print(inspect(adjustedreqt))
	local h = _M.open(adjustedreqt)	

	-- this sends the upgrade request	
	h:sendupgraderequest()
	h:sendupgradeheaders(adjustedreqt.headers)

	-- this receives the 101 switching reply
	local code, status = h:receiveline()
	if code == 101 then 
		-- send connection preface first
		while true do
			local size, typ, flags, streamid = h:receiveframe()
			-- interpret the settings here 

			-- use copas dispatcher here
		end


		h:sendconnectionpreface()

		-- send settings frame
		h:send_settings_frame(false, default_settings)


		-- acknowledge the settings data here
		-- h:send_settings_frame(true)


	end

	h:close()
	return 1, code, headers, status
end
trequest(reqt, default_settings)
_M.request = trequest


return _M
