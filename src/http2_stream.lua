local inspect = require("inspect")

local band = require "http.bit".band
local bor = require "http.bit".bor
local new_fifo = require "fifo"
local spack = string.pack or require "compat53.string".pack 
local sunpack = string.unpack or require "compat53.string".unpack 
local unpack = table.unpack or unpack 

local socket = require("socket")
local url = require("socket.url")
local ltn12 = require("ltn12")
local mime = require("mime")
local string = require("string")
local headers = require("socket.headers")
local base = _G
local table = require("table")
local ssl = require("ssl")
local try = socket.try


local settings_table = {
  [1] = "HEADER_TABLE_SIZE",
  [2] = "ENABLE_PUSH",
  [3] = "MAX_CONCURRENT_STREAMS",
  [4] = "INITIAL_WINDOW_SIZE",
  [5] = "MAX_FRAME_SIZE",
  [6] = "MAX_HEADER_LIST_SIZE",
}

local frame_types = {
	[1] = "DATA",
	[2] = "HEADERS",
	[3] = "PRIORITY",
	[4] = "RST_STREAM",
	[5] = "SETTING",
	[6] = "PUSH_PROMISE",
	[7] = "PING",
	[8] = "GOAWAY",
	[9] = "WINDOW_UPDATE",
	[9] = "CONTINUATION",
}

local _M = {
	USERAGENT = socket._VERSION,
	_VERSION   = "0.6",
	_COPYRIGHT = "LuaSec 0.6 - Copyright (C) 2009-2017 PUC-Rio",
	known_settings = known_settings,
	frame_types = frame_types,

}
local metat = { __index = {} }


local reqt = {
  url = 'http://nghttp2.org',
  redirect = true,
  target = {},
}
reqt.create = function(reqt) return socket.tcp() end

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

local function adjustheaders(reqt)
    -- default headers
    local host = string.gsub(reqt.authority, "^.-@", "")
    local lower = {
        ["User-Agent"] = _M.USERAGENT,
        ["Host"] = host,
        ["Connection"] = "Upgrade, HTTP2-Settings",
        ["Upgrade"] = "h2c",
        ["Http2-Settings"] = ""
    }
    return lower
end

function metat.__index:sendupgraderequest(host, settings)
	local reqline = string.format("GET / HTTP/1.1\r\n")
	return self.try(self.c:send(reqline))
end
function metat.__index:sendconnectionpreface()
	local reqline = string.format("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
	return self.try(self.c:send(reqline))
end
function metat.__index:sendupgradeheaders(tosend)
    local canonic = headers.canonic
    local h = "\r\n"
    for f, v in base.pairs(tosend) do
        h = (canonic[f] or f) .. ": " .. v .. "\r\n" .. h
    end
    print(h)
    self.try(self.c:send(h))
    return 1
end
function metat.__index:sendheaderframe(tosend)
    local canonic = headers.canonic
    local h = "\r\n"
    for f, v in base.pairs(tosend) do
        h = (canonic[f] or f) .. ": " .. v .. "\r\n" .. h
    end
    self.try(self.c:send(h))
    return 1
end

function metat.__index:receiveframe()
    local status = self.try(self.c:receive(5))
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

function metat.__index:close()
	return self.c:close()
end

local function adjustrequest(reqt)
	-- parse url if provided
	local nreqt = reqt.url and url.parse(reqt.url, default) or {}
	-- explicit components override url
	for i,v in base.pairs(reqt) do nreqt[i] = v end
	nreqt.port = 80
	-- for now, adjust headers for upgrade
	nreqt.headers = adjustheaders(nreqt)
	return nreqt
end
local function forwardcall(conn)
   local mt = getmetatable(conn.c).__index
   for name, method in pairs(mt) do
      if type(method) == "function" then
         conn[name] = function (self, ...)return method(self.c, ...) end
      end
   end
end

function trequest(reqt)
	local adjustedreqt = adjustrequest(reqt)
	-- print(inspect(adjustedreqt))
	local h = _M.open(adjustedreqt)	

	-- this sends the upgrade request	
	h:sendupgraderequest()
	h:sendupgradeheaders(adjustedreqt.headers)

	-- this receives the 101 switching reply
	local code, status = h:receiveframe()
	if code == 101 then 
		print('it works')
		-- start sending setting packets and other relevant frames
		-- first the connection preface
		h:sendconnectionpreface()
		-- then the settings frame
	end

	h:close()
	return 1, code, headers, status
end

-- local _, _, h, _ = trequest(reqt)
-- print(inspect(reqt))
trequest(reqt)

-- return _M
