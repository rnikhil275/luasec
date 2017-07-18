local inspect = require("inspect")


local socket = require("socket")
local url = require("socket.url")
local ssl = require("ssl")


local known_settings = {
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
    _COPYRIGHT = "LuaSec 0.6 - Copyright (C) 2009-2016 PUC-Rio",
    known_settings = known_settings,
    frame_types = frame_types,

}

local function makeFrame( )
	-- body
end







-- return _M
