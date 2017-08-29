--[[
The data returned is of the form 'name', 'code', 'description'. 
]]

local errors = {}

local http_error_methods = {}
local http_error_mt = {
	__name = "http.h2_error";
	__index = http_error_methods;
}

function http_error_mt:__tostring()
	local s = string.format("%s(0x%x): %s", self.name, self.code, self.description)
	if self.message then
		s = s .. ": " .. self.message
	end

	return s
end

function http_error_methods:new(ob)
	return setmetatable({
		name = ob.name or self.name;
		code = ob.code or self.code;
		description = ob.description or self.description;
		message = ob.message;
		stream_error = ob.stream_error or false;
	}, http_error_mt)
end


http_error_mt.__call = http_error_methods.error

-- add a function to replace assert(). check and return error from here. 

local function is(ob)
	return getmetatable(ob) == http_error_mt
end

local function add_error(name, code, description)
	local e = setmetatable({
		name = name;
		code = code;
		description = description;
	}, http_error_mt)
	errors[name] = e
	errors[code] = e
end

-- Taken from https://http2.github.io/http2-spec/#iana-errors

add_error("NO_ERROR",            0x0, "Graceful shutdown")
add_error("PROTOCOL_ERROR",      0x1, "Protocol error detected")
add_error("INTERNAL_ERROR",      0x2, "Implementation fault")
add_error("FLOW_CONTROL_ERROR",  0x3, "Flow control limits exceeded")
add_error("SETTINGS_TIMEOUT",    0x4, "Settings not acknowledged")
add_error("STREAM_CLOSED",       0x5, "Frame received for closed stream")
add_error("FRAME_SIZE_ERROR",    0x6, "Frame size incorrect")
add_error("REFUSED_STREAM",      0x7, "Stream not processed")
add_error("CANCEL",              0x8, "Stream cancelled")
add_error("COMPRESSION_ERROR",   0x9, "Compression state not updated")
add_error("CONNECT_ERROR",       0xa, "TCP connection error for CONNECT method")
add_error("ENHANCE_YOUR_CALM",   0xb, "Processing capacity exceeded")
add_error("INADEQUATE_SECURITY", 0xc, "Negotiated TLS parameters not acceptable")
add_error("HTTP_1_1_REQUIRED",   0xd, "Use HTTP/1.1 for the request")

return {
	errors = errors;
	is = is;
}
