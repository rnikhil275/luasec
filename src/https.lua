----------------------------------------------------------------------------
-- LuaSec 0.6
-- Copyright (C) 2009-2014 PUC-Rio
--
-- Author: Pablo Musa
-- Author: Tomas Guisasola
---------------------------------------------------------------------------

local socket = require("socket")
local ssl    = require("ssl")
local ltn12  = require("ltn12")
local http   = require("ssl.http")
local url    = require("socket.url")
local try    = socket.try
local table  = require("table")

--
-- Module
--
local _M = {
  _VERSION   = "0.6",
  _COPYRIGHT = "LuaSec 0.6 - Copyright (C) 2009-2016 PUC-Rio",
  PORT       = 443,
}

-- TLS configuration
local cfg = {
  protocol = "any",
  options  = {"all", "no_sslv2", "no_sslv3"},
  verify   = "none",
}
--------------------------------------------------------------------
-- Auxiliar Functions
--------------------------------------------------------------------

-- Convert an URL to a table according to Luasocket needs.
local function urlstring_totable(url, body, result_table)
   url = {
      url = url,
      method = body and "POST" or "GET",
      sink = ltn12.sink.table(result_table)
   }
   if body then
      url.source = ltn12.source.string(body)
      url.headers = {
         ["content-length"] = #body,
         ["content-type"] = "application/x-www-form-urlencoded",
      }
   end
   return url
end

-- Forward calls to the real connection object.
local function reg(conn)
   local mt = getmetatable(conn.sock).__index
   for name, method in pairs(mt) do
      if type(method) == "function" then
         conn[name] = function (self, ...)
                         return method(self.sock, ...)
                      end
      end
   end
end

-- Return a function which performs the SSL/TLS connection.
local function tcp(params)
   params = params or {}
   -- Default settings
   for k, v in pairs(cfg) do 
      params[k] = params[k] or v
   end
   -- Force client mode
   params.mode = "client"
   -- upvalue to track https -> http redirection
   local washttps = false
   local tunnel = false
   -- 'create' function for LuaSocket
   return function (reqt)
      local u = url.parse(reqt.url)
      if (reqt.scheme or u.scheme) == "https" then
        if params.proxy then
          washttps = true
          tunnel = true
          return socket.tcp()
        end
        if tunnel then
          print("second chance")
        end
        -- https, provide an ssl wrapped socket
        local conn = {}
        conn.sock = try(socket.tcp())
        local st = getmetatable(conn.sock).__index.settimeout
        function conn:settimeout(...)
           return st(self.sock, ...)
        end
        -- Replace TCP's connection function
        function conn:connect(host, port)
           try(self.sock:connect(host, port))
           self.sock = try(ssl.wrap(self.sock, params))
           self.sock:sni(host)
           try(self.sock:dohandshake())
           reg(self, getmetatable(self.sock))
           return 1
        end
        -- insert https default port, overriding http port inserted by LuaSocket
        if not u.port then
           u.port = _M.PORT
           reqt.url = url.build(u)
           reqt.port = _M.PORT 
        end
        washttps = true
        return conn
      else
        -- regular http, needs just a socket...
        if washttps and params.redirect ~= "all" then
          try(nil, "Unallowed insecure redirect https to http")
        end
        return socket.tcp()
      end  
   end
end

--------------------------------------------------------------------
-- Main Function
--------------------------------------------------------------------

-- Make a HTTP request over secure connection.  This function receives
--  the same parameters of LuaSocket's HTTP module (except 'proxy' and
--  'redirect') plus LuaSec parameters.
--
-- @param url mandatory (string or table)
-- @param body optional (string)
-- @return (string if url == string or 1), code, headers, status
--
local function request(url, body)
  local result_table = {}
  local stringrequest = type(url) == "string"
  if stringrequest then
    --proxy is not possible with stringrequest. so no modification here
    url = urlstring_totable(url, body, result_table)
  end
  -- New 'create' function to establish the proper connection
  url.create = url.create or tcp(url)
  local res, code, headers, status = http.request(url)
  if res and stringrequest then
    return table.concat(result_table), code, headers, status
  end
  return res, code, headers, status
end

_M.request = request
return _M
