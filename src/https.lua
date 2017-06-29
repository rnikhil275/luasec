-----------------------------------------------------------------------------
-- HTTP/1.1 client support for the Lua language.
-- LuaSocket toolkit.
-- Author: Diego Nehab
-----------------------------------------------------------------------------

-----------------------------------------------------------------------------
-- Declare module and import dependencies
-------------------------------------------------------------------------------
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
-----------------------------------------------------------------------------
-- Program constants and the module
-----------------------------------------------------------------------------
local _M = {
    TIMEOUT = 60,
    PORT = 80,
    SSLPORT = 443,
    USERAGENT = socket._VERSION,
    _VERSION   = "0.6",
    _COPYRIGHT = "LuaSec 0.6 - Copyright (C) 2009-2016 PUC-Rio",
}
-- TLS configuration
local cfg = {
  protocol = "any",
  options  = {"all", "no_sslv2", "no_sslv3"},
  verify   = "none",
}
-----------------------------------------------------------------------------
-- Reads MIME headers from a connection, unfolding where needed
-----------------------------------------------------------------------------
local function receiveheaders(sock, headers)
    local line, name, value, err
    headers = headers or {}
    -- get first line
    line, err = sock:receive()
    if err then return nil, err end
    -- headers go until a blank line is found
    while line ~= "" do
        -- get field-name and value
        name, value = socket.skip(2, string.find(line, "^(.-):%s*(.*)"))
        if not (name and value) then return nil, "malformed reponse headers" end
        name = string.lower(name)
        -- get next line (value might be folded)
        line, err  = sock:receive()
        if err then return nil, err end
        -- unfold any folded values
        while string.find(line, "^%s") do
            value = value .. line
            line , err = sock:receive()
            if err then return nil, err end
        end
        -- save pair in table
        if headers[name] then headers[name] = headers[name] .. ", " .. value
        else headers[name] = value end
    end
    return headers
end

-----------------------------------------------------------------------------
-- Extra sources and sinks
-----------------------------------------------------------------------------
socket.sourcet["http-chunked"] = function(sock, headers)
    return base.setmetatable({
        getfd = function() return sock:getfd() end,
        dirty = function() return sock:dirty() end
    }, {
        __call = function()
            -- get chunk size, skip extention
            local line, err = sock:receive()
            if err then return nil, err end
            local size = base.tonumber(string.gsub(line, ";.*", ""), 16)
            if not size then return nil, "invalid chunk size" end
            -- was it the last chunk?
            if size > 0 then
                -- if not, get chunk and skip terminating CRLF
                local chunk, err = sock:receive(size)
                if chunk then sock:receive() end
                return chunk, err
            else
                -- if it was, read trailers into headers table
                headers, err = receiveheaders(sock, headers)
                if not headers then return nil, err end
            end
        end
    })
end

socket.sinkt["http-chunked"] = function(sock)
    return base.setmetatable({
        getfd = function() return sock:getfd() end,
        dirty = function() return sock:dirty() end
    }, {
        __call = function(self, chunk, err)
            if not chunk then return sock:send("0\r\n\r\n") end
            local size = string.format("%X\r\n", string.len(chunk))
            return sock:send(size ..  chunk .. "\r\n")
        end
    })
end

-----------------------------------------------------------------------------
-- Low level HTTP API
-----------------------------------------------------------------------------
local metat = { __index = {} }

function _M.open(reqt)
    -- create socket with user connect function
     local c = socket.try(reqt:create())   -- method call, passing reqt table as self!
    local h = base.setmetatable({ c = c }, metat)
    -- create finalized try
    h.try = socket.newtry(function() h:close() end)
    -- set timeout before connecting
    h.try(c:settimeout(_M.TIMEOUT))
    h.try(c:connect(reqt.host, reqt.port or _M.PORT))
    -- here everything worked
    return h
end
function metat.__index:sendrequestline(method, uri)
    local reqline = string.format("%s %s HTTP/1.1\r\n", method or "GET", uri)
    return self.try(self.c:send(reqline))
end
 
function metat.__index:sendheaders(tosend)
    local canonic = headers.canonic
    local h = "\r\n"
    for f, v in base.pairs(tosend) do
        h = (canonic[f] or f) .. ": " .. v .. "\r\n" .. h
    end
    self.try(self.c:send(h))
    return 1
end

function metat.__index:sendbody(headers, source, step)
    source = source or ltn12.source.empty()
    step = step or ltn12.pump.step
    -- if we don't know the size in advance, send chunked and hope for the best
    local mode = "http-chunked"
    if headers["content-length"] then mode = "keep-open" end
    return self.try(ltn12.pump.all(source, socket.sink(mode, self.c), step))
end

function metat.__index:receivestatusline()
    local status = self.try(self.c:receive(5))
    -- identify HTTP/0.9 responses, which do not contain a status line
    -- this is just a heuristic, but is what the RFC recommends
    if status ~= "HTTP/" then return nil, status end
    -- otherwise proceed reading a status line
    status = self.try(self.c:receive("*l", status))
    local code = socket.skip(2, string.find(status, "HTTP/%d*%.%d* (%d%d%d)"))
    return self.try(base.tonumber(code), status)
end

function metat.__index:receiveheaders()
    return self.try(receiveheaders(self.c))
end

function metat.__index:receivebody(headers, sink, step)
    sink = sink or ltn12.sink.null()
    step = step or ltn12.pump.step
    local length = base.tonumber(headers["content-length"])
    local t = headers["transfer-encoding"] -- shortcut
    local mode = "default" -- connection close
    if t and t ~= "identity" then mode = "http-chunked"
    elseif base.tonumber(headers["content-length"]) then mode = "by-length" end
    return self.try(ltn12.pump.all(socket.source(mode, self.c, length),
        sink, step))
end

function metat.__index:receive09body(status, sink, step)
    local source = ltn12.source.rewind(socket.source("until-closed", self.c))
    source(status)
    return self.try(ltn12.pump.all(source, sink, step))
end

function metat.__index:close()
    return self.c:close()
end

-----------------------------------------------------------------------------
-- High level HTTP API
-----------------------------------------------------------------------------
local function adjusturi(reqt)
    local u = reqt
    -- if there is a proxy, we need the full url. otherwise, just a part.
    if not reqt.proxy and not _M.PROXY then
        u = {
           path = socket.try(reqt.path, "invalid path 'nil'"),
           params = reqt.params,
           query = reqt.query,
           fragment = reqt.fragment
        }
    end
    return url.build(u)
end


local function adjustheaders(reqt)
    -- default headers
    local host = string.gsub(reqt.authority, "^.-@", "")
    local lower = {
        ["user-agent"] = _M.USERAGENT,
        ["host"] = host,
        ["connection"] = "close, TE",
        ["te"] = "trailers"
    }
    -- if we have authentication information, pass it along
    if reqt.user and reqt.password then
        lower["authorization"] =
            "Basic " ..  (mime.b64(reqt.user .. ":" ..
        url.unescape(reqt.password)))
    end
    local proxy = reqt.proxy or _M.PROXY
    if proxy then
        proxy = url.parse(proxy)
        if proxy.user and proxy.password then
            lower["proxy-authorization"] =
                "Basic " ..  (mime.b64(proxy.user .. ":" .. proxy.password))
        end
        -- keep the connection alive to open a tunnel
        if reqt.connectproxy then
            lower['connection'] = 'keep-alive'
            lower["Proxy-Connection"]="keep-alive"
        end
    end
    -- override with user headers
    for i,v in base.pairs(reqt.headers or lower) do
        lower[string.lower(i)] = v
    end
    return lower
end

-- default url parts
local default = {
    host = "",
    port = _M.PORT,
    path ="/",
    scheme = "http"
}
local function adjustproxy(reqt)
    local proxy = reqt.proxy or _M.PROXY
    if proxy then
        proxy = url.parse(proxy)
        return proxy.host, proxy.port or 3128
    else
        return reqt.host, reqt.port
    end
end

local function adjustrequest(reqt)
    -- parse url if provided
    local nreqt = reqt.url and url.parse(reqt.url, default) or {}
    -- explicit components override url
    for i,v in base.pairs(reqt) do nreqt[i] = v end
    if nreqt.port == "" then nreqt.port = _M.PORT end
    socket.try(nreqt.host and nreqt.host ~= "", 
        "invalid host '" .. base.tostring(nreqt.host) .. "'")
    -- compute uri if user hasn't overriden
    if reqt.connectproxy then
        -- connect proxy has special needs for uri in connect request
        if url.parse(reqt.url, default).scheme == "https" then
            nreqt.uri = reqt.uri or nreqt.authority .. ":" .. _M.SSLPORT
        else
            nreqt.uri = reqt.uri or nreqt.authority .. ":" .. _M.PORT
        end
    else
        nreqt.uri = reqt.uri or adjusturi(nreqt)
    end   
    -- ajust host and port if there is a proxy
    nreqt.host, nreqt.port = adjustproxy(nreqt)
    -- adjust headers in request
    nreqt.headers = adjustheaders(nreqt)
    return nreqt
end



local function shouldredirect(reqt, code, headers)
    return headers.location and
           string.gsub(headers.location, "%s", "") ~= "" and
           (reqt.redirect ~= false) and
           (code == 301 or code == 302 or code == 303 or code == 307) and
           (not reqt.method or reqt.method == "GET" or reqt.method == "HEAD")
           and (not reqt.nredirects or reqt.nredirects < 5)
end

local function shouldreceivebody(reqt, code)
    if reqt.method == "HEAD" then return nil end
    if code == 204 or code == 304 then return nil end
    if code >= 100 and code < 200 then return nil end
    return 1
end
-- forward declarations
local trequest, tredirect

--[[local]] function tredirect(reqt, location)
    if reqt.connectredirect == true then
        local result, code, headers, status = trequest {
            -- the RFC says the redirect URL has to be absolute, but some
            -- servers do not respect that
            url = url.absolute(reqt.url, location),
            source = reqt.source,
            sink = reqt.sink,
            headers = reqt.headers,
            proxy = reqt.proxy, 
            nredirects = (reqt.nredirects or 0) + 1,
            create = reqt.create,
            connectproxy = true,
            protocol = "any",
            options  = {"all", "no_sslv2", "no_sslv3"},
            verify   = "none",
            mode = "client"
        }
    elseif reqt.connectredirect == false then
        local result, code, headers, status = trequest {
            -- the RFC says the redirect URL has to be absolute, but some
            -- servers do not respect that
            url = url.absolute(reqt.url, location),
            source = reqt.source,
            sink = reqt.sink,
            headers = reqt.headers,
            proxy = reqt.proxy, 
            nredirects = (reqt.nredirects or 0) + 1,
            create = reqt.create,
            connectproxy = reqt.connectproxy
        }
    end
    -- pass location header back as a hint we redirected
    headers = headers or {}
    headers.location = headers.location or location
    return result, code, headers, status
end
-- forward calls to connection object
local function reg(conn)
   local mt = getmetatable(conn.c).__index
   for name, method in pairs(mt) do
      if type(method) == "function" then
         conn[name] = function (self, ...)
                        return method(self.c, ...)
                      end
      end
   end
end
--[[local]] function trequest(reqt)
    -- we loop until we get what we want, or
    -- until we are sure there is no way to get it
    nreqt = adjustrequest(reqt)
    local h = _M.open(nreqt)
    if  reqt.connectproxy then
        nreqt.method = "CONNECT"
        h:sendrequestline(nreqt.method, nreqt.uri)
        h:sendheaders(nreqt.headers)
        local code, status = h:receivestatusline()       
        local headers = h:receiveheaders()
        if code == 200 then            
            if url.parse(reqt.url, default).scheme == "https" then
                washttps = true
                -- the tunnel is established and we wrap the socket for https requests
                h.c = h.try(ssl.wrap(h.c, nreqt))
                h.try(h.c:dohandshake())
                reg(h, getmetatable(h.c))
            end
            -- these go through the tunnel
            nreqt.method = "GET"
            -- replace host and port so that requests go normally through tunnel
            nreqt.host, nreqt.port = reqt.host,reqt.port
            nreqt.uri = adjusturi(nreqt)
        else
            return nil, "Problem in establishing tunnel"
        end
    end
    h:sendrequestline(nreqt.method, nreqt.uri)
    h:sendheaders(nreqt.headers)

    -- if there is a body, send it
    if nreqt.source then
        h:sendbody(nreqt.headers, nreqt.source, nreqt.step) 
    end
    local code, status = h:receivestatusline()
    -- set the reqt.connectredirect variable to be used in the redirect function
    if code == 301 and reqt.connectproxy == true then 
        reqt.connectredirect = true
    else
        reqt.connectredirect = false
    end
    -- if it is an HTTP/0.9 server, simply get the body and we are done
    if not code then
        h:receive09body(status, nreqt.sink, nreqt.step)
        return 1, 200
    end
    local headers
    -- ignore any 100-continue messages
    while code == 100 do 
        headers = h:receiveheaders()
        code, status = h:receivestatusline()
    end
    headers = h:receiveheaders()
    -- at this point we should have a honest reply from the server
    -- we can't redirect if we already used the source, so we report the error 

    if shouldredirect(nreqt, code, headers) and not nreqt.source then
        if washttps and reqt.unsaferedirect ~=true and url.parse(headers.location,default).scheme == "http" then
          return nil, "Unsafe redirects from HTTPS to HTTP not allowed"
        else
          if not washttps and url.parse(headers.location, default).scheme == "https" and reqt.proxy then
            reqt.connectredirect = true
          end
          h:close()
          return tredirect(reqt, headers.location)
        end
    end
    -- here we are finally done
    if shouldreceivebody(nreqt, code) then
        h:receivebody(headers, nreqt.sink, nreqt.step)
    end
    h:close()
    return 1, code, headers, status
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
   -- 'create' function for LuaSocket
   return function (reqt)
      local u = url.parse(reqt.url)
      if (reqt.scheme or u.scheme) == "https" then
        if reqt.connectproxy then
          --give a normal socket for now. wrap it later if proxy responds and scheme is https
          -- if scheme is not https then http.lua will use the normal proxy itself. 
          return socket.tcp()
        end
        -- https, provide an ssl wrapped socket
        local conn = {}
        conn.c = try(socket.tcp())
        local st = getmetatable(conn.c).__index.settimeout
        function conn:settimeout(...)
           return st(self.c, ...)
        end
        -- Replace TCP's connection function
        function conn:connect(host, port)
           try(self.c:connect(host, port))
           self.c = try(ssl.wrap(self.c, params))
           self.c:sni(host)
           try(self.c:dohandshake())
           reg(self, getmetatable(self.c))
           return 1
        end
        -- insert https default port, overriding http port inserted by LuaSocket
        if not u.port then
           u.port = _M.SSLPORT
           reqt.url = url.build(u)
           reqt.port = _M.SSLPORT 
        end
        washttps = true
        return conn
      else
        -- regular http, needs just a socket...
        if washttps and params.unsaferedirect ~= true then
          try(nil, "Unsafe redirects from HTTPS to HTTP not allowed")
        end
        return socket.tcp()
      end  
   end
end


-- parses a shorthand form into the advanced table form.
-- adds field `target` to the table. This will hold the return values.
_M.parseRequest = function(u, b)
    local t = {}
    local reqt = {
        url = u,
        sink = ltn12.sink.table(t),
        target = t,
    }
    if b then
        reqt.source = ltn12.source.string(b)
        reqt.headers = {
            ["content-length"] = string.len(b),
            ["content-type"] = "application/x-www-form-urlencoded"
        }
        reqt.method = "POST"
    end
    return reqt
end

_M.request = socket.protect(function(reqt, body)
    if base.type(reqt) == "string" then 
      reqt = _M.parseRequest(reqt, body)
      local t, code, headers, status = reqt.target, socket.skip(1, _M.request(reqt))
      return table.concat(t), code, headers, status
    else
      if reqt.proxy then
        if socket.url.parse(reqt.url, default).scheme == "https" then
          reqt.connectproxy = true
        end
      end   
      reqt.create = reqt.create or tcp(reqt)
      return trequest(reqt) 
    end
end)

return _M
