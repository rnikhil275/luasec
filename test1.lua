local https = require("ssl.https")

local function doreq(url)
	local reqt = {
	  url = url,
	  unsaferedirect = true,     --> allows https-> http redirect
	  target = {},
	  -- proxy = "http://172.28.128.1:4444",
	  -- connectproxy = 'true',
	}
	reqt.sink = ltn12.sink.table(reqt.target)

	local result, code, headers, status = https.request(reqt)
	print("Fetching:",url,"==>",code, status)
	-- if headers then for k,v in pairs(headers) do print("",k,v) end end
	-- print(result)

	return result, code, headers, status
end

-- local result, code, headers, status = doreq("https://icanhazip.com/")
local result, code, headers, status = doreq("https://goo.gl/tBfqNu")  

