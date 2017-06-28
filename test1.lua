local https = require("ssl.https")
-- just a tool for quickly printing tables
local inspect = require("inspect")
local result_table = {}

local function doreq(url)
	local reqt = {
	  url = url,
	  redirect = true,
	  -- unsaferedirect = true,     --> allows https-> http redirect
	  target = {},
	  proxy = "http://172.28.128.1:4444",
	}
	reqt.sink = ltn12.sink.table(result_table)

	local result, code, headers, status = https.request(reqt)
	print("Fetching:",url,"==>",code, status)
	if result then for k,v in pairs(headers) do print("",k,v) end end
	-- print(result)
	-- print(type(result))
	print(inspect(result_table))

	return result, code, headers, status
end

-- local result, code, headers, status = doreq("http://example.com")--simple http 
-- local result, code, headers, status = doreq("http://goo.gl/tBfqNu") -- http --> http redirect

-- local result, code, headers, status = doreq("https://rnikhil275.github.io") --simple https
-- local result, code, headers, status = doreq("https://goo.gl/UBCUc5")  -- https --> https redirect

-- local result, code, headers, status = doreq("http://goo.gl/UBCUc5")  -- http --> https redirect
-- local result, code, headers, status = doreq("https://goo.gl/tBfqNu")  -- https --> http security test case 



