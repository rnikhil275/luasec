--------------------------------------------------------------------------------
-- Decode functions

local decode = {}

decode.fields = {}

-- Decode boolean (field t)
decode.bool = function(buf, pos)
  local value
  value, pos = string.unpack("B", buf, pos)
  return (value ~= 0), pos
end

-- Decode int8 (field b) 
decode.int8 = function(buf, pos)
  return string.unpack("b", buf, pos)
end

-- Decode uint8 (field B)
decode.uint8 = function(buf, pos)
  return string.unpack("B", buf, pos)
end

-- Decode int16 BE (field u)
decode.int16 = function(buf, pos)
  return string.unpack(">h", buf, pos)
end

-- Decode uint16 BE (field U)
decode.uint16 = function(buf, pos)
  return string.unpack(">H", buf, pos)
end

-- Decode int32 BE (field i)
decode.int32 = function(buf, pos)
  return string.unpack(">i4", buf, pos)
end

-- Decode uint32 BE (field I)
decode.uint32 = function(buf, pos)
  return string.unpack(">I4", buf, pos)
end

-- Decode int64 BE (field l)
decode.int64 = function(buf, pos)
  return string.unpack(">i8", buf, pos)
end

-- Decode uint64 BE (field L)
decode.uint64 = function(buf, pos)
  return string.unpack(">I8", buf, pos)
end

-- Decode float (field f)
decode.float = function(buf, pos)
  return string.unpack("f", buf, pos)
end

-- Decode double (field d)
decode.double = function(buf, pos)
  return string.unpack("d", buf, pos)
end

-- Decode decimal (field D)
-- Return a table with fields 'value' and 'scale'
decode.decimal = function(buf, pos)
  local scale, value
  scale, value, pos = string.unpack(">BI4", buf, pos)
  return {value = value, scale = scale}, pos
end

-- Decode short string (field s)
-- uint8 (length) + string
decode.sstr = function(buf, pos)
  return string.unpack("s1", buf, pos)
end

-- Decode long string (field S)
-- uint32 (length) + string
decode.lstr = function(buf, pos)
  return string.unpack(">s4", buf, pos)
end

-- Decode array (field A)
-- uint32 (length) + data
decode.array = function(buf, pos)
  local array = {}
  local size, pos = string.unpack(">I4", buf, pos)
  for i = 1, size do
    local kind = string.unpack("c1", buf, pos)
    array[#array+1], pos = decode.fields[kind](buf, pos)
  end
end

-- Decode null (field V)
decode.null = function(buf, pos)
  return nil, pos
end

-- Decode timestemp (field T)
decode.timestamp = function(buf, pos)
  return string.unpack(">I8", buf, pos)
end

-- Decode table (field F)
decode.table = function(buf, pos)
  local tmp = 1
  local tb  = {}
  local data, field, kind, value
  data, pos = string.unpack(">s4", buf, pos)
  while tmp < #data do
    field, kind, tmp = string.unpack(">s1c1", data, tmp)
    value, tmp = decode.fields[kind](data, tmp)
    tb[field] = value
  end
  return tb, pos
end

decode.fields.t = decode.bool
decode.fields.b = decode.int8
decode.fields.B = decode.uint8
decode.fields.u = decode.int16
decode.fields.U = decode.uint16
decode.fields.i = decode.int32
decode.fields.I = decode.uint32
decode.fields.l = decode.int64
decode.fields.L = decode.uint32
decode.fields.f = decode.float
decode.fields.d = decode.double
decode.fields.D = decode.decimal
decode.fields.s = decode.sstr
decode.fields.S = decode.lstr
decode.fields.A = decode.array
decode.fields.V = decode.null
decode.fields.T = decode.timestamp
decode.fields.F = decode.table

--------------------------------------------------------------------------------
-- Encode functions

local encode = {}

encode.fields = {}

-- Encode uint8 (field B)
encode.uint8 = function(n)
  return string.pack("B", n)
end

-- Encode uint16 BE (field U)
encode.uint16 = function(n)
  return string.pack(">H", n)
end

-- Encode uint32 BE (field I)
encode.uint32 = function(n)
  return string.pack(">I4", n)
end

-- Encode uint64 BE (field L)
encode.uint64 = function(n)
  return string.pack(">I8", n)
end

-- Encode table (field F)
encode.table = function(tb)
  local str = ''
  for k, v in pairs(tb) do
    str = str .. string.pack(">s1c1s4", k, 'S', v)
  end
  return string.pack(">s4", str)
end

-- Encode short string (field s)
encode.sstr = function(str)
  return string.pack("s1", str)
end

-- Encode long string (field S)
encode.lstr = function(str)
  return string.pack(">s4", str)
end

--------------------------------------------------------------------------------
-- Module

return {
  encode = encode,
  decode = decode
}
