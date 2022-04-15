local bs = require("base16384")

local encoded = bs.encode("xxxxx")
print(encoded)

print(bs.decode(encoded))

print(bs.encode_len(12))
print(bs.decode_len(12))
