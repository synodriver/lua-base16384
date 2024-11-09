local bs = require("base16384")
print(_VERSION)
local encoded = bs.encode("xxxxx")
print(encoded)

print(bs.decode(encoded))

print(bs.encode_len(12))
print(bs.decode_len(12))
print(bs.ENCBUFSZ)
print(bs.DECBUFSZ)
print(bs.FLAG_NOHEADER)
print(bs.FLAG_SUM_CHECK_ON_REMAIN)
print(bs.FLAG_DO_SUM_CHECK_FORCELY)