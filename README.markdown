<h1 align="center"><i>✨ lua-base16384 ✨ </i></h1>

<h3 align="center">The lua binding for <a href="https://github.com/fumiama/base16384">base16384</a> </h3>


### 使用
```lua
local bs = require("base16384")

local encoded = bs.encode("xxxxx")
print(encoded)

print(bs.decode(encoded))

print(bs.encode_len(12))
print(bs.decode_len(12))
```