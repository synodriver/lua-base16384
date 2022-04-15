#include "lua.h"
#include "lauxlib.h"

#include "base14.h"

#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport)
#elif
#define DLLEXPORT
#endif /* _WIN32 */


static int lencode_len(lua_State *L)
{
    int dlen = (int) luaL_checkinteger(L, 1);
    lua_pushinteger(L, (lua_Integer) encode_len(dlen));
    return 1;
}

static int ldecode_len(lua_State *L)
{
    int dlen = (int) luaL_checkinteger(L, 1);
    lua_pushinteger(L, (lua_Integer) decode_len(dlen, 0));
    return 1;
}


static int lencode(lua_State *L)
{
    size_t len = 0;
    const char *data = luaL_checklstring(L, 1, &len);
    size_t bufflen = (size_t) encode_len((int) len) + 16;
    void *buffer = lua_newuserdata(L, bufflen);
    int encoded = encode(data, (int) len, (char *) buffer, (int) bufflen);
    lua_pushlstring(L, (char *) buffer, (size_t)encoded);
    return 1;
}

static int ldecode(lua_State *L)
{
    size_t len = 0;
    const char *data = luaL_checklstring(L, 1, &len);
    size_t bufflen = (size_t) decode_len((int) len, 0) + 16;
    void *buffer = lua_newuserdata(L, bufflen);
    int decoded = decode(data, (int) len, (char *) buffer, (int) bufflen);
    lua_pushlstring(L, (char *) buffer, (size_t)decoded);
    return 1;
}


static luaL_Reg lua_funcs[] = {
        {"encode_len", &lencode_len},
        {"decode_len", &ldecode_len},
        {"encode",     &lencode},
        {"decode",     &ldecode},
        {NULL, NULL}
};

DLLEXPORT int luaopen_base16384(lua_State *L)
{
    luaL_newlib(L, lua_funcs);
    return 1;
}