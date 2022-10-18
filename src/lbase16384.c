#include "lua.h"
#include "lauxlib.h"

#include "base16384.h"

#ifdef _WIN32
#define DLLEXPORT __declspec(dllexport)
#elif
#define DLLEXPORT
#endif /* _WIN32 */

#define checklen(size) \
if(lua_gettop(L)!=(size)) \
{                      \
return luaL_error(L, "wrong parameter number");                     \
}

static int
lencode_len(lua_State *L)
{
    checklen(1);
    int dlen = (int) luaL_checkinteger(L, 1);
    lua_pushinteger(L, (lua_Integer) base16384_encode_len(dlen));
    return 1;
}

static int
ldecode_len(lua_State *L)
{
    checklen(1);
    int dlen = (int) luaL_checkinteger(L, 1);
    lua_pushinteger(L, (lua_Integer) base16384_decode_len(dlen, 0));
    return 1;
}


static int
lencode(lua_State *L)
{
    checklen(1);
    size_t len = 0;
    const char *data = luaL_checklstring(L, 1, &len);
    size_t bufflen = (size_t) base16384_encode_len((int) len) + 16;
    void *buffer = lua_newuserdata(L, bufflen);
    int encoded = base16384_encode(data, (int) len, (char *) buffer, (int) bufflen);
    lua_pushlstring(L, (char *) buffer, (size_t) encoded);
    return 1;
}

static int
ldecode(lua_State *L)
{
    checklen(1);
    size_t len = 0;
    const char *data = luaL_checklstring(L, 1, &len);
    size_t bufflen = (size_t) base16384_decode_len((int) len, 0) + 16;
    void *buffer = lua_newuserdata(L, bufflen);
    int decoded = base16384_decode(data, (int) len, (char *) buffer, (int) bufflen);
    lua_pushlstring(L, (char *) buffer, (size_t) decoded);
    return 1;
}

static int
lencode_file(lua_State *L)
{
    checklen(2);
    char encbuf[BASE16384_ENCBUFSZ];
    char decbuf[BASE16384_DECBUFSZ];
    const char *inpname = luaL_checkstring(L, 1);
    const char *outname = luaL_checkstring(L, 2);
    switch (base16384_encode_file(inpname, outname, encbuf, decbuf))
    {
        case base16384_err_get_file_size:
            return luaL_error(L, "base16384_err_get_file_size");
        case base16384_err_fopen_output_file:
            return luaL_error(L, "base16384_err_fopen_output_file");
        case base16384_err_fopen_input_file:
            return luaL_error(L, "base16384_err_fopen_input_file");
        case base16384_err_write_file:
            return luaL_error(L, "base16384_err_write_file");
        case base16384_err_open_input_file:
            return luaL_error(L, "base16384_err_open_input_file");
        case base16384_err_map_input_file:
            return luaL_error(L, "base16384_err_map_input_file");
        case base16384_err_read_file:
            return luaL_error(L, "base16384_err_read_file");
        default:
            return 0;
    }
}

static int
ldecode_file(lua_State *L)
{
    checklen(2);
    char encbuf[BASE16384_ENCBUFSZ];
    char decbuf[BASE16384_DECBUFSZ];
    const char *inpname = luaL_checkstring(L, 1);
    const char *outname = luaL_checkstring(L, 2);
    switch (base16384_decode_file(inpname, outname, encbuf, decbuf))
    {
        case base16384_err_get_file_size:
            return luaL_error(L, "base16384_err_get_file_size");
        case base16384_err_fopen_output_file:
            return luaL_error(L, "base16384_err_fopen_output_file");
        case base16384_err_fopen_input_file:
            return luaL_error(L, "base16384_err_fopen_input_file");
        case base16384_err_write_file:
            return luaL_error(L, "base16384_err_write_file");
        case base16384_err_open_input_file:
            return luaL_error(L, "base16384_err_open_input_file");
        case base16384_err_map_input_file:
            return luaL_error(L, "base16384_err_map_input_file");
        case base16384_err_read_file:
            return luaL_error(L, "base16384_err_read_file");
        default:
            return 0;
    }
}

static int
lencode_fp(lua_State *L)
{
    checklen(2);
    FILE *inp = (FILE *) lua_touserdata(L, 1);
    FILE *out = (FILE *) lua_touserdata(L, 2);
    char encbuf[BASE16384_ENCBUFSZ];
    char decbuf[BASE16384_DECBUFSZ];
    switch (base16384_encode_fp(inp, out, encbuf, decbuf))
    {
        case base16384_err_get_file_size:
            return luaL_error(L, "base16384_err_get_file_size");
        case base16384_err_fopen_output_file:
            return luaL_error(L, "base16384_err_fopen_output_file");
        case base16384_err_fopen_input_file:
            return luaL_error(L, "base16384_err_fopen_input_file");
        case base16384_err_write_file:
            return luaL_error(L, "base16384_err_write_file");
        case base16384_err_open_input_file:
            return luaL_error(L, "base16384_err_open_input_file");
        case base16384_err_map_input_file:
            return luaL_error(L, "base16384_err_map_input_file");
        case base16384_err_read_file:
            return luaL_error(L, "base16384_err_read_file");
        default:
            return 0;
    }
}


static int
ldecode_fp(lua_State *L)
{
    checklen(2);
    FILE *inp = (FILE *) lua_touserdata(L, 1);
    FILE *out = (FILE *) lua_touserdata(L, 2);
    char encbuf[BASE16384_ENCBUFSZ];
    char decbuf[BASE16384_DECBUFSZ];
    switch (base16384_decode_fp(inp, out, encbuf, decbuf))
    {
        case base16384_err_get_file_size:
            return luaL_error(L, "base16384_err_get_file_size");
        case base16384_err_fopen_output_file:
            return luaL_error(L, "base16384_err_fopen_output_file");
        case base16384_err_fopen_input_file:
            return luaL_error(L, "base16384_err_fopen_input_file");
        case base16384_err_write_file:
            return luaL_error(L, "base16384_err_write_file");
        case base16384_err_open_input_file:
            return luaL_error(L, "base16384_err_open_input_file");
        case base16384_err_map_input_file:
            return luaL_error(L, "base16384_err_map_input_file");
        case base16384_err_read_file:
            return luaL_error(L, "base16384_err_read_file");
        default:
            return 0;
    }
}


static int
lencode_fd(lua_State *L)
{
    checklen(2);
    int inp = (int) luaL_checkinteger(L, 1);
    int out = (int) luaL_checkinteger(L, 2);
    char encbuf[BASE16384_ENCBUFSZ];
    char decbuf[BASE16384_DECBUFSZ];
    switch (base16384_encode_fd(inp, out, encbuf, decbuf))
    {
        case base16384_err_get_file_size:
            return luaL_error(L, "base16384_err_get_file_size");
        case base16384_err_fopen_output_file:
            return luaL_error(L, "base16384_err_fopen_output_file");
        case base16384_err_fopen_input_file:
            return luaL_error(L, "base16384_err_fopen_input_file");
        case base16384_err_write_file:
            return luaL_error(L, "base16384_err_write_file");
        case base16384_err_open_input_file:
            return luaL_error(L, "base16384_err_open_input_file");
        case base16384_err_map_input_file:
            return luaL_error(L, "base16384_err_map_input_file");
        case base16384_err_read_file:
            return luaL_error(L, "base16384_err_read_file");
        default:
            return 0;
    }
}


static int
ldecode_fd(lua_State *L)
{
    checklen(2);
    int inp = (int) luaL_checkinteger(L, 1);
    int out = (int) luaL_checkinteger(L, 2);
    char encbuf[BASE16384_ENCBUFSZ];
    char decbuf[BASE16384_DECBUFSZ];
    switch (base16384_decode_fd(inp, out, encbuf, decbuf))
    {
        case base16384_err_get_file_size:
            return luaL_error(L, "base16384_err_get_file_size");
        case base16384_err_fopen_output_file:
            return luaL_error(L, "base16384_err_fopen_output_file");
        case base16384_err_fopen_input_file:
            return luaL_error(L, "base16384_err_fopen_input_file");
        case base16384_err_write_file:
            return luaL_error(L, "base16384_err_write_file");
        case base16384_err_open_input_file:
            return luaL_error(L, "base16384_err_open_input_file");
        case base16384_err_map_input_file:
            return luaL_error(L, "base16384_err_map_input_file");
        case base16384_err_read_file:
            return luaL_error(L, "base16384_err_read_file");
        default:
            return 0;
    }
}

static luaL_Reg lua_funcs[] = {
        {"encode_len",  &lencode_len},
        {"decode_len",  &ldecode_len},
        {"encode",      &lencode},
        {"decode",      &ldecode},
        {"encode_file", &lencode_file},
        {"decode_file", &ldecode_file},
        {"encode_fp",   &lencode_fp},
        {"decode_fp",   &ldecode_fp},
        {"encode_fd",   &lencode_fd},
        {"decode_fd",   &ldecode_fd},
        {NULL, NULL}
};

DLLEXPORT int luaopen_base16384(lua_State *L)
{
    luaL_newlib(L, lua_funcs);
    return 1;
}