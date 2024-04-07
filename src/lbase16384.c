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

static inline
int raiseerror(lua_State *L, base16384_err_t code)
{
    switch (code)
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
        case base16384_err_invalid_file_name:
            return luaL_error(L, "base16384_err_invalid_file_name");
        case base16384_err_invalid_commandline_parameter:
            return luaL_error(L, "base16384_err_invalid_commandline_parameter");
        case base16384_err_invalid_decoding_checksum:
            return luaL_error(L, "base16384_err_invalid_decoding_checksum");
        default:
            return 0;
    }
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
    int encoded = base16384_encode(data, (int) len, (char *) buffer);
    lua_pushlstring(L, (char *) buffer, (size_t) encoded);
    return 1;
}

static int
lencode_safe(lua_State *L)
{
    checklen(1);
    size_t len = 0;
    const char *data = luaL_checklstring(L, 1, &len);
    size_t bufflen = (size_t) base16384_encode_len((int) len);
    void *buffer = lua_newuserdata(L, bufflen);
    int encoded = base16384_encode_safe(data, (int) len, (char *) buffer);
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
    int decoded = base16384_decode(data, (int) len, (char *) buffer);
    lua_pushlstring(L, (char *) buffer, (size_t) decoded);
    return 1;
}

static int
ldecode_safe(lua_State *L)
{
    checklen(1);
    size_t len = 0;
    const char *data = luaL_checklstring(L, 1, &len);
    size_t bufflen = (size_t) base16384_decode_len((int) len, 0);
    void *buffer = lua_newuserdata(L, bufflen);
    int decoded = base16384_decode_safe(data, (int) len, (char *) buffer);
    lua_pushlstring(L, (char *) buffer, (size_t) decoded);
    return 1;
}

static int
lencode_file(lua_State *L)
{
    char encbuf[BASE16384_ENCBUFSZ];
    char decbuf[BASE16384_DECBUFSZ];
    const char *inpname;
    const char *outname;
    int flag;
    switch(lua_gettop(L))
    {
        case 2:
            inpname = luaL_checkstring(L, 1);
            outname = luaL_checkstring(L, 2);
            flag = 0;
            break;
        case 3:
            inpname = luaL_checkstring(L, 1);
            outname = luaL_checkstring(L, 2);
            flag = (int)luaL_checkinteger(L, 3);
            break;
        default:
            return luaL_error(L, "expect inpname, outname and a optional flag");
    }
    return raiseerror(L, base16384_encode_file_detailed(inpname, outname, encbuf, decbuf, flag));
}

static int
ldecode_file(lua_State *L)
{
    char encbuf[BASE16384_ENCBUFSZ];
    char decbuf[BASE16384_DECBUFSZ];
    const char *inpname;
    const char *outname;
    int flag;
    switch(lua_gettop(L))
    {
        case 2:
            inpname = luaL_checkstring(L, 1);
            outname = luaL_checkstring(L, 2);
            flag = 0;
            break;
        case 3:
            inpname = luaL_checkstring(L, 1);
            outname = luaL_checkstring(L, 2);
            flag = (int)luaL_checkinteger(L, 3);
            break;
        default:
            return luaL_error(L, "expect inpname, outname and a optional flag");
    }
    return raiseerror(L, base16384_decode_file_detailed(inpname, outname, encbuf, decbuf, flag));
}

static int
lencode_fp(lua_State *L)
{
    checklen(2);
    FILE *inp = (FILE *) lua_touserdata(L, 1);
    FILE *out = (FILE *) lua_touserdata(L, 2);
    int flag = 0;
    if(lua_gettop(L)==3)
    {
        flag = (int)luaL_checkinteger(L, 3);
    }
    char encbuf[BASE16384_ENCBUFSZ];
    char decbuf[BASE16384_DECBUFSZ];
    return raiseerror(L, base16384_encode_fp_detailed(inp, out, encbuf, decbuf, flag));
}


static int
ldecode_fp(lua_State *L)
{
    FILE *inp = (FILE *) lua_touserdata(L, 1);
    FILE *out = (FILE *) lua_touserdata(L, 2);
    int flag = 0;
    if(lua_gettop(L)==3)
    {
        flag = (int)luaL_checkinteger(L, 3);
    }
    char encbuf[BASE16384_ENCBUFSZ];
    char decbuf[BASE16384_DECBUFSZ];
    return raiseerror(L, base16384_decode_fp_detailed(inp, out, encbuf, decbuf, flag));
}


static int
lencode_fd(lua_State *L)
{
    checklen(2);
    int inp = (int) luaL_checkinteger(L, 1);
    int out = (int) luaL_checkinteger(L, 2);
    int flag = 0;
    if(lua_gettop(L)==3)
    {
        flag = (int)luaL_checkinteger(L, 3);
    }
    char encbuf[BASE16384_ENCBUFSZ];
    char decbuf[BASE16384_DECBUFSZ];
    return raiseerror(L, base16384_encode_fd_detailed(inp, out, encbuf, decbuf, flag));
}


static int
ldecode_fd(lua_State *L)
{
    checklen(2);
    int inp = (int) luaL_checkinteger(L, 1);
    int out = (int) luaL_checkinteger(L, 2);
    int flag = 0;
    if(lua_gettop(L)==3)
    {
        flag = (int)luaL_checkinteger(L, 3);
    }
    char encbuf[BASE16384_ENCBUFSZ];
    char decbuf[BASE16384_DECBUFSZ];
    return raiseerror(L, base16384_decode_fd_detailed(inp, out, encbuf, decbuf, flag));
}

static luaL_Reg lua_funcs[] = {
        {"encode_len",  &lencode_len},
        {"decode_len",  &ldecode_len},
        {"encode",      &lencode},
        {"encode_safe", &lencode_safe},
        {"decode",      &ldecode},
        {"decode_safe", &ldecode_safe},
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
#define ADD_CONST(name, value) lua_pushinteger(L, (lua_Integer)value); \
    lua_setfield(L, -2, name);

    ADD_CONST("ENCBUFSZ", BASE16384_ENCBUFSZ)
    ADD_CONST("DECBUFSZ", BASE16384_DECBUFSZ)
    ADD_CONST("FLAG_NOHEADER", BASE16384_FLAG_NOHEADER)
    ADD_CONST("FLAG_SUM_CHECK_ON_REMAIN", BASE16384_FLAG_SUM_CHECK_ON_REMAIN)
    ADD_CONST("FLAG_DO_SUM_CHECK_FORCELY", BASE16384_FLAG_DO_SUM_CHECK_FORCELY)
#undef ADD_CONST
    return 1;
}