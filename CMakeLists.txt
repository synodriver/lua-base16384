cmake_minimum_required(VERSION 3.20)
project(lua_base16384 C)
set(CMAKE_C_STANDARD 11)
set(LUA_INCLUDE E:\\pyproject\\Lua_5.4_WinBuild\\lua-5.4.7\\src) # D:\\conda\\envs\\py310\\Library\\include
set(LUA_LIB E:\\pyproject\\Lua_5.4_WinBuild\\cmake-build-release-visual-studio)
# change this to your lua.h directory
include_directories(${LUA_INCLUDE} ./base16384)
# change this to your lua.lib\liblua.a directory
link_directories(${LUA_LIB})# "D:\\conda\\envs\\py310\\Library\\lib" D:\\conda\\envs\\py310\\Library\\bin)


include(TestBigEndian)
test_big_endian(isBigEndian)
if (${isBigEndian})
    add_definitions(-DWORDS_BIGENDIAN)
endif()

if(CMAKE_CL_64)
    MESSAGE("target is 64bit")
    set(SOURCES base16384/base1464.c  base16384/file.c base16384/wrap.c)
    add_compile_definitions("CPUBIT64")
    add_compile_definitions("IS_64BIT_PROCESSOR")
else()
    MESSAGE("target is 32bit")
    set(SOURCES base16384/base1432.c base16384/file.c base16384/wrap.c)
    add_compile_definitions("CPUBIT32")
endif()



add_library(base16384 SHARED src/lbase16384.c ${SOURCES})
target_link_libraries(base16384 lua)
set_target_properties(base16384 PROPERTIES OUTPUT_NAME base16384)

