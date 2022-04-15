cmake_minimum_required(VERSION 3.20)
project(lua_base16384 C)
set(CMAKE_C_STANDARD 11)
include_directories(F:/conda/Library/include ./base16384)
link_directories("F:\\conda\\Library\\lib" F:/conda/Library/bin)

include(TestBigEndian)
test_big_endian(isBigEndian)
if (${isBigEndian})
    add_definitions(-DWORDS_BIGENDIAN)
endif()

if(CMAKE_CL_64)
    MESSAGE("target is 64bit")
    set(SOURCES base16384/base1464.c)
    add_compile_definitions("CPUBIT64")
else()
    MESSAGE("target is 32bit")
    set(SOURCES base16384/base1432.c)
    add_compile_definitions("CPUBIT32")
endif()



add_library(base16384 SHARED src/lbase16384.c ${SOURCES})
target_link_libraries(base16384 lua)
set_target_properties(base16384 PROPERTIES OUTPUT_NAME base16384)

