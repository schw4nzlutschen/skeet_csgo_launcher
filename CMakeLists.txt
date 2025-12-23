cmake_minimum_required(VERSION 3.16)
project(skeet_launcher)

set(CMAKE_CXX_FLAGS "")
set(CMAKE_CXX_FLAGS_DEBUG "")
set(CMAKE_CXX_FLAGS_RELEASE "")

if(NOT CMAKE_VS_PLATFORM_NAME)
    set(CMAKE_VS_PLATFORM_NAME "x86")
endif()

message(STATUS "${CMAKE_VS_PLATFORM_NAME} architecture in use")

if(NOT "${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x86")
    message(FATAL_ERROR "${CMAKE_VS_PLATFORM_NAME} arch is not supported!")
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(STATUS "Clang compiler detected - configuring for Windows")

    set(CMAKE_SYSTEM_NAME Windows)

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -target i686-pc-windows-msvc")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=lld")

    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++")

    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -D_DEBUG")
    else()
        set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
    endif()
endif()

add_subdirectory(steam_module)