cmake_minimum_required(VERSION 3.16)
project(steam LANGUAGES CXX)

unset(CMAKE_CXX_FLAGS CACHE)
unset(CMAKE_CXX_FLAGS_DEBUG CACHE)
unset(CMAKE_CXX_FLAGS_RELEASE CACHE)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(STATUS "Using Clang compiler")

    set(CMAKE_CXX_STANDARD 23)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    add_compile_options(
            -std=c++23
            -D_CRT_SECURE_NO_WARNINGS
            -D_WIN32_WINNT=0x0601
            -fms-extensions
            -Wno-microsoft-cast
            -Wno-c++20-designator
    )

    add_link_options(-static)

elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    message(STATUS "Using MSVC compiler")
    add_compile_options(/MT /std:c++latest)
endif()

add_executable(steam
        steam_module.cpp
        skCrypter.h
)

target_link_libraries(steam kernel32 user32)