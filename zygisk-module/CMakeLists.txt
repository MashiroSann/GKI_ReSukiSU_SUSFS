cmake_minimum_required(VERSION 3.16)
project(hide_memory_traces LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED OUTPUT_NAME)
    set(OUTPUT_NAME "hide_memory_traces")
endif()

add_library(zygisk_module SHARED src/module.cpp)

target_include_directories(zygisk_module PRIVATE src)

target_compile_options(zygisk_module PRIVATE
        -Os
        -fno-exceptions
        -fno-rtti
        -fvisibility=hidden
        -fvisibility-inlines-hidden
        -Wall
        -Wextra
        -Wno-unused-parameter)

target_link_options(zygisk_module PRIVATE
        -Wl,-z,max-page-size=16384
        -Wl,--gc-sections
        -Wl,--exclude-libs,ALL)

target_link_libraries(zygisk_module log)

set_target_properties(zygisk_module PROPERTIES
        PREFIX ""
        OUTPUT_NAME "${OUTPUT_NAME}")
