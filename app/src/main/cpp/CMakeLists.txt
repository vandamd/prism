cmake_minimum_required(VERSION 3.22.1)
project(lp3binderdirect LANGUAGES CXX)

add_library(lp3binderdirect SHARED direct.cpp)
add_library(bootcopy SHARED bootcopy.cpp)

add_library(prismprimitivecore STATIC
    primitive_core.cpp)

add_executable(prism_primitive
    primitive_cli.cpp)

set_target_properties(prism_primitive PROPERTIES
    OUTPUT_NAME prism-primitive)

target_link_libraries(lp3binderdirect
    prismprimitivecore
    binder_ndk
    log)

target_link_libraries(prismprimitivecore
    binder_ndk
    log)

target_link_libraries(prism_primitive
    prismprimitivecore
    dl
    log)

target_link_options(prism_primitive PRIVATE
    -static-libstdc++)
