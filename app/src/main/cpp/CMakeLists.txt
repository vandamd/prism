cmake_minimum_required(VERSION 3.22.1)
project(lp3binderdirect LANGUAGES CXX)

add_library(lp3binderdirect SHARED direct.cpp)
add_library(bootcopy SHARED bootcopy.cpp)

target_link_libraries(lp3binderdirect
    binder_ndk
    log)
