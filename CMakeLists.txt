cmake_minimum_required(VERSION 3.19)
project("zdb" LANGUAGES CXX)
include(CTest)
add_subdirectory("src")
add_subdirectory("tools")

if(BUILD_TESTING)
    add_subdirectory("test")
endif()