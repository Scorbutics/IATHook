cmake_minimum_required(VERSION 3.9)
project(iathook)

set(CMAKE_CXX_STANDARD 17)

file(GLOB_RECURSE SOURCES
    src/*.h
    src/*.cpp
	src/*.asm
)

string(REGEX REPLACE "[^;]*CMakeFiles/[^;]+;?" "" SOURCES "${SOURCES}")

add_library(iathook SHARED ${SOURCES})


