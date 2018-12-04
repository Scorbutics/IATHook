cmake_minimum_required(VERSION 3.9)
project(iathook)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(external/asm_utils)
add_subdirectory(src/architecture)

include_directories(external/asm_utils/src)

link_directories(external/asm_utils/${CMAKE_BUILD_TYPE})
link_directories(src/architecture/${CMAKE_BUILD_TYPE})

file(GLOB_RECURSE SOURCES
    src/*.h
    src/*.cpp
)

string(REGEX REPLACE "[^;]*CMakeFiles/[^;]+;?" "" SOURCES "${SOURCES}")

add_library(iathook SHARED ${SOURCES})
target_link_libraries(iathook asm_utils iathook_architecture_dependent)
