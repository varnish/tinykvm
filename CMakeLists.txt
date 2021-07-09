cmake_minimum_required(VERSION 3.16)
project(kvmtest CXX)

option(FLTO "Link-time optimizations" OFF)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -O2 -g -march=native")

set (SOURCES
	src/main.cpp
	src/functions.cpp
	)

add_executable(kvmtest ${SOURCES})

target_link_libraries(kvmtest jemalloc)


add_subdirectory(lib tinykvm)
target_link_libraries(kvmtest tinykvm pthread)

if (FLTO)
	target_compile_options(kvmtest PRIVATE "-flto=thin")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=lld")
endif()
