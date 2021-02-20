cmake_minimum_required(VERSION 3.16)
project(kvmtest)

set (SOURCES
	src/main.cpp
	)

add_executable(kvmtest ${SOURCES})
target_link_libraries(kvmtest jemalloc)

add_subdirectory(lib tinykvm)
target_link_libraries(kvmtest tinykvm)
