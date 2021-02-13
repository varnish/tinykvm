cmake_minimum_required(VERSION 3.16)
project(tinykvm)
#
# C++17 KVM library
#

option(KVM_DEBUG        "Enable debugging features" OFF)
option(KVM_EXPERIMENTAL "Enable experimental features" OFF)

set (SOURCES
	src/main.cpp
	)

add_executable(tinykvm ${SOURCES})
target_link_libraries(tinykvm jemalloc)
