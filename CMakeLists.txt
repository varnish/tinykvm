cmake_minimum_required(VERSION 3.16)
project(tinykvm)
#
# C++17 KVM library
#

option(KVM_DEBUG        "Enable debugging features" OFF)
option(KVM_EXPERIMENTAL "Enable experimental features" OFF)

set (SOURCES
	src/main.cpp
	src/machine.cpp
	src/memory.cpp
	src/vcpu.cpp
	src/kernel/gdt.cpp
	src/kernel/idt.cpp
	)

add_executable(tinykvm ${SOURCES})
set_property(TARGET tinykvm PROPERTY CXX_STANDARD 20)
target_compile_definitions(tinykvm PUBLIC _GNU_SOURCE=1)
target_link_libraries(tinykvm jemalloc)

if (KVM_DEBUG)
	target_compile_options(tinykvm PUBLIC -O0 -g)
else()
	target_compile_options(tinykvm PUBLIC -O2 -g)
endif()
