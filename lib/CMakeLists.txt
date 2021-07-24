cmake_minimum_required(VERSION 3.10)
project(tinykvm)
#
# C++17 KVM library
#

option(KVM_DEBUG        "Enable debugging features" OFF)
option(KVM_EXPERIMENTAL "Enable experimental features" OFF)

set (SOURCES
	tinykvm/machine.cpp
	tinykvm/machine_elf.cpp
	tinykvm/machine_env.cpp
	tinykvm/machine_utils.cpp
	tinykvm/memory.cpp
	tinykvm/memory_bank.cpp
	tinykvm/rsp_client.cpp
	tinykvm/threads.cpp
	tinykvm/vcpu.cpp
	tinykvm/kernel/gdt.cpp
	tinykvm/kernel/idt.cpp
	tinykvm/kernel/tss.cpp
	tinykvm/kernel/paging.cpp
	tinykvm/kernel/vdso.cpp
	)

add_library(tinykvm STATIC ${SOURCES})
set_property(TARGET tinykvm PROPERTY CXX_STANDARD 17)
target_compile_definitions(tinykvm PUBLIC _GNU_SOURCE=1)
target_include_directories(tinykvm PUBLIC .)
target_compile_features(tinykvm PUBLIC cxx_std_17)

if (KVM_DEBUG)
	target_compile_options(tinykvm PUBLIC -O0 -g)
else()
	target_compile_options(tinykvm PUBLIC -O2 -g)
endif()
