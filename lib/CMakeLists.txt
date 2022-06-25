cmake_minimum_required(VERSION 3.10)
project(tinykvm)
#
# C++17 KVM library
#

option(KVM_AVX512       "Enable AVX512 instructions" OFF)
option(KVM_EXPERIMENTAL "Enable experimental features" OFF)

set (SOURCES
	tinykvm/machine.cpp
	tinykvm/machine_elf.cpp
	tinykvm/machine_env.cpp
	tinykvm/machine_utils.cpp
	tinykvm/memory.cpp
	tinykvm/memory_bank.cpp
	tinykvm/page_streaming.cpp
	tinykvm/smp.cpp
	tinykvm/rsp_client.cpp
	tinykvm/threads.cpp
	tinykvm/vcpu.cpp
	tinykvm/vcpu_run.cpp
	tinykvm/kernel/gdt.cpp
	tinykvm/kernel/idt.cpp
	tinykvm/kernel/tss.cpp
	tinykvm/kernel/paging.cpp
	tinykvm/kernel/usercode.cpp
	tinykvm/kernel/vdso.cpp
	)

add_library(tinykvm STATIC ${SOURCES})
target_compile_definitions(tinykvm PUBLIC _GNU_SOURCE=1)
target_include_directories(tinykvm PUBLIC .)
target_compile_features(tinykvm PUBLIC cxx_std_17)
target_link_libraries(tinykvm PUBLIC pthread rt)

set_source_files_properties(
	tinykvm/page_streaming.cpp
	PROPERTIES COMPILE_FLAGS -mavx2)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	target_compile_options(tinykvm PUBLIC -O0 -ggdb3)
else()
	target_compile_options(tinykvm PUBLIC -O2 -g)
endif()
if (KVM_AVX512)
	target_compile_definitions(tinykvm PUBLIC KVM_AVX512=1)
endif()
if (KVM_EXPERIMENTAL)
	target_compile_definitions(tinykvm PUBLIC TINYKVM_FAST_EXECUTION_TIMEOUT=1)
endif()
