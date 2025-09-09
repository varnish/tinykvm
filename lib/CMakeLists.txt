cmake_minimum_required(VERSION 3.10)
project(tinykvm)
#
# C++17 KVM library
#

option(KVM_EXPERIMENTAL "Enable experimental features" OFF)

if (CMAKE_SYSTEM_PROCESSOR MATCHES "(x86)|(X86)|(amd64)|(AMD64)")
	set (TINYKVM_ARCH "AMD64" CACHE STRING "TinyKVM Arch Backend")
else()
	# TODO: Detect ARM properly
	set (TINYKVM_ARCH "ARM64" CACHE STRING "TinyKVM Arch Backend")
endif()

set (SOURCES
	tinykvm/machine.cpp
	tinykvm/machine_debug.cpp
	tinykvm/machine_elf.cpp
	tinykvm/machine_env.cpp
	tinykvm/machine_utils.cpp
	tinykvm/memory.cpp
	tinykvm/memory_bank.cpp
	tinykvm/memory_maps.cpp
	tinykvm/page_streaming.cpp
	tinykvm/remote.cpp
	tinykvm/smp.cpp
	tinykvm/vcpu.cpp
	tinykvm/vcpu_run.cpp

	tinykvm/linux/fds.cpp
	tinykvm/linux/signals.cpp
	tinykvm/linux/system_calls.cpp
	tinykvm/linux/threads.cpp
	)
if (TINYKVM_ARCH STREQUAL "AMD64")
	list(APPEND SOURCES
		tinykvm/amd64/gdt.cpp
		tinykvm/amd64/idt.cpp
		tinykvm/amd64/tss.cpp
		tinykvm/amd64/paging.cpp
		tinykvm/amd64/usercode.cpp
		tinykvm/amd64/vdso.cpp
		tinykvm/rsp_client.cpp
	)
endif()

add_library(tinykvm STATIC ${SOURCES})
target_compile_definitions(tinykvm PUBLIC _GNU_SOURCE=1)
target_include_directories(tinykvm PUBLIC .)
target_compile_features(tinykvm PUBLIC cxx_std_20)
target_link_libraries(tinykvm PUBLIC pthread rt)

set_source_files_properties(
	tinykvm/page_streaming.cpp
	PROPERTIES COMPILE_FLAGS -mavx2)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
	target_compile_options(tinykvm PUBLIC -O0 -ggdb3)
else()
	target_compile_options(tinykvm PUBLIC -O2 -g)
endif()
if (KVM_EXPERIMENTAL)
	target_compile_definitions(tinykvm PUBLIC TINYKVM_FAST_EXECUTION_TIMEOUT=1)
endif()
