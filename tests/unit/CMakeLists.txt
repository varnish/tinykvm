cmake_minimum_required(VERSION 3.10)
project(tinykvm_unittests CXX)

# Appended, not assigned: the compile-time A/B defaults
# (-DTINYKVM_LAZY_VCPU_MMAP_DEFAULT=true, -DTINYKVM_VM_GROUP_DEFAULT=true,
# -DTINYKVM_VM_GROUP_ARENA_SLOT_DEFAULT=PerSeat) are
# passed in as -DCMAKE_CXX_FLAGS, and assigning here silently discarded them --
# so the "whole suite also passes with the flag on" runs were not testing
# anything. They must reach the tests as well as the library: the defaults live
# in MachineOptions, i.e. at the caller.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -ggdb3")

add_subdirectory(../../lib tinykvm)
add_subdirectory(../Catch2 Catch2)

enable_testing()

function(add_unit_test NAME)
	add_executable(${NAME}
		${ARGN}
		codebuilder.cpp
	)
	target_link_libraries(${NAME} tinykvm Catch2WithMain)
	add_test(
		NAME test_${NAME}
		COMMAND ${NAME}
	)
endfunction()

if (TINYKVM_ARCH STREQUAL "AMD64")
	add_unit_test(basic  basic.cpp)
	add_unit_test(elf    elf.cpp)
	add_unit_test(fork   fork.cpp)
	add_unit_test(lazy_kvm_run lazy_kvm_run.cpp)
	add_unit_test(mmap   mmap.cpp)
	add_unit_test(remote remote.cpp)
	add_unit_test(reset  reset.cpp)
	add_unit_test(timeout timeout.cpp)
	add_unit_test(tegridy tegridy.cpp)
	add_unit_test(syscalls syscalls.cpp)
	# One case here asserts that a guest-controlled length is not walked page
	# by page. Before the fix it does not fail fast, it grinds -- cap it so a
	# regression cannot wedge CI.
	set_tests_properties(test_syscalls PROPERTIES TIMEOUT 120)
	add_unit_test(seccomp seccomp.cpp)
	add_unit_test(vm_group vm_group.cpp)
elseif (TINYKVM_ARCH STREQUAL "ARM64")
	add_unit_test(arm64_minimal arm64_minimal.cpp)
	add_unit_test(arm64_elf arm64_elf.cpp)
	add_unit_test(arm64_fork arm64_fork.cpp)
	add_unit_test(arm64_threads arm64_threads.cpp)
	add_unit_test(arm64_signals arm64_signals.cpp)
	add_unit_test(seccomp seccomp.cpp)
endif()
