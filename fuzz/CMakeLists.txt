cmake_minimum_required(VERSION 3.9)
project(riscv CXX)

#set(FUZZER_MODE "memory,undefined" "-fsanitize-memory-track-origins")
set(FUZZER_MODE "address,undefined")

add_subdirectory(../lib lib)
target_compile_options(tinykvm PUBLIC "-fsanitize=${FUZZER_MODE},fuzzer-no-link")
target_compile_definitions(tinykvm PUBLIC FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1)

if (NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	message(FATAL_ERROR "libfuzzer is part of the Clang compiler suite.")
endif()

find_program(LLD_LINKER NAMES lld ld.lld)

function(add_fuzzer NAME SOURCE MODE)
	add_executable(${NAME} ${SOURCE})
	target_link_libraries(${NAME} PUBLIC tinykvm)
	set_target_properties(${NAME} PROPERTIES CXX_STANDARD 20)
	target_link_libraries(${NAME} PUBLIC "-fsanitize=${FUZZER_MODE},fuzzer")
	if (LLD_LINKER)
		target_link_libraries(${NAME} PUBLIC "-fuse-ld=lld")
	endif()
	target_compile_definitions(${NAME} PRIVATE ${MODE}=1)
endfunction()

add_fuzzer(elffuzzer     fuzz.cpp             FUZZ_ELF)
add_fuzzer(elfsymfuzzer  elf_symbols_fuzz.cpp FUZZ_ELF_SYMBOLS)
add_fuzzer(syscallfuzzer syscall_fuzz.cpp     FUZZ_SYSCALLS)

# The syscall fuzzer needs a real, fully-initialized master VM to fork from,
# so it loads a small static guest ELF built here. It is an ordinary Linux
# userspace binary -- not sanitized, not linked against the library.
find_program(GUEST_CC NAMES gcc cc REQUIRED)
set(GUEST_ELF "${CMAKE_CURRENT_BINARY_DIR}/syscall_fuzz_guest.elf")
add_custom_command(
	OUTPUT  ${GUEST_ELF}
	COMMAND ${GUEST_CC} -O2 -static -std=c11
	        -o ${GUEST_ELF} ${CMAKE_CURRENT_SOURCE_DIR}/guest/syscall_fuzz_guest.c
	DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/guest/syscall_fuzz_guest.c
	COMMENT "Building syscall fuzzer guest ELF"
)
add_custom_target(syscall_fuzz_guest DEPENDS ${GUEST_ELF})
add_dependencies(syscallfuzzer syscall_fuzz_guest)
target_compile_definitions(syscallfuzzer PRIVATE FUZZ_GUEST_PATH="${GUEST_ELF}")
