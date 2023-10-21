cmake_minimum_required(VERSION 3.9)
project(riscv CXX)

#set(FUZZER_MODE "memory,undefined" "-fsanitize-memory-track-origins")
set(FUZZER_MODE "address,undefined")

add_subdirectory(../lib lib)
target_compile_options(tinykvm PUBLIC -ggdb3 -Og)
target_compile_options(tinykvm PUBLIC "-fsanitize=${FUZZER_MODE}")
target_compile_options(tinykvm PUBLIC "-fsanitize=fuzzer-no-link")
target_compile_definitions(tinykvm PUBLIC FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1)

if (NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	message(FATAL_ERROR "libfuzzer is part of the Clang compiler suite.")
endif()

set(SOURCES
	fuzz.cpp
)

function(add_fuzzer NAME MODE)
	add_executable(${NAME} ${SOURCES})
	target_link_libraries(${NAME} tinykvm)
	set_target_properties(${NAME} PROPERTIES CXX_STANDARD 17)
	target_link_libraries(${NAME} "-fsanitize=${FUZZER_MODE}")
	target_link_libraries(${NAME} "-fsanitize=fuzzer" "-fuse-ld=lld")
	target_compile_definitions(${NAME} PRIVATE ${MODE}=1)
endfunction()

add_fuzzer(elffuzzer  FUZZ_ELF)
