cmake_minimum_required(VERSION 3.10)
project(tinykvm_unittests CXX)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -ggdb3")

add_subdirectory(../../lib tinykvm)
add_subdirectory(../Catch2 Catch2)

enable_testing()

function(add_unit_test NAME)
	add_executable(${NAME}
		${ARGN}
		../../src/functions.cpp
		codebuilder.cpp
	)
	target_link_libraries(${NAME} tinykvm Catch2WithMain)
	add_test(
		NAME test_${NAME}
		COMMAND ${NAME}
	)
endfunction()

add_unit_test(basic basic.cpp)
add_unit_test(fork  fork.cpp)
add_unit_test(reset reset.cpp)
add_unit_test(timeout timeout.cpp)
