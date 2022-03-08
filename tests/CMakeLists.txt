cmake_minimum_required(VERSION 3.10)
project(tinykvm_unittests CXX)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -ggdb3")

add_subdirectory(../lib tinykvm)
add_subdirectory(Catch2)

function(add_unit_test NAME)
	add_executable(${NAME}
		${ARGN}
		../src/functions.cpp
	)
	target_link_libraries(${NAME} tinykvm Catch2WithMain)
endfunction()

add_unit_test(basic unit/basic.cpp)
