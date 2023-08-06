cmake_minimum_required(VERSION 3.10)
project(tinykvm CXX)

option(FLTO "Link-time optimizations" OFF)
option(SANITIZE "Enable address and ub sanitizers" OFF)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -O2 -ggdb3")

if (FLTO)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto=thin")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fuse-ld=lld")
endif()
if (SANITIZE)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address,undefined")
endif()

add_subdirectory(lib tinykvm)

target_compile_definitions(tinykvm PUBLIC
	TINYKVM_ARCH_${TINYKVM_ARCH}=1
	TINYKVM_ARCH="${TINYKVM_ARCH}")

add_executable(bench
	src/bench.cpp
	src/functions.cpp
)
target_link_libraries(bench tinykvm)

add_executable(tinytest
	src/tests.cpp
	src/functions.cpp
)
target_link_libraries(tinytest tinykvm)

add_executable(simplekvm
	src/simple.cpp
	src/functions.cpp
)
target_link_libraries(simplekvm tinykvm)

add_executable(storagekvm
	src/storage.cpp
	src/functions.cpp
)
target_link_libraries(storagekvm tinykvm)
