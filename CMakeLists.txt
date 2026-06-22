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

if (TINYKVM_ARCH STREQUAL "AMD64")
	add_executable(bench
		src/bench.cpp
	)
	target_link_libraries(bench tinykvm)

	add_executable(tinytest
		src/tests.cpp
	)
	target_link_libraries(tinytest tinykvm)

	add_executable(simplekvm
		src/simple.cpp
	)
	target_link_libraries(simplekvm tinykvm)

	add_executable(storagekvm
		src/storage.cpp
	)
	target_link_libraries(storagekvm tinykvm)

	add_executable(snapshot_bench
		src/snapshot_bench.cpp
	)
	target_link_libraries(snapshot_bench tinykvm)

	add_executable(pipekvm
		src/pipe.cpp
	)
	target_link_libraries(pipekvm tinykvm)
elseif (TINYKVM_ARCH STREQUAL "ARM64")
	add_executable(arm64_demo
		src/arm64_demo.cpp
	)
	target_link_libraries(arm64_demo tinykvm)

	add_executable(arm64_bench
		src/arm64_bench.cpp
	)
	target_link_libraries(arm64_bench tinykvm)
endif()
