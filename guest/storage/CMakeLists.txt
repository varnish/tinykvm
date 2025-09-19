cmake_minimum_required(VERSION 3.16)
project(storage)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_SHARED_LIBS "" OFF)
option(BUILD_TESTING "" OFF)
option(RAPIDJSON_BUILD_DOC "" OFF)
option(RAPIDJSON_BUILD_EXAMPLES "" OFF)
option(RAPIDJSON_BUILD_TESTS "" OFF)
option(RAPIDJSON_BUILD_CXX20 "" ON)
include(FetchContent)
FetchContent_Declare(rapidjson
	GIT_REPOSITORY https://github.com/Tencent/rapidjson.git
	GIT_TAG master
)
FetchContent_MakeAvailable(rapidjson)

# Build storage first
add_executable(storage
	storage.cpp
)
target_compile_options(storage PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(storage PRIVATE -static-pie)
target_link_libraries(storage PRIVATE RapidJSON)
target_include_directories(storage PUBLIC
	${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_BINARY_DIR}/_deps/rapidjson-src/include
)

# Symbol offset helper program
add_executable(symbol_offset
	${CMAKE_CURRENT_SOURCE_DIR}/symbol_offset.c
)

# Now execute objcopy to extract symbols
# objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=!_Z*remote* --strip-symbol=* storage storage.syms
# Output: storage.syms
add_custom_command(
	COMMAND objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=!_Z*remote* --strip-symbol=* storage storage.syms
	COMMAND ./symbol_offset storage.syms 0x4400200000 +exec
	OUTPUT storage.syms
	DEPENDS storage
	DEPENDS symbol_offset
)
add_custom_target(extract_symbols
	DEPENDS storage.syms
)
set_source_files_properties("storage.syms" PROPERTIES GENERATED TRUE)

# Now build main, linking against the symbols from storage.syms
add_executable(main
    main.cpp
	${CMAKE_CURRENT_BINARY_DIR}/storage.syms
)
target_compile_options(main PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(main PRIVATE -static -Wl,--just-symbols=storage.syms)
target_link_libraries(main PRIVATE RapidJSON)
target_include_directories(main PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
	${CMAKE_BINARY_DIR}/_deps/rapidjson-src/include
)
set_target_properties(main PROPERTIES LINK_DEPENDS "storage.syms")
