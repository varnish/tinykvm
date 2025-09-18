#include <cassert>
#include <cstdio>
#include <array>
#include <memory_resource>
#include "json.hpp"
#define DECLARE_REMOTE_FUNCTION(name, ...) \
	extern "C" int call_ ## name(__VA_ARGS__); \
	asm(".global call_" #name "\n" \
		"call_" #name ":\n" \
		"    movabs $" #name ", %rax\n" \
		"    jmp *%rax\n");
// Test 1: Simple remote function
DECLARE_REMOTE_FUNCTION(remote_function, int(*arg)(int), int value);
// Test 2: Remote allocation with polymorphic memory resource
static std::vector<std::byte> buffer(65536);
static std::pmr::monotonic_buffer_resource mbr{buffer.data(), buffer.size()};
extern std::pmr::vector<int> remote_allocation(std::pmr::memory_resource* mr, size_t size);
// Test 3: RapidJSON using same polymorphic memory resource
DECLARE_REMOTE_FUNCTION(remote_json, JsonDocument& j);
#define my_assert(x) do { if (!(x)) { printf("Assertion failed: %s\n", #x); std::abort(); } } while(0)

static int double_int(int value)
{
	return value * 2;
}

int main()
{
	printf("Hello from Main VM!\n");
	if constexpr (true) {
		for (int i = 0; i < 10; i++) {
			const int val = call_remote_function(double_int, 21);
			my_assert(val == 42);
		}
		printf("* Verified remote_function works\n");
	}
	//if constexpr (true) {
	//	std::pmr::memory_resource* mr = &mbr;
	//	for (int i = 0; i < 10; i++) {
	//		std::pmr::vector<int> vec = remote_allocation(mr, 1024);
	//		my_assert(!vec.empty());
	//		my_assert(vec.size() == 1024);
	//		for (size_t j = 0; j < vec.size(); j++) {
	//			my_assert(vec[j] == j);
	//			//printf("%d ", vec[j]);
	//		}
	//	}
	//	printf("* Verified remote_allocation works\n");
	//}
	if constexpr (true) {
		char valueBuffer[8192];
		char parseBuffer[2048];
		rapidjson::MemoryPoolAllocator<> valueAllocator(valueBuffer, sizeof(valueBuffer));
		rapidjson::MemoryPoolAllocator<> parseAllocator(parseBuffer, sizeof(parseBuffer));
		JsonDocument j(&valueAllocator, sizeof(parseBuffer), &parseAllocator);
		call_remote_json(j);
		my_assert(!j.HasParseError());
		my_assert(j.IsObject());
		my_assert(j.HasMember("key"));
		my_assert(j["key"].IsString());
		my_assert(strcmp(j["key"].GetString(), "value") == 0);
		my_assert(j.HasMember("number"));
		my_assert(j["number"].IsInt());
		my_assert(j["number"].GetInt() == 42);
		my_assert(j.HasMember("array"));
		my_assert(j["array"].IsArray());
		const auto& arr = j["array"];
		my_assert(arr.Size() == 3);
		my_assert(arr[0].IsInt() && arr[0].GetInt() == 1);
		my_assert(arr[1].IsInt() && arr[1].GetInt() == 2);
		my_assert(arr[2].IsInt() && arr[2].GetInt() == 3);
		my_assert(j.HasMember("boolean"));
		my_assert(j["boolean"].IsBool());
		my_assert(j["boolean"].GetBool() == true);
		// Pretty print the Document
		rapidjson::StringBuffer buffer;
		rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(buffer);
		writer.SetIndent(' ', 4); // Use 4 spaces for indentation
		j.Accept(writer);
		printf("Remote JSON document: %s\n", buffer.GetString());
		printf("* Verified remote_json works\n");
	}
	fflush(stdout);
	return 0;
}

extern "C" int do_calculation(int value)
{
	return call_remote_function(double_int, value);
}
extern "C" void do_nothing(int) { }
