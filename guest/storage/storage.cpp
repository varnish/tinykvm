#include <cstdio>
#include <cstdlib>
#include <memory_resource>
#include "json.hpp"
using namespace rapidjson;

extern int remote_function(int (*arg)(int), int value)
{
	//write(1, "In remote_function\n", 20);
	return arg(value);
}

extern std::pmr::vector<int> remote_allocation(std::pmr::memory_resource* mr, size_t size)
{
	std::pmr::vector<int> vec{mr};
	for (size_t i = 0; i < size; i++)
		vec.push_back(i);
	return vec;
}

extern void remote_json(JsonDocument& j)
{
	auto& alloc = j.GetAllocator();
	// Create JSON object
	j.SetObject();
	j.AddMember(Value("key", alloc), Value("value", alloc), alloc);
	j.AddMember(Value("number", alloc), Value(42), alloc);
	// Add JSON from document string
	JsonDocument d;
	d.Parse(R"({"array": [1, 2, 3], "boolean": true})");
	assert(!d.HasParseError());
	for (auto& m : d.GetObject())
		j.AddMember(m.name, m.value, alloc);
}

int main()
{
	printf("Hello from Storage!\n");
	return 0;
}
