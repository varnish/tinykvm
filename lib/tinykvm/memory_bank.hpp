#pragma once
#include <vector>
#include <mutex>

namespace tinykvm {

struct MemoryBank {
	char*       ptr;
	std::size_t size;
};

struct MemoryBanks {
	void  insert(char* ptr, std::size_t size);
	char* get(std::size_t size);

private:
	std::vector<MemoryBank> m_mem;
	std::mutex m_guard;
};

}
