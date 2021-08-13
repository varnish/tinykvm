#pragma once

#ifndef LIKELY
#define LIKELY(x) __builtin_expect((x), 1)
#endif
#ifndef UNLIKELY
#define UNLIKELY(x) __builtin_expect((x), 0)
#endif

#ifndef TINYKVM_MAX_SYSCALLS
#define TINYKVM_MAX_SYSCALLS  384
#endif

#define TINYKVM_COLD()   __attribute__ ((cold))

#include <cstdint>
#include <exception>
#include <functional>
#include <string>

namespace tinykvm
{
	struct MachineOptions {
		uint64_t max_mem;
		uint32_t max_cow_mem = 0;

		bool verbose_loader = false;
		std::function<char*(size_t N)> page_allocator = nullptr;
		std::function<void(char*)> page_deallocator = nullptr;
	};

	class MachineException : public std::exception {
	public:
	    MachineException(const char* msg, uint64_t data = 0)
			: m_msg(msg), m_data(data) {}
	    const char* what() const noexcept override {
	        return m_msg;
	    }
		auto data() const noexcept { return m_data; }
	private:
		const char* m_msg;
		uint64_t m_data;
	};

	class MemoryException: public std::exception {
	public:
	    MemoryException(const char* msg, uint64_t addr, uint64_t sz)
			: m_msg(msg), m_addr(addr), m_size(sz) {}
	    const char* what() const noexcept override {
	        return m_msg;
	    }
		auto addr() const noexcept { return m_addr; }
		auto size() const noexcept { return m_size; }
	private:
		const char* m_msg;
		uint64_t m_addr;
		uint64_t m_size;
	};

	template<typename T>
	struct is_string
		: public std::disjunction<
			std::is_same<char *, typename std::decay<T>::type>,
			std::is_same<const char *, typename std::decay<T>::type>
	> {};

	template<class T>
	struct is_stdstring : public std::is_same<T, std::basic_string<char>> {};
}
