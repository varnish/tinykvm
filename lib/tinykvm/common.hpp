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
#include <string>
#include <string_view>

namespace tinykvm
{
	struct MachineOptions {
		uint64_t max_mem;
		uint32_t max_cow_mem = 0;
		float timeout = 0.f;
		std::string_view binary = {};

		bool verbose_loader = false;
		bool linearize_memory = false;
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

	class MachineTimeoutException: public MachineException {
	public:
		using MachineException::MachineException;
		float seconds() const noexcept { return data() / 62500000.0; }
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
