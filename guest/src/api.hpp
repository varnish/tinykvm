#pragma once
#include <cstddef>
#include <cstdint>

extern "C" long syscall(int scall, ...);
extern "C" long native_syscall(int scall, ...);
extern "C" __attribute__((noreturn)) void exit(int code) __THROW;

#define PUBLIC(x)  extern "C" __attribute__((used)) x


extern uint32_t crc32c_sse42(const uint8_t* buffer, size_t len);

inline uint32_t crc32c_sse42(const char* buffer, size_t len) {
	return crc32c_sse42((const uint8_t *)buffer, len);
}
