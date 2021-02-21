#pragma once
#include <cstddef>

extern "C" long syscall(int scall, ...);
extern "C" __attribute__((noreturn)) void exit(int code) __THROW;

#define PUBLIC(x)  extern "C" __attribute__((used)) x
