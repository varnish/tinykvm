#pragma once

#ifndef LIKELY
#define LIKELY(x) __builtin_expect((x), 1)
#endif
#ifndef UNLIKELY
#define UNLIKELY(x) __builtin_expect((x), 0)
#endif

#ifndef TINYKVM_MAX_SYSCALLS
#define TINYKVM_MAX_SYSCALLS  128
#endif
