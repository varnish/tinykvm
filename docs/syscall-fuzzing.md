# Fuzzing the syscall emulation layer

`fuzz/syscall_fuzz.cpp` is a coverage-guided fuzzer for the host-side Linux
emulation in `lib/tinykvm/linux/`. It exists because that layer is the only
channel an untrusted guest has into the host process, and it is ~3300 lines of
hand-written pointer and length arithmetic over ~112 syscall handlers, every one
of which reads six fully guest-controlled 64-bit register arguments.

```bash
fuzz/syscall_fuzzer.sh                  # build + run until interrupted
fuzz/syscall_fuzzer.sh -runs=1000000    # extra libFuzzer flags pass through
fuzz/triage_syscall_crashes.sh          # group artifacts by root cause
```

Requires clang (libFuzzer), gcc (for the guest ELF), and `/dev/kvm`.

## How it works

The harness builds a master VM from a small static guest
(`fuzz/guest/syscall_fuzz_guest.c`), prepares it copy-on-write, and drives
`Machine::system_call()` **directly** on a fork — no VM entry, no trampoline.
The code under test is host code either way, so this runs at ~10k execs/second
under ASan+UBSan instead of the ~100/second a guest-driven harness would manage.
Each input is a sequence of records:

- `POKE` writes fuzzer-chosen bytes into guest memory.
- `CALL` sets the six syscall argument registers and dispatches a syscall number.

`POKE` is what makes the pointer arguments worth anything: most handlers read
structs out of the guest (`iovec`, `sockaddr`, `msghdr`, `pollfd`, `timespec`,
path strings), so the fuzzer has to control both the pointer *and* the bytes it
points at. Pointer arguments are drawn from a table of *interesting* guest
addresses — page boundaries, the last bytes of a mapping, one page past the end,
unmapped holes, non-canonical addresses — because uniformly random 64-bit
pointers just bounce off `copy_from_guest()` and coverage flatlines.

The fork is reset from the master after every input, which also closes any file
descriptors the guest opened, so inputs stay reproducible.

### Oracle

- `MachineException` (and subclasses) escaping a handler is **correct** — that is
  how the layer rejects a bad pointer or length. Caught and ignored.
- ASan/UBSan reports are findings.
- Any *other* `std::exception` escaping a handler is reported once per unique
  type+message. An embedder that catches `MachineException` would let these
  through into its own request loop. `TINYKVM_FUZZ_STRICT=1` turns them into
  hard findings.

### Sandboxing

The handlers really do call `open`, `write`, `connect`, `mmap`. The harness
therefore:

- rewrites every guest path to one of two files in a private temp directory, so
  the whole open→manage→translate→read/write→close path is exercised with no way
  to reach the rest of the filesystem;
- denies `connect`/`bind`/`listen`/`accept`, so sockets are created and tracked
  but there is no egress;
- sets `O_NONBLOCK` on every fd the guest creates, so `read()` on an empty pipe
  cannot wedge a worker;
- refuses a short list of syscalls that either block for a guest-controlled
  duration or have side effects outside the sandbox (see `blocked_syscall()`).

Note that `blocked_syscall()` is a *harness* concession, not a statement that
those syscalls are safe. As it stands, **none of the syscalls on that list has a
handler** — they all fall through to the unhandled path and return `-ENOSYS`, so
refusing them costs no coverage today and only guards against a future handler
that would block a worker or escape the sandbox.

The two blocking handlers that *do* exist are covered rather than refused:

- `accept4` — its `accept_callback` is consulted before the blocking `accept4()`,
  and the sandbox installs one that declines, so the handler's prefix is still
  exercised.
- `clock_nanosleep` — wrapped to clamp the *values* of the guest `timespec` in
  guest memory to 1µs before running the original handler unmodified. The fuzzer
  still picks the pointer, so the `copy_from_guest`/`copy_to_guest` edges (the
  part worth fuzzing) stay reachable and only the duration is bounded.

That clamp exists because the real handler passes a guest-controlled `timespec`
straight to `clock_nanosleep()`: a guest can pin a host thread for years, and
like finding #5 this sits inside the syscall handler where the execution timeout
does not reach. Unlike #5, bounding it changes guest-visible semantics (a guest
may legitimately want to sleep), so it is left as a decision — see below.

## What it found

First campaign, ~20M executions. All of these are reachable from an ordinary
unprivileged guest using legal syscalls, and all are fixed in the same series of
commits as this document except where noted.

| # | Site | Bug | Impact |
|---|------|-----|--------|
| 1 | `getdents64` | host return value stored in `__u64 sysret()` then tested `> 0`, so `-1` became a ~2^64 `copy_to_guest` length | host stack streamed into guest memory, then a wild copy — **info leak + crash**, reachable via `getdents64` on any regular fd (ENOTDIR) |
| 2 | `sendmsg` | `msg_namelen` copied from the guest into a 128-byte `sockaddr_storage` with no bound | **guest-controlled stack buffer overflow** |
| 3 | `sendmmsg` | `vlen` checked only for `> 0` before being used as a copy length into a 64KB stack array | **guest-controlled stack buffer overflow** |
| 4 | `write`, `read`, `pread64`, `pwrite64`, `mmap`, `recvmsg`, `sendmsg`, `sendto`, `recvfrom`, `sendmmsg` | zero-length request gathers no buffers, then `buffers[0]` / `&buffers[0]` on the empty vector | `write(fd, p, 0)` — a legal no-op — **null-dereferences and kills the VMM**; UB elsewhere |
| 5 | `madvise(MADV_DONTNEED)` → `Machine::memzero` | guest length walked one page-table lookup per 4K, missing pages silently skipped, no bound | **unkillable host hang**: ~9M pages/s, so a 2^64 length pins the thread for years, and it is inside the syscall handler so the execution timeout does not apply |

The clamp added for #5 bounds the walk to `memory.remote_end` (plus a connected
remote's range). That is the right bound for *virtual* addresses, which is what
`memzero` receives: `mmap_allocate()` hands out virtual addresses starting at
`heap_address` and well below `max_address` — `vMemory::MMAP_PHYS_BASE`
(0x4000000000) is the **physical** base of the mmap arena, not a virtual one, so
mmap'd guest memory is inside the clamped range and is still zeroed. Verified
both by measurement and by the positive
`madvise(MADV_DONTNEED) still zeroes in-range memory` test, which checks a full
range and a partial (middle-pages-only) discard.

A second test connects a storage VM so `has_remote()` is true, which is the only
way to reach the remote-widening branch of that clamp. Be aware of what it does
and does not show: it proves the branch runs and does not break zeroing of the
VM's *own* memory. It cannot show the widening is *necessary*, since a narrower
bound would still cover own memory. Whether a guest should be able to
`madvise(MADV_DONTNEED)` a connected storage VM's pages at all is a separate
isolation question, and arguably the answer is no — worth settling before anyone
relies on the current behaviour.
| 6 | `prctl(PR_GET_NAME)` | `buflen` (up to 16) read straight out of the 8-byte literal `"tinykvm"` | OOB read; adjacent `.rodata` handed to the guest |
| 7 | `ppoll` | `ts.tv_sec * 1000` on a raw guest value | signed-overflow UB, then truncation to an arbitrary timeout |
| 8 | `recvmsg`, `recvfrom` | `socklen_t&` bound to a guest pointer of arbitrary alignment | UB; benign on x86-64, matters under stricter codegen |
| 9 | `openat` | non-zero `open_how.mode` passed for every write-open; `openat2` requires `mode == 0` without `O_CREAT` | functional: guests could **never** open an existing file for writing (EINVAL). Found while writing the regression test for #4, not by the fuzzer |
| 10 | `timerfd_create`, `eventfd2`, `inotify_init1` | failed host fd passed to `FileDescriptors::manage()`, which *throws* on a negative fd — so the `if (vfd < 0)` below each call was dead code | `std::runtime_error` escapes the handler; `timerfd_create`'s `clockid` and `inotify_init1`'s `flags` are guest-controlled, so any guest can trigger it. `epoll_create1` in the same file already had the correct shape |

Regression tests for these are in `tests/unit/syscalls.cpp`.

### Not fixed: guest-triggerable `std::runtime_error`

Finding #10 is one instance of a wider issue. The layer's contract is that guest
misbehaviour surfaces as `MachineException` (`MemoryException` and
`RetryException` derive from it), which is what embedders catch. But several
paths throw plain `std::runtime_error` instead, and a guest can reach them at
will:

- `futex()` with any unimplemented operation —
  `throw std::runtime_error("Unimplemented futex op: N")` in
  `linux/threads.cpp`. `FUTEX_REQUEUE` is enough.
- `FileDescriptors::manage()` on hitting `max_files`, and on a negative fd
  (finding #10 was the reachable route to the latter).
- `FileDescriptors::translate_writable_vfd()` — "File descriptor is not
  writable", reachable by writing to any read-only fd.

Retyping these to `MachineException` is the obvious fix and is what the rest of
the layer does, but it is left alone here because it changes the library's
exception taxonomy — an embedder could plausibly be catching `std::runtime_error`
specifically today. Worth deciding deliberately rather than as a fuzzing
by-product. Until then, embedders should catch `std::exception`, not just
`MachineException`.

The harness reports these once per unique type+message rather than treating them
as crashes; `TINYKVM_FUZZ_STRICT=1` promotes them to hard findings.

### Not fixed: SIGPIPE kills the VMM

```c
int fds[2]; pipe2(fds, 0); close(fds[0]); write(fds[1], buf, 16);
```

Three legal syscalls, and the host process dies with SIGPIPE. The emulation
layer passes `MSG_NOSIGNAL` on the `sendmsg`/`sendto` paths, so the hazard is
clearly known, but plain `write()`/`writev()`/`pwritev64()` have no equivalent
and pipes cannot be protected that way at all.

This is left as a deliberate decision rather than a patch, because every fix
changes something outside the library's own scope:

- `signal(SIGPIPE, SIG_IGN)` in `Machine::init()` is what most servers want, but
  silently changing a host process's signal disposition is a side effect a
  library arguably should not impose (the `src/` example CLIs would stop dying on
  `EPIPE` when piped into `head`).
- Using `send(..., MSG_NOSIGNAL)` for socket fds would need `FileDescriptors` to
  actually retain the `is_socket` flag it is currently passed and discards, and
  still leaves pipes exposed.
- Blocking SIGPIPE around each write is correct but costs a syscall pair per I/O.

Until it is decided, **embedders must ignore SIGPIPE**. The fuzz harness does so
itself, with a comment pointing here.

## Notes for future work

- `writable_memarray<T>(guest_ptr, guest_count)` in `poll`/`ppoll` binds a `T*`
  to a guest-chosen address with a guest-chosen count. The count is bounded by
  the mapping check inside `writable_memview`, but the *alignment* is not, which
  is the same UB as finding #8. Fixing it means either copying in/out or
  rejecting misaligned arrays with `-EFAULT`; the latter changes guest-visible
  semantics, so it needs a decision.
- `poll`/`ppoll` honour a guest timeout verbatim on a forked VM, so they can
  block a worker indefinitely. The harness neutralises this with a
  `poll_callback` returning false; production embedders should bound it.
- `poll`, `ppoll`, `epoll_wait` and `accept4` all `return` early when their
  callback declines, *without* setting `sysret()`. The guest therefore reads
  whatever was already in the return register — at syscall entry on AMD64 that is
  the syscall number, so e.g. a declined `accept4` looks like it returned fd 288.
  This is presumably fine when the embedder's callback also pauses or reschedules
  the guest, but it is an implicit part of the callback contract that is not
  documented anywhere, and is a trap for a new embedder.
- `readv()` (syscall 19) has no handler at all, so it returns `-ENOSYS`, while
  `writev()` is fully implemented. Noticed while writing the positive
  round-trip test in `tests/unit/syscalls.cpp`. Not a safety issue — a guest
  just sees ENOSYS — but the asymmetry is surprising, and glibc does use `readv`
  in some configurations.
- `TINYKVM_FUZZ_UNSAFE=1` installs the "unsafe" set — `symlink`, `fchdir`,
  `io_uring_setup`, `inotify_init1`, `inotify_add_watch`. It has only been
  smoke-tested (20k execs), which is what surfaced finding #10 via
  `inotify_init1`. The path-taking handlers there are properly gated through
  `is_writable_path`/`is_readable_path`, and `io_uring_setup` is an `-ENOSYS`
  stub, so the surface is small — but it deserves a real campaign.
- ARM64 is untested here; the harness itself is arch-neutral but has only been
  run on AMD64.
