# AGENTS.md

This file provides guidance to AI agents when working with code in this repository.

## What this is

TinyKVM is a **C++20 static library** (`lib/tinykvm/`) for embedding KVM-based
userspace emulation into a host program. It is not a runtime, VMM product, or
standalone binary: consumers (e.g. Varnish's vmod-tinykvm, or other embedders)
link `libtinykvm` and drive the `tinykvm::Machine` API directly. Everything
under `src/` is just example/benchmark programs exercising the library, and
`guest/` holds sample guest programs for them.

There is no guest OS. A guest is an ordinary, unmodified Linux userspace ELF
(static or dynamic) running at native speed under hardware virtualization. A
tiny built-in "kernel" — a few pages of trampolines — bounces every guest
syscall out to the host process via a port-I/O VM exit, where the **host
emulates Linux** in `lib/tinykvm/linux/system_calls.cpp`. Embedders can
override any syscall via the static handler table
(`Machine::install_syscall_handler`); `Machine::setup_linux_system_calls()`
installs the default emulation.

## Build

```bash
# Library + example binaries (bench, tinytest, simplekvm, storagekvm, pipekvm, syscall_bench)
mkdir -p build && cd build && cmake .. && make -j8
```

CMake options: `SANITIZE=ON` (ASan+UBSan), `FLTO=ON` (thin LTO, needs lld),
`KVM_EXPERIMENTAL=ON` (fast execution timeouts). The example binaries take a
guest ELF path as argv[1]; guest programs are built separately in `guest/*`
subdirectories (each has its own build script or Makefile). Running anything
requires `/dev/kvm` access.

## Tests

```bash
tests/run_unit_tests.sh          # builds into tests/build_unittests + runs ctest
```

The script initializes the `tests/Catch2` submodule on first run. Tests are
Catch2 binaries in `tests/unit/`, one executable per file (fork, reset, mmap,
remote, timeout, seccomp, ...). Most tests **compile small C guests at test
time** via `codebuilder.cpp` — a working `gcc` is required (override with the
`CC` env var).

Run a single test suite or case:

```bash
cd tests/build_unittests
ctest -R test_fork --verbose      # by ctest name
./fork "Verify fork and reset"    # directly, with a Catch2 test-name filter
```

`fuzz/fuzzer.sh` builds and runs the libFuzzer-based ELF loader fuzzer
(clang required).

## Architecture

### Two backends, chosen at configure time

`TINYKVM_ARCH` is AMD64 or ARM64 (auto-detected from the host). The backends
share `machine.*`, `memory*`, and the Linux emulation layer; arch-specific
code lives in `lib/tinykvm/amd64/` and `lib/tinykvm/arm64/`. **AMD64 is the
reference backend**; ARM64 is partial — `docs/arm64-feature-matrix.md` is the
authoritative status list (SMP, remote VMs, GDB support intentionally throw).
Cross-cutting changes usually need doing twice, or a stub/throw on ARM64.

### Machine lifecycle and the fork model

The central abstraction is `tinykvm::Machine` (`lib/tinykvm/machine.hpp`).
The signature workflow — what the library is *for* — is warm forking for
request-based workloads:

1. `Machine::init()` once per process; construct a **master** from an ELF +
   `MachineOptions` (`common.hpp`), `setup_linux(args, env)`, `run()` through
   the guest's initialization.
2. `prepare_copy_on_write()` freezes the master (it is never run again; its
   FPU/register state is snapshotted at prepare time for cross-process use).
3. `Machine(master, options)` creates cheap CoW **forks**: they share the
   master's pages read-only and materialize private pages on write faults
   from a per-fork memory bank (`memory_bank.cpp`). `reset_to(master, ...)`
   returns a dirty fork to pristine state without reconstructing it.
4. Work is done either by running the guest or via `vmcall()` /
   `timed_vmcall()` — SYSV function calls into the guest at a resolved symbol
   address, with execution timeouts.

CoW paging, page materialization, and the fork/reset paths (`memory.cpp`,
`memory_bank.cpp`, `page_streaming.cpp`, `machine_state.cpp`) are the most
invariant-heavy code in the tree — stale-TLB and register-state bugs here are
subtle and have bitten before. Be conservative and test with the fork/reset
unit tests.

### Other load-bearing pieces

- **Remote VMs** (`remote.cpp`): two Machines can merge address spaces so one
  guest calls into another (the "storage" pattern; see `src/storage.cpp` and
  `storage.sh`).
- **Guest ABI blobs** (`lib/tinykvm/amd64/builtin/`): the in-guest trampoline
  code is NASM source pre-assembled and committed as `kernel_assembly.h`.
  Editing `interrupts.asm` etc. does nothing until you regenerate the header
  with the adjacent `assembly.sh` (requires `nasm`, `xxd`) and commit both.
- **Sandboxing is two-layered**: the syscall emulation layer decides what the
  *guest* may do (payload-aware); the optional two-phase seccomp-BPF filter
  (`linux/seccomp.hpp`, `docs/seccomp.md`) bounds what the *VMM process
  itself* can execute after compromise. They are complementary — don't move
  responsibilities between them.
- **Threads/signals/fds**: guest multithreading is emulated on one vCPU
  (`linux/threads.cpp`); guest fds are virtualized through a translation
  layer (`linux/fds.cpp`) which is also where path/socket policy hooks live.

## License

GPL-3.0 with a commercial dual-licensing option held by Varnish Software;
contributions fall under the CLA in `CONTRIBUTOR_LICENSE_AGREEMENT.md`.
