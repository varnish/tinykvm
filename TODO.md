# TODO — ARM64 backend

Outstanding work on the `arm64` branch, in rough priority order.

## Goal

Run tinykvm guests on **ARM64** under KVM. The port already runs on
Apple-Silicon arm64 (Asahi); broad arm64 is the target. BlueField 4 (NVIDIA
DPU) is a bonus deployment, not a gate. Target guest workloads are **Python and
Node**, which means the cooperative multithreading path has to be real and
tested — not just present.

## State of the port

The warm-fork CoW sandbox path is functionally complete and tested:
static + dynamic (ld.so) ELF, CoW fork / `reset_to` (~33 µs fast reset),
file-backed mmap, write-prefetch, accessed-page harvesting, EL0 usermode with
CoW-integrity protection, and clean VM teardown on fatal guest signals. A real
`python3 -c` guest runs end-to-end (single-threaded). 20 tests pass
(`arm64_minimal`, `arm64_elf`).

The cooperative multithreading engine is **implemented and partly verified** on
arm64 (`arm64/stubs.cpp`): `clone`/`clone3`/`futex`/`gettid`/`set_tid_address`/
`sched_yield`/`exit`/`tgkill` and the full `MultiThreading` scheduler, using
arch-neutral accessors (`stackptr()`/`sysret()`/`sysarg()`, `set_tls_base` →
TPIDR_EL0). It mirrors the amd64 model: one vCPU, green-thread cooperative
scheduling (a thread runs until it blocks on a futex/yield, then hands off).
True SMP (parallel vCPUs) is intentionally **not** implemented — amd64 runs
guest threads cooperatively on one vCPU too, so this matches the warm-fork
design.

A real pthread test (`tests/unit/arm64_threads.cpp`) now exercises it.
**pthread create/join, mutex-contended counters, and condition-variable
producer/consumer all work** end to end; getting there fixed three scheduler
bugs plus the futex wake. The remaining gap before Python/Node is
guest signal-handler delivery (see below).

## Gating Python / Node

- [ ] **Guest signal handler delivery is stubbed.** `Signals::enter` throws
  ("Guest signals are not implemented on ARM64"). Today any non-ignored signal
  terminates the VM via `tgkill` even if the guest registered a handler. Node
  and CPython both install handlers (SIGPIPE, SIGINT, SIGCHLD). Port the
  `linux/signals.cpp` `enter()` path to arm64 so guests can handle signals
  instead of dying.

## Performance

- [ ] **Validate beyond Apple Silicon.** Current numbers are from an
  Asahi/Apple-Silicon dev box — real arm64, but one microarchitecture. Shape
  holds (reads free, each CoW write ≈ one ~3 µs VM-exit, prefetch removes
  exits), but absolute µs will differ on arm64 servers (Graviton/Ampere) and on
  BlueField 4. DPU cores are likely slower per-core, which would make the
  prefetch win larger. Not a gate — a confidence check.

- [ ] **Reduce fixed per-fork cost (~88 µs).** Page-table setup per fork is a
  flat overhead independent of workload — a separate lever if per-agent latency
  matters.

## Decided / not doing (kept for context)

- [ ] **Option B (read-access tracking via AF faults): not worth building** for
  the warm-fork model — reads never fault (benchmark: 256 reads → 0 faults), so
  there is nothing to prefetch. Only revisit if the harness switches to a
  demand-paged / snapshot-restore memory model.

- [ ] **True SMP (parallel vCPUs): not planned.** The warm-fork model is one
  vCPU per agent; guest threads run cooperatively on that vCPU, matching amd64.

## Housekeeping (low priority)

- [ ] **`unittests.yml` jobs are green no-ops on hosted runners.** Both jobs use
  `runs-on: ubuntu-latest` (x86_64, no `/dev/kvm`), so the KVM gate skips all
  build/test steps and PRs show passing checks with zero tests run. Needs
  self-hosted KVM runners (x86_64 and aarch64) or the green check is misleading.

- [ ] **Document `get_accessed_pages` semantics** in `paging.hpp` —
  arm64 reports written (not read) pages, reset per fork; reads untracked by
  design (AF pre-set).

- [ ] Decide whether to commit `src/arm64_bench.cpp` + its CMake target, or keep
  it local as a profiling tool.
