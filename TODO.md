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
bugs plus the futex wake. Guest signal-handler delivery now works too (see
Done), so the threading and signal prerequisites for Python/Node are in place.

## Gating Python / Node

- [ ] **Add a threaded-Python and a Node guest test.** The threading, futex,
  and signal-delivery prerequisites are now done and unit-tested; what's left
  is an end-to-end guest that combines them. A single-threaded `python3 -c`
  guest already runs (`arm64_elf.cpp`); extend to a threaded-Python script and
  a real Node guest to shake out anything the micro-tests miss.

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

## Done

- [x] **Guest signal-handler delivery on ARM64.** `Signals::enter` no longer
  throws: it now redirects EL0 to the registered handler the same way the
  cooperative scheduler redirects threads. It saves the interrupted EL0 frame
  (via `cpu.registers()` at EL1h → ELR_EL1/SP_EL0) into the per-thread
  `sigret` slot, then sets x0=sig, x30=`SIGRETURN_ADDR`, pc=handler, and
  optionally switches to the SA_ONSTACK altstack. A 2-instruction `rt_sigreturn`
  trampoline (`movz x8,#139; svc #0`) lives in the unused 16th vector slot
  (`SIGRETURN_ADDR`, EL0-executable); the handler returns into it, and the new
  `rt_sigreturn` (139) syscall restores the saved frame — exactly like
  `Thread::resume`. `tgkill` now delivers to a registered handler (SIG_DFL/
  SIG_IGN and the default-ignored signals keep their old dispositions; unhandled
  fatal signals still terminate with 128+sig). `sigaltstack` storage was
  unified onto `gettid()` (was hardcoded `per_thread(0)` on arm64) so delivery
  reads back the stack the guest set. New `tests/unit/arm64_signals.cpp`
  (8 cases): delivery+resume, context preservation, 1000× repeated delivery,
  SIG_IGN drop, SA_ONSTACK, unhandled-fatal terminate, a signal raised on a
  worker thread under the scheduler, and nested delivery (a handler that raises
  a second signal). 4/4 arm64 suites pass.
  A code-review pass then hardened it: the per-thread `sigret` is now a **stack**
  of frames so nested signals restore correctly (was a single slot that lost the
  outer frame); the SA_ONSTACK top is 16-byte aligned per AAPCS; `static_assert`s
  guard the packed 16th-vector-slot layout; and a pre-existing amd64 off-by-one
  in `Signals::enter` (`signals.at(sig)` vs the `sig-1` storage) was fixed.
  Known limits (acceptable, matching the minimal amd64 model; revisit if a guest
  needs them): no signal masking / `sa_mask` during the handler (same signal can
  re-enter, though the frame stack keeps nesting safe); no siginfo/ucontext
  (x1/x2) for `SA_SIGINFO` handlers — only x0=sig; FP/SIMD not saved across the
  handler (AAPCS callee-saved are safe); synchronous delivery only
  (tgkill/raise/pthread_kill — no async/timer signals exist in this model).

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
