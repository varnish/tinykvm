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
bugs plus the futex wake (see Done). Guest signal-handler delivery now works
too — including a real CPython guest that installs a Python signal handler and
sees it fire (see below / Done). No item is currently gating a single-VM
Python/Node run on this hardware; what remains is broad-arm64 validation and
the warm-fork niceties (handler inheritance on fork, extended futex ops).

## Gating Python / Node

- [x] **Threading test coverage — create/join + mutex + condvar all pass.**
  `tests/unit/arm64_threads.cpp` has a raw pthread create/join + shared-memory
  test, a 4-thread mutex-contended counter, and a condition-variable
  producer/consumer — all passing. Writing them surfaced and fixed three real
  bugs (see Done): a swapped-arg `prlimit64`, an arm64 `memzero` dirty-bit
  mismatch, and — the big one — the cooperative scheduler switching the wrong
  banked SP; plus the address-aware futex wake below. Still to add: a real
  Node and a threaded-Python guest (gated on signal delivery).

- [x] **`futex` wake is now address-aware → condvars work.** The condvar test
  used to deadlock: `FUTEX_WAKE` resumed the *next* suspended thread regardless
  of which address it waited on, so a signal landed on the wrong waiter.
  Fixed by tagging each suspended thread with the address it blocked on
  (`Thread::futex_addr`, shared `linux/threads.hpp`): `FUTEX_WAIT` blocks on
  the address and the scheduler only resumes *runnable* threads (`futex_addr
  == 0`); `FUTEX_WAKE` marks up to `val` address-matching waiters runnable.
  Second, crucial part: the waker **yields to the woken thread**. The scheduler
  is cooperative and a producer never blocks on the mutex on its own (nothing
  else is running to hold it), so a non-yielding waker would run a flag-based
  producer to completion before the consumer ran once — lost-wakeup deadlock.
  Thread exit now also does a `FUTEX_WAKE` on `clear_tid` so `pthread_join`
  wakes properly. Mirrored into the shared amd64 scheduler (`linux/threads.cpp`
  — inspected, but not compile-run here: this Asahi host has no x86 KVM headers
  / cross-toolchain). Still unhandled and likely needed for Node/CPython:
  `FUTEX_CMP_REQUEUE` (4) / `FUTEX_WAKE_OP` (5) (still throw), timed waits, and
  `FUTEX_PRIVATE`/`FUTEX_CLOCK_REALTIME` flag handling.

- [x] **Guest signal handler delivery now works (incl. a real CPython guest).**
  `Signals::enter` builds a kernel-shaped `rt_sigframe` on the (alternate)
  stack and re-points the EL1h trap frame at the handler (x0=signo, x1/x2 =
  siginfo*/ucontext* for SA_SIGINFO, lr = a new EL0 `rt_sigreturn` trampoline
  in the vectors page, pc = handler). The interrupted GP+FP+SPSR context is
  snapshotted host-side (a per-thread LIFO, so nested handlers work) and
  restored by a new `rt_sigreturn` (139) handler. `kill`/`tkill`/`tgkill`
  (129/130/131) all route through one delivery helper: handler → deliver,
  SIG_IGN → drop, else default disposition (a few ignored, otherwise terminate
  with 128+signo). Tested in `tests/unit/arm64_signals.cpp` (9 cases:
  handler-runs-and-returns, SA_SIGINFO, FP/integer state preserved across the
  handler, SIG_IGN, re-entrant, worker-thread delivery, kill(), abort(), and
  default-termination) plus a real `python3` guest that installs a Python
  `signal.signal` handler, `raise_signal`s it, and observes the handler fire
  (`arm64_elf.cpp`). x9 needs special care on both save and restore: the EL1
  sync-vector stub banks the user's x9 in TPIDR_EL1 and reloads it on `eret`,
  so the snapshot reads x9 from TPIDR_EL1 and rt_sigreturn writes it back
  there. Known limits (fine for Python/Node, none hit in practice): only
  *synchronous* delivery via kill/tkill/tgkill is wired up — a guest fault
  (SIGSEGV/SIGFPE/&c, e.g. Python's faulthandler) still terminates the VM
  rather than invoking the guest handler; handler edits to `uc_mcontext` are
  not honored on return (restore is from the host-side snapshot);
  `FUTEX_CMP_REQUEUE`/`WAKE_OP`, timed waits, and the futex flag bits are still
  unhandled; and forks do not inherit the master's handlers (`m_signals` is
  recreated empty per fork — pre-existing, arch-neutral behavior in
  `machine.cpp`'s fork ctor, not specific to signals).

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

- [x] **Threading worked once the tests surfaced three hidden bugs.** Adding
  `arm64_threads.cpp` turned "threading is implemented" into create/join +
  mutex passing, by fixing — in order of discovery:
  1. *`prlimit64` had `new_limit`/`old_limit` swapped* (`linux/system_calls.cpp`,
     shared with amd64). A `RLIMIT_STACK` *read* (`new=NULL, old=&buf`) was
     misread as a *set*, so glibc's buffer was never filled — it then sized
     thread stacks from stack garbage and tried to `mmap` a ~4 GB stack.
  2. *`Machine::memzero` used amd64's dirty bit on arm64* (`machine_utils.cpp`).
     The "only zero dirty pages" check tested bit 6 = `PDE64_DIRTY` on amd64,
     but bit 6 on arm64 is `DESC_AP_USER` (set on *every* user page), so a
     large `PROT_NONE` mmap reservation (glibc's 128 MB malloc arena) was
     walked page-by-page off the end of guest RAM. Added arch-neutral
     `paging_dirty_bit()` (`paging.hpp` + both `*/paging.cpp`); arm64 returns
     `DESC_DIRTY` (bit 55).
  3. *The cooperative scheduler switched the wrong banked SP* (`arm64/vcpu.cpp`,
     the real fix). During a syscall the vCPU is at EL1h, so `registers()`
     returned the EL1 vector context: `pc` = the vector stub and `sp` =
     `sp_el1` (vector scratch). The thread scheduler switches stacks via
     `regs.sp`, so cloned threads got `sp_el1` set instead of their EL0 stack
     and ran on the **parent's** stack (glibc's `advise_stack_range` then
     aborted; futex resume restored the wrong context). Fix: at EL1h
     `get/set_arm64_regs` now map `regs.pc`↔`ELR_EL1` and `regs.sp`↔`SP_EL0`
     (`user_pt_regs.sp`, the EL0 user stack) instead of the vector PC and
     `sp_el1`. Harmless for single-threaded guests (handlers only touch GPRs),
     and `arm64_minimal`/`arm64_elf` (52 + 17 assertions) still pass.

- [x] **`reset_to` broke re-runs — fixed; root causes were not the page tables.**
  The tables were always rebuilt correctly (`setup_cow_mode` re-clones them).
  Two real bugs hid behind the symptom:
  1. *Deferred MMIO PC increment.* KVM advances the guest PC past a stop-MMIO
     store only on the next `KVM_RUN` entry — against whatever PC userspace
     loaded meanwhile, so every set-PC + re-run after a stop skipped its first
     instruction. Fixed by completing the MMIO eagerly with an
     `immediate_exit` dummy `KVM_RUN` at the stop/syscall-stop exits
     (`lib/tinykvm/arm64/vcpu_run.cpp`). Exit PC now points *past* the stop
     store, matching amd64 semantics.
  2. *Stale stage-1 guest TLB.* A host-side TTBR0_EL1 write flushes nothing,
     so after the reset rebuilt the tables the vCPU could still translate
     through recycled bank pages. Currently masked by the kernel's
     `tlbi vmalle1is` side effect of `MADV_DONTNEED` in `banks.reset()`, but
     fixed properly: a TLBI stub in the vectors page (`TLB_FLUSH_ADDR`) runs
     for one VM entry after every table switch
     (`arm64_flush_guest_tlb`, ~6 µs).
  Regression test: "ARM64 fork re-runs correctly after reset_to" in
  `tests/unit/arm64_minimal.cpp`. Bench now has `mixed+reset` configs:
  fast reset ≈ 33 µs vs ≈ 120 µs fresh fork per iteration.

- [x] **ARM64 static-ELF path.** The shared loader/`setup_linux`/syscall
  table were already arch-clean; the real gap was that guest RAM had no EL0
  access bits, so nothing could run in usermode. Guests now run at EL0
  (required for CoW integrity: an EL1 guest could rewrite its own stage-1
  tables and strip the read-only bits protecting master memory). RAM is
  user-RWX with a new L3 table for the first 2 MB (vectors page user-RO so it
  stays EL1-executable, PT/vCPU-table pages EL1-only, pages below 0x8000
  unmapped as a null-deref guard); the MMIO trap block is user-accessible so
  EL0 hits the stop/syscall MMIO directly. SCTLR gains SPAN/DZE/UCT/UCI/
  nTWI/nTWE for glibc string routines and PAN-safe vectors. `setup_linux`
  masks HWCAP_SVE/HWCAP_CPUID/HWCAP2_SME (host caps the vCPU lacks; CPUID
  invites EL0 ID-register reads our vectors treat as fatal). Static glibc
  binaries run end-to-end: argv/env, write(), heap (`dc zva`), `vmcall` into
  ELF functions, and forked CoW-isolated vmcalls — see `tests/unit/arm64_elf.cpp`
  (6 cases). Bench/reset numbers unchanged (~33 µs reset).

- [x] **ARM64 dynamic ELF (interpreter) path.** `ld-linux-aarch64.so.1`
  is loaded as the machine binary with the real program as argv, exactly like
  the amd64 `elf.cpp` tests. The mmap/protection machinery was already
  arch-clean (small files go through plain `preadv`); the real bugs were:
  1. *RELR double-relocation.* `dynamic_linking` pre-applied `.relr.dyn`
     (`*addr += base`, not idempotent) — but a glibc ET_DYN entered at its own
     entry point self-relocates, and modern aarch64 ld.so carries `DT_RELR`,
     so init_array/cpu_list pointers got `image_base` added twice → guest
     crash. ARM64 now leaves all relocation to the guest
     (`machine_elf.cpp`); the amd64 path is untouched.
  2. *Signal-table off-by-one.* The arm64 `Signals::get` stub indexed
     `at(sig)` instead of `at(sig-1)`, so CPython's rt_sigaction sweep
     (signals 1..64) threw out of the host. Also `rt_sigaction` now returns
     `-EINVAL` for sig > 64 (glibc `_NSIG` is 65) instead of crashing.
  Non-PIE dynamic executables (this gcc's default!) need
  `heap_address_hint` above the fixed link address, or ld.so's MAP_FIXED at
  0x400000 collides with the mmap arena — covered by a test. End-to-end:
  PIE + non-PIE C guests and a real `python3 -c "print(...)"` guest
  (512 MB, stdout via printer, clean exit) — `tests/unit/arm64_elf.cpp`
  (9 cases). `mmap_backed_files` works too: the Python test runs with it
  enabled and asserts libpython (5.9 MB) was served by a file-backed
  region. That needed two physical-address fixes: `MMAP_PHYS_BASE` moved
  from 256 GB to 32 GB on ARM64 (Apple-Silicon KVM caps stage-2 IPA at
  36 bits / 64 GB), and `TCR_EL1.IPS` widened from its implicit 4 GB to
  the VM's actual IPA size (was fine before only because every physical
  address — RAM, banks at 2 GB — sat below 4 GB).

- [x] **Write-prefetch optimization (Option A).** New
  `Machine::prefetch_pages(pages)` API (declared in `machine.hpp`, implemented
  in `memory.cpp`, cross-arch) batch pre-CoWs an `(addr, size)` range list with
  the same flags/dirty semantics as the write-fault path; block-sized entries
  are walked at page granularity. The full pipeline — warmup fork →
  `get_accessed_pages()` → replay via `prefetch_pages()` on every fork/reset —
  is now exercised end-to-end by `arm64_bench` (harvested set, no more
  hardcoded addresses) and by the unit test "ARM64 prefetch_pages pre-CoWs a
  harvested write set" (asserts zero write faults after prefetch, fresh-fork
  and reset_to paths). Steady-state numbers hold: ~32 µs reset + ~3.5 µs
  prefetch + ~101 µs run vs ~843 µs unprefetched (~6× on the mixed workload).
  Note: prefetching marks pages accessed, so a re-harvest from a prefetched
  fork never shrinks the set — harvest once from a clean warmup fork.

- [x] **`get_accessed_pages` decoupled onto `DESC_ACCESSED` bit (Option A).**
  Separate from `DESC_DIRTY` so the fork reset can't corrupt CoW's
  duplicate-vs-zero decision. Builds clean, 27/27 arm64 tests pass.

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
