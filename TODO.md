# TODO — ARM64 backend

Outstanding work on the `arm64` branch, in rough priority order.

## Bugs

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

## Features

- [x] **ARM64 static-ELF path — done.** The shared loader/`setup_linux`/syscall
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

- [x] **ARM64 dynamic ELF (interpreter) path — done.** `ld-linux-aarch64.so.1`
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

- [x] **Write-prefetch optimization (Option A) — done.** New
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

## Performance

- [ ] **Run `arm64_bench` on BlueField 4.** Current numbers are from an
  Apple-Silicon/Asahi dev box. Shape holds (reads free, each CoW write ≈ one
  ~3 µs VM-exit, prefetch removes exits), but absolute µs will differ; DPU cores
  are likely slower per-core, which would make the prefetch win larger.

- [ ] **Reduce fixed per-fork cost (~88 µs).** Page-table setup per fork is a
  flat overhead independent of workload — a separate lever if per-agent latency
  matters.

## Decided / not doing (kept for context)

- [x] **`get_accessed_pages` decoupled onto `DESC_ACCESSED` bit (Option A).**
  Done — separate from `DESC_DIRTY` so the fork reset can't corrupt CoW's
  duplicate-vs-zero decision. Builds clean, 27/27 arm64 tests pass.
- [ ] **Option B (read-access tracking via AF faults): not worth building** for
  the warm-fork model — reads never fault (benchmark: 256 reads → 0 faults), so
  there is nothing to prefetch. Only revisit if the harness switches to a
  demand-paged / snapshot-restore memory model.

## CI / housekeeping

- [ ] **`unittests.yml` jobs are green no-ops on hosted runners.** Both jobs use
  `runs-on: ubuntu-latest` (x86_64, no `/dev/kvm`), so the KVM gate skips all
  build/test steps and PRs show passing checks with zero tests run. Needs
  self-hosted KVM runners (x86_64 and aarch64) or the green check is misleading.

- [ ] **Optional: document `get_accessed_pages` semantics** in `paging.hpp` —
  arm64 reports written (not read) pages, reset per fork; reads untracked by
  design (AF pre-set).

- [ ] Decide whether to commit `src/arm64_bench.cpp` + its CMake target, or keep
  it local as a profiling tool.
