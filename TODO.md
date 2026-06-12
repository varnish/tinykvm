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

- [ ] **ARM64 ELF / dynamic-loading path.** Backend only runs raw hand-assembled
  guests today (`lib/tinykvm/arm64/` has no ELF handling, only stubs). Needed to
  run a real Python "agents.py" guest and get end-to-end numbers instead of
  synthetic microbenchmarks.

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
