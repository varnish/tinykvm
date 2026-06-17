# TinyKVM ARM64 Feature Matrix

Status reflects the in-tree ARM64 backend. AMD64 remains the reference backend
for behavior that is shared across architectures.

| Feature | Status | Notes |
| --- | --- | --- |
| Raw ARM64 guest execution | Implemented | Guests run at EL0 (EL1 hosts the vectors/stubs only); MMIO stop exits and direct `vmcall` entry are covered by ARM64 unit tests. |
| Static ELF loading | Implemented | `Machine(binary)` + `setup_linux(args, env)` runs statically linked AArch64 Linux ELFs (glibc tested) at EL0; covered by the `arm64_elf` unit tests. |
| Dynamic ELF / interpreter loading | Deferred | `is_dynamic_elf` detection is shared, but the interpreter (`ld-linux-aarch64`) path is untested on ARM64. |
| ARM64 SVC syscall exits | Implemented | SVC traps through the ARM64 MMIO syscall ABI and dispatches through the shared syscall table. |
| Linux syscall argument adapter | Implemented | ARM64 syscall dispatch uses the arch register adapter in `linux/system_calls.cpp`. |
| Copy-to/from guest memory | Implemented | Host API writes mark ARM64 page descriptors dirty and invalidate the instruction cache for copied code. |
| Copy-on-write fork/reset | Implemented | Guest write faults allocate writable pages and preserve master memory in the ARM64 runtime tests. |
| Snapshot state | Implemented | ARM64 CPU and memory snapshot create/open paths are covered by runtime tests. |
| FP/NEON register state | Implemented | ARM64 fixed SIMD/FP state is saved and restored through KVM one-reg access. |
| Accessed/dirty page reporting | Implemented | `get_accessed_pages` reports dirty ARM64 L2 blocks and L3 pages for incremental copy paths. |
| Hugepage merge | Implemented | Uniform contiguous 4 KiB L3 leaves can merge into 2 MiB L2 blocks. The old L3 page-table page is retired from the walk but not reclaimed. |
| ARM64 example | Implemented | `arm64_demo` runs a raw AArch64 guest and exits through the TinyKVM MMIO ABI. |
| ARM64 CI build | Implemented | The CMake workflow builds both AMD64 and ARM64 backends. |
| ARM64 runtime CI tests | Partial | The workflow runs ARM64 tests only on an AArch64 runner with `/dev/kvm`; other runners skip cleanly. |
| 4 KiB guest page granule | Implemented | Page tables and `TCR_EL1` are configured for 4 KiB granules. |
| 16 KiB / 64 KiB page granules | Deferred | The ARM64 backend still assumes 4 KiB pages in descriptor masks, index shifts, and `TCR_EL1`. |
| SMP | Deferred | ARM64 SMP entry points intentionally throw until implemented. |
| Remote VM support | Deferred | ARM64 remote VM entry points intentionally throw until implemented. |
| Guest signal delivery | Implemented | `tgkill` delivers registered handlers through the shared signal dispatcher; ARM64 handlers return through an EL0 `rt_sigreturn` trampoline, including nested-frame restore and alternate-stack coverage in unit tests. |
| Remote GDB support | Deferred | ARM64 remote GDB support intentionally throws until implemented. |
| Hardware breakpoints | Deferred | ARM64 breakpoint support intentionally throws until implemented. |
| SVE/SVE2 | Deferred | Scalable vector state is not implemented. |
| PAC/BTI/MTE | Deferred | ARM-native security extensions are not enabled for guests yet. |
| Performance benchmarks | Deferred | No committed ARM64 vs AMD64 fork/syscall/hugepage benchmark numbers are present. |
