# Host-side seccomp sandbox

TinyKVM's guest-facing syscall emulation (`lib/tinykvm/linux/`) is the
first security layer: it decides what a guest may ask for, with full
payload awareness (paths, socket addresses, virtual fds). The seccomp
sandbox in `lib/tinykvm/linux/seccomp.hpp` is the second layer, behind
it: a kernel-enforced allowlist bounding what the **VMM process itself**
can execute. If a bug in a syscall handler is ever exploited, the
attacker lands inside a process that can no longer `execve`, `ptrace`,
`mount`, load kernel modules, or issue any syscall outside the small
set the emulation layer legitimately needs.

The layers are complementary, not redundant: BPF cannot dereference
pointers, so seccomp can never check a path or a sockaddr — that depth
belongs to the emulation layer. Conversely, the emulation layer cannot
defend against its own compromise — that is what seccomp is for.

## Two phases

Seccomp filters stack and can only ever tighten; installation is
irrevocable. This maps onto the guest lifecycle:

```cpp
#include <tinykvm/linux/seccomp.hpp>

// At VMM startup: wide allowlist. Guest initialization (ELF loading,
// dynamic linking, warm-fork prepare) needs a broad footprint, and the
// guest is not yet processing untrusted input. Still excludes the
// host-takeover set (execve, ptrace, mount, bpf, ...).
tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Init);

// ... load and prepare the master VM ...

// After prepare(), before serving the first request: strict allowlist.
// Only the KVM_RUN loop and what the syscall handlers actually call.
tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Runtime);
```

In a fork-per-VM architecture, install `Init` in the parent and
`Runtime` in each child after `fork()` — filters are inherited.

## Scope warning: threads

Filters apply to the **calling thread** by default, or to all threads
with `SeccompOptions::all_threads` (TSYNC). Both are permanent. A
thread-pool thread that installs a filter stays filtered after it
returns to the pool. Embedders that share threads between TinyKVM and
other work (e.g. a Varnish worker process) must dedicate threads to VM
execution or isolate VMs in their own process before using this.

Embedder callbacks (`connect_socket_callback`, path callbacks, logging)
run on the filtered thread. If a callback needs syscalls outside the
built-in tables (e.g. DNS resolution), add them via
`SeccompOptions::extra_rules`.

## Validating the allowlist (soak mode)

The built-in tables are derived from reading the handlers and verified
against the unit test suite; treat them as a starting point. Before
enforcing in a new environment (new glibc, new allocator, new embedder),
soak with log-only mode:

```cpp
tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Runtime,
                                { .log_only = true });
```

Violations are logged to the kernel audit log instead of killing the
process. Run production-like workloads, then check `dmesg | grep SECCOMP`
(or auditd, `type=SECCOMP`); the `syscall=` field gives the number.
When the log stays quiet, switch to enforcing mode. Re-soak after
glibc or distro upgrades — glibc quietly adopts new syscalls
(`rseq`, `clone3`, `statx` historically), and this is the main way
enforcing filters break in production.

`strace -f -c` over the test suite is the complementary tool: it shows
which allowed syscalls are never used and could be removed.
