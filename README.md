Tiny KVM virtual machine
==============

This repository is hosting a tiny KVM virtual machine.
It implements a subset of the Linux system ABI.

```
0x1600   - GDT
0x1700   - TSS
0x1800   - IDT
0x2000   - Interrupt assembly
0x3000   - 4k IST stack
0x4000   - Page tables
0x100000 - Stack
0x200000 - Binary, heap
```

Static musl - Hello World
==============

```
Construct: 260174ns (260 micros)
Runtime: 91659ns (91 micros)
Destruct: 1552ns (1 micros)
Complete: 377121ns (377 micros)
```
500 TinyKVM guest VMs with warmup.

It's not yet clear that we have to execute for a substantial amount of time before the hardware-accelerated virtual machines will have a performance benefit. These are also synthetic benchmarks, and we can fairly reasonably expect these trivial one-page programs to use 5-10x the amount of run-time in a production environment.

We will need to implement a fast forking constructor first to really know if we can avoid the guests startup time. May be able to use shm_open to CoW the master machines memory.
