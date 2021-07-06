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

Static -O2 musl - Hello World
==============

The time it takes to create the master VM:
```
Construct: 315900ns (315 micros)
```

Run-time to initialize the master VM:
```
Runtime: 2566188ns (2566 micros)
```

Time to call the `test` function in the master VM:
```
vmcall(test): 12325ns (12 micros)
```

Time to destroy the master VM:
```
Destruct: 277226ns (277 micros)
```

VM fast-forking
==============

Time to create a copy-on-write fork of the master VM:
```
VM fork: 145963ns (145 micros)
```

Time to call the `test` function in the forked VM:
```
Fork vmcall: 30034ns (30 micros)
```

Time to create, call into and destroy the fork:
```
Fork totals: 262976ns (262 micros)
```

These benchmarks are based on 300 tinyKVM guest VMs with no warmup.


VM fork resetting
==============

By reusing each fork, and just resetting them between usage, keeping some of the most costly things to re-initialize, we can save a bunch of time, and in the end we will initialize faster than competitors WASM implementations.


Time needed to reset a fork to initial forked state:
```
Fast reset: 13629ns (13 micros)
```

Time to do a function call into a reset, forked VM:
```
Fast vmcall: 21315ns (21 micros)
```

For a total reset+call time of 34 microseconds, which is much less than the official 60 microseconds for a Lucet WASM request. We don't have any destruction cost for this mode of operation. However, the context switching itself seems to be lower on Lucet.
