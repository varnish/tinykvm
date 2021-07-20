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
0x4000   - VSYSCALL page
0x5000   - Page tables
0x100000 - Stack
0x200000 - Binary, heap
```

Static -O2 musl - Hello World
==============

The time it takes to create the master VM:
```
Construct: 349313ns (349 micros)
```

Run-time to initialize the master VM:
```
Runtime: 2926952ns (2926 micros)
```

Time to call the `test` function in the master VM:
```
vmcall(test): 6947ns (6 micros)
```

Time to destroy the master VM:
```
Destruct: 308352ns (308 micros)
```

VM fast-forking
==============

Time to create a copy-on-write fork of the master VM:
```
VM fork: 220743ns (220 micros)
```

Time to call the `test` function in the forked VM:
```
Subsequent vmcalls: 1983ns (1 micro)
```

Time to create, call into and destroy the fork:
```
VM fork totals: 306539ns (306 micros)
```

These benchmarks are based on 300 tinyKVM guest VMs with no warmup.


VM fork resetting
==============

By reusing each fork, and just resetting them between usage, keeping some of the most costly things to re-initialize, we can save a bunch of time, and in the end we will initialize faster than competitors WASM implementations.

Time to do a function call into a forked VM:
```
Fast vmcall: 5546ns (5 micros)
```

Time needed to reset a fork to initial forked state:
```
Fast reset: 3581ns (3 micros)
```

For a total reset+call time of 9 microseconds, which is much less than the official 60 microseconds for a Lucet WASM request. We don't have any destruction cost for this mode of operation. However, the context switching itself seems to be lower on Lucet.

Also, we can start processing after only 5 microseconds, and immediately deliver the result to the client. The reset cost can be deferred until after delivery. This lowers the time to first byte, which is an important number in HTTP caches.
