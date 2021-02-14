Tiny KVM virtual machine
==============

This repository is hosting the smallest possible KVM virtual machine.
It prints hello using an I/O port.

```
0x2000   - Page tables
0x100000 - Binary, rodata
0x200000 - Stack, heap
```

High single-use cost
==============

```
Time spent: 239810ns (239 micros)
Time spent: 237736ns (237 micros)
Time spent: 236555ns (236 micros)
Time spent: 238876ns (238 micros)
Time spent: 241880ns (241 micros)
```
Creating and closing a single VM 2k times shows that there is an overhead of 240 microseconds. These VMs are sharing memory.


Scaling cost of concurrency
================

The cost of VMs scales with the number of active VMs as well:
```
Time spent: 252955ns (252 micros)
Time spent: 281212ns (281 micros)
Time spent: 265023ns (265 micros)
Time spent: 294457ns (294 micros)
Time spent: 232372ns (232 micros)
Time spent: 277947ns (277 micros)
Time spent: 280560ns (280 micros)
Time spent: 268407ns (268 micros)
```

Creating 1000 guests without taking any of them down shows that the time is increasing when there are more virtual machines active, instead of just creating and destroying a single machine. Not particularly surprising.

The memory usage is not particularly high, nor does the kernel create extra threads for these virtual machines. These VMs are sharing memory.


Time spent creating new VMs
==================

```
VMs     Time
1000:   0,311s
2000:   0,650s
3000:   0,998s
4000:   1,342s
5000:   1,763s
6000:   2,099s
7000:   2,515s
8000:   3,049s
9000:   3,641s
10000:  4,249s
11000:  4,825s
12000:  5,192s
13000:  5,957s
```

The time spent creating VMs is linear in time. These VMs are sharing memory.

![KVM virtual machine instantiation time](https://user-images.githubusercontent.com/3758947/107860895-f22a9400-6e39-11eb-86c4-8ef775d879b1.png)


High single-use cost, individual memory
==============

```
Time spent: 417366ns (417 micros)
Time spent: 425040ns (425 micros)
Time spent: 421876ns (421 micros)
Time spent: 422632ns (422 micros)
Time spent: 429785ns (429 micros)
Time spent: 418654ns (418 micros)
Time spent: 421359ns (421 micros)
```

Creating and closing 2000 VMs shows that there is an overhead of 420 microseconds. These VMs each have their own memory, but is still sharing pagetables.


Multiple rounds of 1000 machines, individual memory
===============

By running 1000 machines (single-threaded) in rounds of 400, and taking the average time per guest round, we get a fairly low number. However, in this experiment the resetting of each guest is not happening. That is, no memory is zeroed between each guest program execution.

It is of course not kosher to avoid resetting guest memory between executions. However, it's clear that clearing *all* guest memory between rounds without considering what was actually used, is really bad for performance.

```
Time spent: 24035ns (24 micros)
Time spent: 24008ns (24 micros)
Time spent: 23143ns (23 micros)
Time spent: 23566ns (23 micros)
Time spent: 23443ns (23 micros)
Time spent: 22710ns (22 micros)
Time spent: 23013ns (23 micros)
Time spent: 23850ns (23 micros)
Time spent: 23672ns (23 micros)
Time spent: 23753ns (23 micros)
```


By creating separate memory ranges for all the various uses, and then re-enabling clearing of the write-enabled guest memory, we get these numbers:

```
Time spent: 175764ns (175 micros)
Time spent: 178411ns (178 micros)
```

It's clear that we have to execute for a substantial amount of time before the hardware-accelerated virtual machines will have a performance benefit. These are also synthetic benchmarks, and we can fairly reasonably expect these trivial one-page programs to use 5-10x the amount of run-time in a production environment. That is, the run-time should be somewhere around 1.22ms +/- 0.25ms in production based on experience. With these numbers we need to have programs that run complex calculations for at least 1.5ms to have a chance to compete with low-latency IS emulators.
