Tiny KVM virtual machine
==============

This repository is hosting the smallest possible KVM virtual machine.
It prints hello using an I/O port.


High single-use cost
==============

```
Time spent: 239810ns (239 micros)
Time spent: 237736ns (237 micros)
Time spent: 236555ns (236 micros)
Time spent: 238876ns (238 micros)
Time spent: 241880ns (241 micros)
```
Creating and closing a single VM 2k times shows that there is an overhead of 240 microseconds.


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

The memory usage is not particularly high, nor does the kernel create extra threads for these virtual machines.


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

The time spent creating VMs is linear in time.

![KVM virtual machine instantiation time](https://user-images.githubusercontent.com/3758947/107860895-f22a9400-6e39-11eb-86c4-8ef775d879b1.png)
