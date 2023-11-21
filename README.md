TinyKVM userspace emulator library
==============

TinyKVM is a simple, slim and highly specialized userspace emulator with _native performance_. It is highly embeddable and with only 10k LOC, has an unbelievably tiny attack surface.

TinyKVM is designed to execute request-based workloads in high-performance HTTP caches and web servers.

KVM is the most robust, battle-hardened virtualization API that exists right now. It is only 60k LOC in the kernel, and it is the foundation of the modern public cloud. TinyKVM does not exercise the full KVM API, as it does not use any virtualized devices.


## Userspace Emulation

Userspace emulation means running userspace programs. You can take a regular Linux program that you just built in your terminal and run it in TinyKVM. It will have the same exact run-time, the same exact CPU features and so on.

The rule-of-thumb is thus: If you can run it locally on your machine, you can run it in TinyKVM, at the same speed.

But there are some differences:

- TinyKVM has an execution timeout feature, allowing automatic stopping of stuck programs
- TinyKVM has memory limits
- TinyKVM can fork an initialized program into hundreds of pre-initialized VMs
- TinyKVM can load programs while preferring hugepages, leading to performance gains


## Home-field Advantage

A very understated feature of running directly on the CPU using hardware virtualization is that you don't need fancy toolchains to build programs. This is a most surprising and welcome feature as building and working with other architectures is often a struggle.

Secondly, as CPUs evolve, so does TinyKVM. It never has to be updated, yet it will continue to run at native speeds on your CPU.

