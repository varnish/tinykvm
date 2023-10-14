#include <tinykvm/machine.hpp>
#include <cstring>
#include <cstdio>
#include <cassert>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include "load_file.hpp"

#include <tinykvm/rsp_client.hpp>

#define NUM_GUESTS   100
#define NUM_RESETS   40000
#define GUEST_MEMORY  0x40000000  /* 1024MB memory */
#define GUEST_COW_MEM 65536  /* 64KB memory */
static constexpr size_t BENCH_SAMPLES = 100u;
static constexpr bool   BENCH_BASICS  = false;
static constexpr bool   BENCH_STARTUP = false;
static constexpr bool   FULL_RESET    = true;

inline timespec time_now();
inline long nanodiff(timespec start_time, timespec end_time);
static long micro_benchmark(std::function<void()>);
static void benchmark_alternate_tenant_resets(tinykvm::Machine &, size_t);
static void benchmark_multiple_vms(tinykvm::Machine&, size_t, size_t);
static void benchmark_multiple_pooled_vms(tinykvm::Machine&, size_t, size_t);
static std::vector<uint8_t> binary;

int main(int argc, char** argv)
{
	if (argc < 2) {
		fprintf(stderr, "Missing argument: 64-bit ELF binary\n");
		exit(1);
	}
	binary = load_file(argv[1]);
	std::vector<tinykvm::Machine*> vms;
	vms.reserve(NUM_GUESTS);

	tinykvm::Machine::init();
	extern void setup_kvm_system_calls();
	setup_kvm_system_calls();

	/* Warmup */
	uint64_t vmcall_address = 0x0;
	{
		tinykvm::MachineOptions options {
			.max_mem = GUEST_MEMORY,
			.max_cow_mem = GUEST_COW_MEM,
		};
		tinykvm::Machine master_vm {binary, options};
		master_vm.setup_linux(
			{"kvmtest", "Hello World!\n"},
			{"LC_TYPE=C", "LC_ALL=C", "USER=root"});

		vmcall_address = master_vm.address_of("bench");
		if (vmcall_address == 0x0) {
			fprintf(stderr, "Error: The test function is missing\n");
			exit(1);
		}

		/* Normal execution of _start -> main() */
		if (getenv("DEBUG"))
		{
			auto* vm = &master_vm;
			tinykvm::tinykvm_x86regs regs;

			if (getenv("VMCALL")) {
				master_vm.run();
			}
			if (getenv("FORK")) {
				master_vm.prepare_copy_on_write();
				vm = new tinykvm::Machine {master_vm, options};
				vm->setup_call(regs, vmcall_address, vm->stack_address());
				vm->set_registers(regs);
			} else {
				master_vm.setup_call(regs, vmcall_address, vm->stack_address());
				master_vm.set_registers(regs);
			}

			tinykvm::RSP server {*vm, 2159};
			printf("Waiting for connection localhost:2159...\n");
			auto client = server.accept();
			if (client != nullptr) {
				/* Debugging session of _start -> main() */
				printf("Connected\n");
				try {
					//client->set_verbose(true);
					while (client->process_one());
				} catch (const tinykvm::MachineException& e) {
					printf("EXCEPTION %s: %lu\n", e.what(), e.data());
					vm->print_registers();
				}
			} else {
				/* Resume execution normally */
				vm->run();
			}
			/* Exit after debugging */
			return 0;
		}
		/* Normal execution of _start -> main() */
		master_vm.run();

		printf("Master VM uses CoW memory? %d\n", master_vm.uses_cow_memory());

		if constexpr (BENCH_BASICS)
		{
			auto registers_time = micro_benchmark([&] {
				volatile auto x = master_vm.registers();
			});
			printf("registers() average time: %lu nanos\n", registers_time);
			auto regs = master_vm.registers();
			auto set_registers_time = micro_benchmark([&] {
				master_vm.set_registers(regs);
			});
			printf("set_registers() average time: %lu nanos\n", set_registers_time);

			auto fastest_call_time = micro_benchmark([&] {
				master_vm.timed_vmcall(vmcall_address, 0.0f);
			});
			printf("Fastest possible vmcall time: %lu ns\n", fastest_call_time);

			auto fastest_timed_call_time = micro_benchmark([&] {
				master_vm.timed_vmcall(vmcall_address, 4.0f);
			});
			printf("Fastest possible timed vmcall time: %lu ns\n", fastest_timed_call_time);

			static const auto simple_binary = load_file("../guest/musl/simple");

			auto boot_time = micro_benchmark([&] {
				tinykvm::Machine vm {simple_binary, options};
				vm.setup_linux(
					{"kvmtest", "Hello World!\n"},
					{"LC_TYPE=C", "LC_ALL=C", "USER=root"});
				vm.run();
			});
			printf("VM create-boot-delete time: %lu ns\n", boot_time);

			// Create new VM, prepare it for CoW
			tinykvm::Machine new_master_vm {simple_binary, options};
			new_master_vm.setup_linux(
				{"kvmtest", "Hello World!\n"},
				{"LC_TYPE=C", "LC_ALL=C", "USER=root"});
			new_master_vm.run();
			new_master_vm.prepare_copy_on_write();

			auto fork_boot_time = micro_benchmark([&] {
				tinykvm::Machine vm {new_master_vm, options};
			});
			printf("VM fork-delete time: %lu ns\n", fork_boot_time);

			// memfd_create()
			auto fd = memfd_create("benchmark dontneed", 0);
			assert(fd >= 0);

			const size_t bench_memory_size = 128ULL * 1024 * 1024;
			ftruncate(fd, bench_memory_size);

			auto* mem = (char*) mmap(NULL, bench_memory_size, PROT_READ | PROT_WRITE,
				MAP_SHARED, fd, 0);
			std::memset(mem, 0, bench_memory_size);

			auto insert_memory_time = micro_benchmark([&] {
				tinykvm::VirtualMem vmem {0xC00000000, mem, bench_memory_size};
				master_vm.install_memory(3, vmem, true);
				master_vm.delete_memory(3);
			});
			printf("insert memory average time: %lu nanos\n", insert_memory_time);

			auto dontneed_time = micro_benchmark([&] {
				madvise(mem, bench_memory_size, MADV_DONTNEED);
			});
			munmap(mem, bench_memory_size);
			close(fd);
			printf("madv_dontneed time: %lu nanos\n", dontneed_time);
			// memfd closed

			auto memfd_time = micro_benchmark([&] {
				int mfd = memfd_create("remapped memory", 0);
				ftruncate(mfd, bench_memory_size);
				close(mfd);
			});
			printf("memfd open/close average time: %lu nanos\n", memfd_time);

			int mfd = memfd_create("remapped memory", 0);
			ftruncate(mfd, bench_memory_size);

			tinykvm::VirtualMem vmem{0xC00000000, (char *)0xC00000000, bench_memory_size};
			master_vm.install_memory(3, vmem, true);

			auto remap_memory_time = micro_benchmark([&] {
				mem = (char *)mmap((void*)0xC00000000, bench_memory_size, PROT_READ | PROT_WRITE,
					MAP_SHARED, mfd, 0);
				munmap(mem, bench_memory_size);
			});
			printf("memfd map/unmap average time: %lu nanos\n", remap_memory_time);
		} // BENCH_BASICS
	}

	if constexpr (BENCH_STARTUP)
	{
		asm("" : : : "memory");
		auto t0 = time_now();
		asm("" : : : "memory");

		for (unsigned i = 0; i < NUM_GUESTS; i++)
		{
			tinykvm::MachineOptions options {
				.max_mem = GUEST_MEMORY,
				.max_cow_mem = GUEST_COW_MEM,
				.verbose_loader = false,
				.short_lived = true,
			};
			vms.push_back(new tinykvm::Machine {binary, options});
			auto& vm = *vms.back();
			vm.setup_linux(
				{"kvmtest", "Hello World!\n"},
				{"LC_TYPE=C", "LC_ALL=C", "USER=root"});
		}

		asm("" : : : "memory");
		auto t1 = time_now();
		asm("" : : : "memory");

		for (auto* vm : vms)
		{
			vm->set_printer(
				[] (const char*, size_t) {
				});

			/* Normal execution of _start -> main() */
			vm->run();

			vm->set_printer();
		}

		asm("" : : : "memory");
		auto t2 = time_now();
		asm("" : : : "memory");

		for (auto* vm : vms)
		{
			/* One function call into the VM */
			vm->vmcall(vmcall_address);
		}

		asm("" : : : "memory");
		auto t3 = time_now();
		asm("" : : : "memory");

		for (auto* vm : vms) {
			delete vm;
		}

		asm("" : : : "memory");
		auto t4 = time_now();
		asm("" : : : "memory");

		auto nanos_per_gc = nanodiff(t0, t1) / NUM_GUESTS;
		auto nanos_per_gr = nanodiff(t1, t2) / NUM_GUESTS;
		auto nanos_per_call = nanodiff(t2, t3) / NUM_GUESTS;
		auto nanos_per_gd = nanodiff(t3, t4) / NUM_GUESTS;
		printf("Construct: %ldns (%ld micros)\n", nanos_per_gc, nanos_per_gc / 1000);
		printf("Runtime: %ldns (%ld micros)\n", nanos_per_gr, nanos_per_gr / 1000);
		printf("vmcall(test): %ldns (%ld micros)\n", nanos_per_call, nanos_per_call / 1000);
		printf("Destruct: %ldns (%ld micros)\n", nanos_per_gd, nanos_per_gd / 1000);
	}

	const tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = GUEST_COW_MEM,
		.verbose_loader = false
	};
	tinykvm::Machine master_vm {binary, options};
	master_vm.setup_linux(
		{"kvmtest", "Hello World!\n"},
		{"LC_TYPE=C", "LC_ALL=C", "USER=root"});
	/* Normal execution of _start -> main() */
	master_vm.run();

	/* Make the master VM able to mass-produce copies */
	master_vm.prepare_copy_on_write();

	printf("The 'test' function is at 0x%lX\n", vmcall_address);
	assert(master_vm.address_of("bench") == vmcall_address);
	printf("Call stack is at 0x%lX\n", master_vm.stack_address());
	printf("Heap address is at 0x%lX\n", master_vm.heap_address());

	printf("Benchmarking VM fork + vmcall 0x%lX\n", vmcall_address);

	/* Benchmark the VM fast-forking feature */
	asm("" : : : "memory");
	auto ft0 = time_now();
	asm("" : : : "memory");
	uint64_t forktime = 0;
	uint64_t calltime = 0;
	uint64_t timed_calltime = 0;

	for (unsigned i = 0; i < NUM_GUESTS; i++)
	{
		asm("" : : : "memory");
		auto ft1 = time_now();
		asm("" : : : "memory");
		tinykvm::Machine vm {master_vm, options};
		asm("" : : : "memory");
		auto ft2 = time_now();
		forktime += nanodiff(ft1, ft2);
	}
	tinykvm::Machine cvm {master_vm, options};
	for (unsigned i = 0; i < NUM_GUESTS; i++)
	{
		cvm.vmcall(vmcall_address);
	}
	for (unsigned i = 0; i < NUM_GUESTS; i++)
	{
		asm("" : : : "memory");
		auto ft0 = time_now();
		asm("" : : : "memory");
		cvm.vmcall(vmcall_address);
		asm("" : : : "memory");
		auto ft1 = time_now();
		asm("" : : : "memory");
		cvm.timed_vmcall(vmcall_address, 1.0f);
		asm("" : : : "memory");
		auto ft2 = time_now();
		calltime += nanodiff(ft0, ft1);
		timed_calltime += nanodiff(ft1, ft2);
	}

	asm("" : : : "memory");
	auto ft3 = time_now();
	asm("" : : : "memory");

	#define NUM_VMEXITS      200000
	uint64_t bench_vmexit_address = cvm.address_of("bench_vmexits");
	uint64_t bench_vmexit_time = 0;
	{
		asm("" : : : "memory");
		auto ft0 = time_now();
		asm("" : : : "memory");
		cvm.vmcall(bench_vmexit_address, NUM_VMEXITS);
		asm("" : : : "memory");
		auto ft1 = time_now();
		bench_vmexit_time = nanodiff(ft0, ft1);
	}


	/* Benchmark the fork reset feature */
	printf("Benchmarking fast reset...\n");
	tinykvm::Machine fvm {master_vm, options};
	fvm.vmcall(vmcall_address);

	/* Warmup for resets */
	for (unsigned i = 0; i < 10; i++)
	{
		fvm.reset_to(master_vm, options);
		fvm.vmcall(vmcall_address);
	}

	/* Reset benchmark */
	uint64_t frtime = 0;
	uint64_t frcall = 0;

	for (unsigned i = 0; i < NUM_RESETS; i++)
	{
		auto frt0 = time_now();
		asm("" : : : "memory");
		fvm.reset_to(master_vm, options);
		asm("" : : : "memory");
		auto frt1 = time_now();
		asm("" : : : "memory");
		fvm.timed_vmcall(vmcall_address, 4.0f);
		asm("" : : : "memory");
		auto frt2 = time_now();
		frtime += nanodiff(frt0, frt1);
		frcall += nanodiff(frt1, frt2);
	}
	frtime /= NUM_RESETS;
	frcall /= NUM_RESETS;

	auto nanos_per_gf = forktime / NUM_GUESTS;
	auto nanos_per_fc = nanodiff(ft0, ft3) / NUM_GUESTS;
	printf("VM fork: %ldns (%ld micros)\n", nanos_per_gf, nanos_per_gf / 1000);
	printf("vmcall: %ldns (%ld micros)\n",
		calltime / NUM_GUESTS, calltime / NUM_GUESTS / 1000);
	printf("timed_vmcall: %ldns (%ld micros)\n",
		timed_calltime / NUM_GUESTS, timed_calltime / NUM_GUESTS / 1000);
	printf("vmcall + destructor: %ldns (%ld micros)\n",
		nanos_per_fc - nanos_per_gf, (nanos_per_fc - nanos_per_gf) / 1000);
	printf("VM fork totals: %ldns (%ld micros)\n", nanos_per_fc, nanos_per_fc / 1000);

	auto nanos_per_vmexit = bench_vmexit_time / NUM_VMEXITS;
	printf("VM vmexit time: %ldns (%ld micros)\n", nanos_per_vmexit, nanos_per_vmexit / 1000);

	printf("Fast reset: %ldns (%ld micros)\n", frtime, frtime / 1000);
	printf("Fast vmcall: %ldns (%ld micros)\n", frcall, frcall / 1000);

	// This benchmark mixes different VMs on the same thread,
	// which is supported, but has a serious penalty on Linux.
	benchmark_alternate_tenant_resets(master_vm, 5000);

	// Benchmark calling many forked VMs on same thread
	// Seems to be fine, which I guess means that the penalty
	// has to do with costs attached to main memory switching.
	benchmark_multiple_vms(master_vm, 2, 5000);
	benchmark_multiple_vms(master_vm, 4, 5000);
	benchmark_multiple_vms(master_vm, 8, 5000);
	benchmark_multiple_vms(master_vm, 16, 5000);
	benchmark_multiple_vms(master_vm, 24, 5000);
	benchmark_multiple_vms(master_vm, 32, 5000);
	benchmark_multiple_vms(master_vm, 48, 5000);
	benchmark_multiple_vms(master_vm, 64, 5000);
	benchmark_multiple_vms(master_vm, 96, 5000);
	benchmark_multiple_vms(master_vm, 128, 5000);

	benchmark_multiple_pooled_vms(master_vm, 2, 15000);
	benchmark_multiple_pooled_vms(master_vm, 4, 15000);
	benchmark_multiple_pooled_vms(master_vm, 8, 15000);
	benchmark_multiple_pooled_vms(master_vm, 16, 15000);
	benchmark_multiple_pooled_vms(master_vm, 32, 15000);
	benchmark_multiple_pooled_vms(master_vm, 48, 15000);
	benchmark_multiple_pooled_vms(master_vm, 64, 15000);
}

void benchmark_alternate_tenant_resets(tinykvm::Machine& master_vm, const size_t RESETS)
{
	const uint64_t vmcall_address = master_vm.address_of("bench");

	// Make a full copy of the main VM into other_vm
	tinykvm::Machine other_vm { binary,
	{
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = 0
	} };
	other_vm.setup_linux(
		{"kvmtest", "Hello World!\n"},
		{"LC_TYPE=C", "LC_ALL=C", "USER=root"});
	other_vm.run();
	other_vm.prepare_copy_on_write();

	const tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = GUEST_COW_MEM,
		.allow_reset_to_new_master = true,
	};

	// Forked VM that can be reset to any other VM
	tinykvm::Machine fvm {master_vm, options};

	/* Warmup for resets */
	for (unsigned i = 0; i < 10; i++)
	{
		fvm.reset_to(master_vm, options);
		fvm.vmcall(vmcall_address);
	}

	/* Reset benchmark */
	uint64_t frtime = 0;
	uint64_t frcall = 0;
	uint64_t counter = 0;

	for (unsigned i = 0; i < RESETS; i++)
	{
		auto frt0 = time_now();
		asm("" : : : "memory");
		counter = (counter + 1) % 2;
		fvm.reset_to((counter < 1) ? master_vm : other_vm, options);
		asm("" : : : "memory");
		auto frt1 = time_now();
		asm("" : : : "memory");
		fvm.timed_vmcall(vmcall_address, 4.0f);
		asm("" : : : "memory");
		auto frt2 = time_now();
		frtime += nanodiff(frt0, frt1);
		frcall += nanodiff(frt1, frt2);
	}
	frtime /= RESETS;
	frcall /= RESETS;

	printf("Alternating reset: %ldns (%ld micros)\n", frtime, frtime / 1000);
	printf("Alternating vmcall: %ldns (%ld micros)\n", frcall, frcall / 1000);
}

void benchmark_multiple_vms(tinykvm::Machine& master_vm, size_t NUM, size_t RESETS)
{
	const uint64_t vmcall_address = master_vm.address_of("bench");

	const tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = GUEST_COW_MEM,
	};

	tinykvm::Machine* fvm =
		(tinykvm::Machine *)aligned_alloc(16, NUM * sizeof(tinykvm::Machine));
	for (size_t i = 0; i < NUM; i++)
		new (&fvm[i]) tinykvm::Machine {master_vm, options};

	/* Reset benchmark */
	uint64_t frtime = 0;
	uint64_t frcall = 0;
	uint64_t counter = 0;

	for (unsigned i = 0; i < RESETS; i++)
	{
		auto frt0 = time_now();
		asm("" : : : "memory");
		counter = (counter + 1) % NUM;
		if constexpr (FULL_RESET) {
			fvm[counter].reset_to(master_vm, options);
		}
		asm("" : : : "memory");
		auto frt1 = time_now();
		asm("" : : : "memory");
		if constexpr (FULL_RESET) {
			fvm[counter].timed_vmcall(vmcall_address, 4.0f);
		} else {
			fvm[counter].timed_vmcall(vmcall_address, 4.0f);
		}
		asm("" : : : "memory");
		auto frt2 = time_now();
		frtime += nanodiff(frt0, frt1);
		frcall += nanodiff(frt1, frt2);
	}
	frtime /= RESETS;
	frcall /= RESETS;

	std::free(fvm);

	printf("Multiple %zuxVMs reset: %ldns (%ld micros)\n", NUM, frtime, frtime / 1000);
	printf("Multiple %zuxVMs vmcall: %ldns (%ld micros)\n", NUM, frcall, frcall / 1000);
}

#include <tinykvm/util/threadpool.h>
extern "C" int gettid();

void benchmark_multiple_pooled_vms(tinykvm::Machine& master_vm, size_t NUM, size_t RESETS)
{
	tinykvm::ThreadPool pool { NUM, 0, false };
	std::unordered_map<int, tinykvm::Machine> machines;
	std::mutex machine_mtx;

	struct {
		std::unordered_map<int, tinykvm::Machine>* machines;
		std::mutex* mtx;
		tinykvm::Machine* master_vm;
		uint64_t addr;
	} data {&machines, &machine_mtx, &master_vm, master_vm.address_of("bench")};

	// A single pool task that can be run on any thread
	auto task =
	[&data] () -> std::tuple<timespec, timespec, timespec>
	{
		int tid = gettid();
		thread_local tinykvm::Machine* fvm = nullptr;

		const tinykvm::MachineOptions options {
			.max_mem = GUEST_MEMORY,
			.max_cow_mem = GUEST_COW_MEM,
		};

		if (fvm == nullptr) {
			data.mtx->lock();
			auto it = data.machines->find(tid);
			if (it == data.machines->end()) {
				auto it = data.machines->emplace(std::piecewise_construct,
					std::forward_as_tuple(tid),
					std::forward_as_tuple(*data.master_vm, options));
				fvm = &it.first->second;
			} else {
				fvm = &it->second;
			}
			data.mtx->unlock();
		}

		asm("" : : : "memory");
		auto frt0 = time_now();
		asm("" : : : "memory");
		if constexpr (FULL_RESET) {
			fvm->reset_to(*data.master_vm, options);
		}
		asm("" : : : "memory");
		auto frt1 = time_now();
		asm("" : : : "memory");
		if constexpr (FULL_RESET) {
			fvm->timed_vmcall(data.addr, 4.0f);
		} else {
			fvm->timed_vmcall(data.addr, 4.0f);
		}
		asm("" : : : "memory");
		auto frt2 = time_now();
		return {frt0, frt1, frt2};
	};

	// Perform pool benchmark
	std::vector<std::future<std::tuple<timespec, timespec, timespec>>> results;
	results.reserve(RESETS);

	for (unsigned i = 0; i < RESETS; i++)
	{
		results.emplace_back(pool.enqueue(task));
	}

	// Gather results
	uint64_t frtime = 0;
	uint64_t frcall = 0;
	for (auto& fut : results) {
		auto [frt0, frt1, frt2] = fut.get();
		frtime += nanodiff(frt0, frt1);
		frcall += nanodiff(frt1, frt2);
	}
	frtime /= results.size();
	frcall /= results.size();

	printf("Pooled %zuxVMs reset: %ldns (%ld micros)\n", NUM, frtime, frtime / 1000);
	printf("Pooled %zuxVMs vmcall: %ldns (%ld micros)\n", NUM, frcall, frcall / 1000);
}

timespec time_now()
{
	timespec t;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &t);
	return t;
}
long nanodiff(timespec start_time, timespec end_time)
{
	return (end_time.tv_sec - start_time.tv_sec) * (long)1e9 + (end_time.tv_nsec - start_time.tv_nsec);
}

static long micro_benchmark(std::function<void()> callback)
{
	callback();
	auto t0 = time_now();
	asm("" ::: "memory");
	for (size_t i = 0; i < BENCH_SAMPLES; i++) {
		callback();
	}
	asm("" ::: "memory");
	auto t1 = time_now();
	return nanodiff(t0, t1) / BENCH_SAMPLES;
}
