#include <tinykvm/machine.hpp>
#include <cstring>
#include <cstdio>
#include <cassert>
#include "load_file.hpp"

#include <tinykvm/rsp_client.hpp>

#define NUM_GUESTS   300
#define NUM_RESETS   40000
#define GUEST_MEMORY  0x40000000  /* 1024MB memory */
#define GUEST_COW_MEM 65536  /* 64KB memory */

inline timespec time_now();
inline long nanodiff(timespec start_time, timespec end_time);
static void benchmark_alternate_tenant_resets(tinykvm::Machine&);
static void benchmark_two_tenants_two_vms(tinykvm::Machine&);

int main(int argc, char** argv)
{
	if (argc < 2) {
		fprintf(stderr, "Missing argument: 64-bit ELF binary\n");
		exit(1);
	}
	const auto binary = load_file(argv[1]);
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
	}

	asm("" : : : "memory");
	auto t0 = time_now();
	asm("" : : : "memory");

	for (unsigned i = 0; i < NUM_GUESTS; i++)
	{
		tinykvm::MachineOptions options {
			.max_mem = GUEST_MEMORY,
			.max_cow_mem = GUEST_COW_MEM,
			.verbose_loader = false
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
		asm("" : : : "memory");
		auto ft2 = time_now();
		asm("" : : : "memory");
		cvm.vmcall(vmcall_address);
		asm("" : : : "memory");
		auto ft3 = time_now();
		calltime += nanodiff(ft2, ft3);
	}

	asm("" : : : "memory");
	auto ft3 = time_now();
	asm("" : : : "memory");

	#define NUM_VMEXITS      200000
	uint64_t bench_vmexit_address = cvm.address_of("bench_vmexits");
	uint64_t bench_vmexit_time = 0;
	for (unsigned i = 0; i < 1; i++)
	{
		asm("" : : : "memory");
		auto ft0 = time_now();
		asm("" : : : "memory");
		cvm.vmcall(bench_vmexit_address, NUM_VMEXITS);
		asm("" : : : "memory");
		auto ft1 = time_now();
		bench_vmexit_time += nanodiff(ft0, ft1);
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
	uint64_t frtotal = 0;

	for (unsigned i = 0; i < NUM_RESETS; i++)
	{
		auto frt0 = time_now();
		asm("" : : : "memory");
		fvm.reset_to(master_vm, options);
		asm("" : : : "memory");
		auto frt1 = time_now();
		asm("" : : : "memory");
		fvm.timed_vmcall(vmcall_address, 0x400000);
		asm("" : : : "memory");
		auto frt2 = time_now();
		frtime += nanodiff(frt0, frt1);
		frtotal += nanodiff(frt0, frt2);
	}
	frtime /= NUM_RESETS;
	frtotal /= NUM_RESETS;

	auto nanos_per_gf = forktime / NUM_GUESTS;
	auto nanos_per_fc = nanodiff(ft0, ft3) / NUM_GUESTS;
	printf("VM fork: %ldns (%ld micros)\n", nanos_per_gf, nanos_per_gf / 1000);
	printf("vmcall: %ldns (%ld micros)\n",
		calltime / NUM_GUESTS, calltime / NUM_GUESTS / 1000);
	printf("vmcall + destructor: %ldns (%ld micros)\n",
		nanos_per_fc - nanos_per_gf, (nanos_per_fc - nanos_per_gf) / 1000);
	printf("VM fork totals: %ldns (%ld micros)\n", nanos_per_fc, nanos_per_fc / 1000);

	auto nanos_per_vmexit = bench_vmexit_time / NUM_VMEXITS;
	printf("VM vmexit time: %ldns (%ld micros)\n", nanos_per_vmexit, nanos_per_vmexit / 1000);

	printf("Fast reset: %ldns (%ld micros)\n", frtime, frtime / 1000);
	printf("Fast vmcall: %ldns (%ld micros)\n", frtotal, frtotal / 1000);

	benchmark_alternate_tenant_resets(master_vm);
	benchmark_two_tenants_two_vms(master_vm);
}

void benchmark_alternate_tenant_resets(tinykvm::Machine& master_vm)
{
	const uint64_t vmcall_address = master_vm.address_of("bench");

	tinykvm::Machine other_vm { master_vm,
	{
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = 0,
		.linearize_memory = true
	} };
	other_vm.prepare_copy_on_write();

	const tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = GUEST_COW_MEM,
	};

	tinykvm::Machine fvm {master_vm, options};

	/* Warmup for resets */
	for (unsigned i = 0; i < 10; i++)
	{
		fvm.reset_to(master_vm, options);
		fvm.vmcall(vmcall_address);
	}

	/* Reset benchmark */
	uint64_t frtime = 0;
	uint64_t frtotal = 0;
	uint64_t counter = 0;

	for (unsigned i = 0; i < NUM_RESETS; i++)
	{
		auto frt0 = time_now();
		asm("" : : : "memory");
		counter = (counter + 1) % 2;
		fvm.reset_to((counter < 1) ? master_vm : other_vm, options);
		asm("" : : : "memory");
		auto frt1 = time_now();
		asm("" : : : "memory");
		fvm.timed_vmcall(vmcall_address, 0x400000);
		asm("" : : : "memory");
		auto frt2 = time_now();
		frtime += nanodiff(frt0, frt1);
		frtotal += nanodiff(frt0, frt2);
	}
	frtime /= NUM_RESETS;
	frtotal /= NUM_RESETS;

	printf("Alternating reset: %ldns (%ld micros)\n", frtime, frtime / 1000);
	printf("Alternating vmcall: %ldns (%ld micros)\n", frtotal, frtotal / 1000);
}

void benchmark_two_tenants_two_vms(tinykvm::Machine& master_vm)
{
	const uint64_t vmcall_address = master_vm.address_of("bench");

	tinykvm::Machine other_vm { master_vm,
	{
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = 0,
		.linearize_memory = true
	} };
	other_vm.prepare_copy_on_write();

	const tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = GUEST_COW_MEM,
	};

	tinykvm::Machine fvm[2] {
		tinykvm::Machine {master_vm, options},
		tinykvm::Machine {master_vm, options},
	};

	/* Reset benchmark */
	uint64_t frtime = 0;
	uint64_t frtotal = 0;
	uint64_t counter = 0;

	for (unsigned i = 0; i < NUM_RESETS; i++)
	{
		auto frt0 = time_now();
		asm("" : : : "memory");
		counter = (counter + 1) % 2;
		fvm[counter].reset_to(master_vm, options);
		asm("" : : : "memory");
		auto frt1 = time_now();
		asm("" : : : "memory");
		fvm[counter].timed_vmcall(vmcall_address, 0x400000);
		asm("" : : : "memory");
		auto frt2 = time_now();
		frtime += nanodiff(frt0, frt1);
		frtotal += nanodiff(frt0, frt2);
	}
	frtime /= NUM_RESETS;
	frtotal /= NUM_RESETS;

	printf("Alternating 2xVMs reset: %ldns (%ld micros)\n", frtime, frtime / 1000);
	printf("Alternating 2xVMs vmcall: %ldns (%ld micros)\n", frtotal, frtotal / 1000);
}

timespec time_now()
{
	timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t;
}
long nanodiff(timespec start_time, timespec end_time)
{
	return (end_time.tv_sec - start_time.tv_sec) * (long)1e9 + (end_time.tv_nsec - start_time.tv_nsec);
}
