#include <tinykvm/machine.hpp>
#include <cstring>
#include <cstdio>
#include <cassert>

#include <tinykvm/rsp_client.hpp>

#define NUM_GUESTS   300
#define NUM_RESETS   300
#define GUEST_MEMORY 0x40000000  /* 1024MB memory */

std::vector<uint8_t> load_file(const std::string& filename);
inline timespec time_now();
inline long nanodiff(timespec start_time, timespec end_time);

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
			.verbose_loader = false
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

			if (getenv("VMCALL")) {
				master_vm.run();
			}
			if (getenv("FORK")) {
				master_vm.prepare_copy_on_write();
				vm = new tinykvm::Machine {master_vm, options};
				auto regs = vm->setup_call(vmcall_address);
				vm->set_registers(regs);
			} else {
				auto regs = master_vm.setup_call(vmcall_address);
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
		/* Normal execution of _start -> main() */
		vm->run();
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

	tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
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
		asm("" : : : "memory");
		vm.vmcall(vmcall_address);
		asm("" : : : "memory");
		auto ft3 = time_now();
		calltime += nanodiff(ft2, ft3);
	}

	asm("" : : : "memory");
	auto ft3 = time_now();
	asm("" : : : "memory");

	/* Benchmark the fork reset feature */
	printf("Benchmarking fast reset...\n");
	tinykvm::Machine fvm {master_vm, options};
	fvm.vmcall(vmcall_address);

	/* Warmup for resets */
	for (unsigned i = 0; i < 10; i++)
	{
		fvm.reset_to(master_vm);
		fvm.vmcall(vmcall_address);
	}

	/* Reset benchmark */
	uint64_t frtime = 0;
	uint64_t frtotal = 0;

	for (unsigned i = 0; i < NUM_RESETS; i++)
	{
		auto frt0 = time_now();
		asm("" : : : "memory");
		fvm.reset_to(master_vm);
		asm("" : : : "memory");
		auto frt1 = time_now();
		asm("" : : : "memory");
		fvm.vmcall(vmcall_address);
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
	printf("Fast reset: %ldns (%ld micros)\n", frtime, frtime / 1000);
	printf("Fast vmcall: %ldns (%ld micros)\n", frtotal, frtotal / 1000);
}

#include <stdexcept>
std::vector<uint8_t> load_file(const std::string& filename)
{
	size_t size = 0;
	FILE* f = fopen(filename.c_str(), "rb");
	if (f == NULL) throw std::runtime_error("Could not open file: " + filename);

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);

	std::vector<uint8_t> result(size);
	if (size != fread(result.data(), 1, size, f))
	{
		fclose(f);
		throw std::runtime_error("Error when reading from file: " + filename);
	}
	fclose(f);
	return result;
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
