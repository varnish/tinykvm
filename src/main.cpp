#include <tinykvm/machine.hpp>
#include <cstring>
#include <cstdio>
#include <cassert>

#include <tinykvm/rsp_client.hpp>

#define NUM_GUESTS   100
#define GUEST_MEMORY 0x4000000  /* 64MB memory */

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
	uint64_t exit_address = 0x0;
	{
		tinykvm::MachineOptions options {
			.max_mem = GUEST_MEMORY,
			.verbose_loader = false
		};
		tinykvm::Machine vm {binary, options};
		vm.setup_linux(
			{"kvmtest", "Hello World!\n"},
			{"LC_TYPE=C", "LC_ALL=C", "USER=root"});
		/* Normal execution of _start -> main() */
		vm.run();
		/* vmcall setup */
		vmcall_address = vm.address_of("test");
		assert(vmcall_address != 0);
		exit_address = vm.address_of("rexit");
		assert(exit_address != 0);
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
		vm.set_exit_address(exit_address);
		vm.setup_linux(
			{"kvmtest", "Hello World!\n"},
			{"LC_TYPE=C", "LC_ALL=C", "USER=root"});
	}

	asm("" : : : "memory");
	auto t1 = time_now();
	asm("" : : : "memory");

	for (auto* vm : vms)
	{
		if (getenv("DEBUG"))
		{
			tinykvm::RSP server {*vm, 2159};
			printf("Waiting for connection...\n");
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
					break;
				}
			} else {
				/* Normal execution of _start -> main() */
				vm->run();
			}
		} else {
			/* Normal execution of _start -> main() */
			vm->run();
		}

		if (false)
		{
			/* Execute public function */
			struct Data {
				char   buffer[128];
				size_t len;
			} data;
			strcpy(data.buffer, "Hello Buffered World!\n");
			data.len = strlen(data.buffer);
			vm->vmcall(vm->address_of("empty"), data);
		}
	}

	asm("" : : : "memory");
	auto t2 = time_now();
	asm("" : : : "memory");

	for (auto* vm : vms)
	{
		/* FIXME: Bandaid for broken handmade mini-ELF */
		vm->set_stack_address(0x1ff000);
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
	master_vm.set_stack_address(0x1ff000);

	printf("The 'test' function is at 0x%lX\n", master_vm.address_of("test"));
	assert(master_vm.address_of("test") == vmcall_address);
	printf("Call stack is at 0x%lX\n", master_vm.stack_address());

	asm("" : : : "memory");
	auto ft0 = time_now();
	asm("" : : : "memory");
	uint64_t forktime = 0;

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
		printf("Calling 'test'\n");
		//vm.vmcall("test");
		master_vm.vmcall(vmcall_address);
	}

	asm("" : : : "memory");
	auto ft3 = time_now();
	asm("" : : : "memory");

	auto nanos_per_gf = forktime / NUM_GUESTS;
	printf("Fork: %ldns (%ld micros)\n", nanos_per_gf, nanos_per_gf / 1000);
	auto nanos_per_fc = nanodiff(ft0, ft3) / NUM_GUESTS;
	printf("Fast copy: %ldns (%ld micros)\n", nanos_per_fc, nanos_per_fc / 1000);
	printf("vmcall + destructor: %ldns (%ld micros)\n",
		nanos_per_fc - nanos_per_gf, (nanos_per_fc - nanos_per_gf) / 1000);
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
