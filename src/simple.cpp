#include <tinykvm/machine.hpp>
#include <cstring>
#include <cstdio>
#include "assert.hpp"
#include "load_file.hpp"

#include <tinykvm/rsp_client.hpp>
#define GUEST_MEMORY   0x40000000  /* 1024MB memory */
#define GUEST_WORK_MEM 1024UL * 1024*1024 /* MB working mem */

static uint64_t verify_exists(tinykvm::Machine& vm, const char* name)
{
	uint64_t addr = vm.address_of(name);
	if (addr == 0x0) {
//		fprintf(stderr, "Error: '%s' is missing\n", name);
//		exit(1);
	}
	return addr;
}

inline timespec time_now();
inline long nanodiff(timespec start_time, timespec end_time);

int main(int argc, char** argv)
{
	if (argc < 2) {
		fprintf(stderr, "Missing argument: 64-bit ELF binary\n");
		exit(1);
	}
	const auto binary = load_file(argv[1]);

	tinykvm::Machine::init();
	extern void setup_kvm_system_calls();
	setup_kvm_system_calls();

	tinykvm::Machine::install_unhandled_syscall_handler(
	[] (tinykvm::vCPU& cpu, unsigned scall) {
		switch (scall) {
			case 0x10000:
				cpu.stop();
				break;
			case 0x10001:
				throw "Unimplemented";
			case 0x10707:
				throw "Unimplemented";
			default:
				printf("Unhandled system call: %u\n", scall);
				auto regs = cpu.registers();
				regs.rax = -ENOSYS;
				cpu.set_registers(regs);
		}
	});

	/* Setup */
	const tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = GUEST_WORK_MEM,
		.reset_free_work_mem = 0,
		.verbose_loader = false,
		.hugepages = (getenv("HUGE") != nullptr),
	};
	tinykvm::Machine master_vm {binary, options};
	//master_vm.set_stack_address(0x800000);
	master_vm.setup_linux(
		{"vmod_kvm", "xpizza.com"
					 "0"},
		{"LC_TYPE=C", "LC_ALL=C", "USER=root"});

	const auto rsp = master_vm.stack_address();
	//master_vm.print_pagetables();

	uint64_t call_addr = verify_exists(master_vm, "my_backend");

	/* Remote debugger session */
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
			vm->setup_call(regs, call_addr, rsp);
			vm->set_registers(regs);
		} else if (getenv("VMCALL")) {
			master_vm.setup_call(regs, call_addr, rsp);
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

	asm("" ::: "memory");
	auto t0 = time_now();
	asm("" ::: "memory");

	/* Normal execution of _start -> main() */
	master_vm.run();

	asm("" ::: "memory");
	auto t1 = time_now();
	asm("" ::: "memory");

	if (call_addr == 0x0) {
		double t = nanodiff(t0, t1) / 1e9;
		printf("Time: %fs Return value: %ld\n", t, master_vm.return_value());
		return 0;
	}

	/* Fork master VM */
	master_vm.prepare_copy_on_write();
	tinykvm::Machine vm{master_vm, options};

	/* Make a VM function call */
	tinykvm::tinykvm_x86regs regs;
	vm.setup_call(regs, call_addr, rsp);
	vm.set_registers(regs);
	printf("Calling fork at 0x%lX\n", call_addr);
	vm.run(5.0f);

	/* Re-run */
	vm.reset_to(master_vm, options);

	vm.setup_call(regs, call_addr, rsp);
	vm.set_registers(regs);
	printf("Calling fork at 0x%lX\n", call_addr);
	vm.run(5.0f);
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
