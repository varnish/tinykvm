#include <tinykvm/machine.hpp>
#include <cstring>
#include <cstdio>
#include "assert.hpp"
#include "load_file.hpp"

#include <tinykvm/rsp_client.hpp>
#define GUEST_MEMORY   0x80000000  /* 2GB memory */
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
	std::vector<uint8_t> binary;
	std::vector<std::string> args;
	binary = load_file(argv[1]);

	const bool is_dynamic = tinykvm::is_dynamic_elf(
		std::string_view{(const char*)binary.data(), binary.size()});
	if (is_dynamic)
	{
		// Add ld-linux.so.2 as first argument
		binary = load_file("/lib64/ld-linux-x86-64.so.2");
		args.push_back("/lib64/ld-linux-x86-64.so.2");
	}

	for (int i = 1; i < argc; i++)
	{
		args.push_back(argv[i]);
	}

	tinykvm::Machine::init();

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

	const std::vector<tinykvm::VirtualRemapping> remappings {
		{
			.phys = 0x0,
			.virt = 0xC000000000,
			.size = 512ULL << 20,
		}
	};

	/* Setup */
	const tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = GUEST_WORK_MEM,
		.reset_free_work_mem = 0,
		.vmem_base_address = uint64_t(getenv("UPPER") != nullptr ? 0x40000000 : 0x0),
		.remappings {remappings},
		.verbose_loader = true,
		.hugepages = (getenv("HUGE") != nullptr),
		.relocate_fixed_mmap = (getenv("GO") == nullptr),
		.executable_heap = is_dynamic,
	};
	tinykvm::Machine master_vm {binary, options};
	//master_vm.print_pagetables();
	if (is_dynamic) {
		master_vm.fds().add_readonly_file(argv[1]);
	}

	master_vm.setup_linux(
		args,
		{"LC_TYPE=C", "LC_ALL=C", "USER=root"});

	const auto rsp = master_vm.stack_address();

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
	try {
		master_vm.run();
	} catch (const tinykvm::MachineException& me) {
		master_vm.print_registers();
		fprintf(stderr, "Machine exception: %s  Data: 0x%lX\n", me.what(), me.data());
		throw;
	} catch (...) {
		master_vm.print_registers();
		throw;
	}

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
	tinykvm::tinykvm_regs regs;
	vm.setup_call(regs, call_addr, rsp);
	//regs.rip = vm.entry_address_if_usermode();
	vm.set_registers(regs);
	printf("Calling fork at 0x%lX\n", call_addr);
	vm.run(8.0f);

	/* Re-run */
	//vm.reset_to(master_vm, options);

	vm.setup_call(regs, call_addr, rsp);
	//regs.rip = vm.entry_address_if_usermode();
	vm.set_registers(regs);
	printf("Calling fork at 0x%lX\n", call_addr);
	vm.run(8.0f);
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
