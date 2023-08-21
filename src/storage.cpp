#include <tinykvm/machine.hpp>
#include <cstring>
#include <cstdio>
#include "assert.hpp"
#include "load_file.hpp"
#include "timing.hpp"

#include <tinykvm/rsp_client.hpp>
#define GUEST_MEMORY   0x40000000  /* 1024MB memory */
#define GUEST_WORK_MEM 256UL * 1024*1024 /* MB working mem */

static double timed_action(std::function<void()> action)
{
	asm("" ::: "memory");
	auto t0 = time_now();
	asm("" ::: "memory");

	action();

	asm("" ::: "memory");
	auto t1 = time_now();
	asm("" ::: "memory");

	return nanodiff(t0, t1) / 1e9;
}

int main(int argc, char** argv)
{
	if (argc < 3) {
		fprintf(stderr, "%s  [guest ELF] [storage ELF]\n", argv[0]);
		exit(1);
	}
	const auto guest_binary   = load_file(argv[1]);
	const auto storage_binary = load_file(argv[2]);
	printf(">>> Guest: %s  >>> Storage: %s\n", argv[1], argv[2]);

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
	tinykvm::Machine master_vm {guest_binary, options};
	master_vm.setup_linux(
		{"main", "Hello Main World!"},
		{"LC_TYPE=C", "LC_ALL=C", "USER=root"});
	//master_vm.print_pagetables();

	/* Create storage VM */
	const tinykvm::MachineOptions storage_options {
		.max_mem = 256ULL << 20, // MB
		.vmem_base_address = 1ULL << 30, // 1GB
		.verbose_loader = false,
		.hugepages = (getenv("HUGE") != nullptr),
	};
	tinykvm::Machine storage_vm{storage_binary, storage_options};
	storage_vm.setup_linux(
		{"storage", "Hello Storage World!"},
		{"LC_TYPE=C", "LC_ALL=C", "USER=root"});
	storage_vm.run(5.0f);

	master_vm.remote_connect(storage_vm, false);

	auto tdiff = timed_action([&] {
		try {
			master_vm.run();
		} catch (const tinykvm::MachineException& e) {
			fprintf(stderr, "Exception: %s with data 0x%lX\n",
				e.what(), e.data());
		} catch (const tinykvm::MemoryException& e) {
			fprintf(stderr, "Exception: %s at 0x%lX (size=%lu)\n",
				e.what(), e.data(), e.size());
		}
	});
	printf("Call time: %fms Return value: %ld\n", tdiff*1e3, master_vm.return_value());

	/* Allow forking the master VM */
	master_vm.prepare_copy_on_write(GUEST_WORK_MEM, 1ULL << 30);

	/* Fork the master VM, and install remote memory */
	tinykvm::Machine vm{master_vm, options};
	assert(vm.is_remote_connected());

	/* Call 'do_calculation' with 21 as argument */
	const auto call_addr = vm.address_of("do_calculation");
	if (call_addr == 0x0)
		throw std::runtime_error("Function 'do_calculation' is missing in " + std::string(argv[1]));
	auto fork_tdiff = timed_action([&] {
		try {
			vm.timed_vmcall(call_addr, 5.0f, 21);
		} catch (const tinykvm::MachineException& e) {
			fprintf(stderr, "Exception: %s with data 0x%lX\n",
				e.what(), e.data());
		} catch (const tinykvm::MemoryException& e) {
			fprintf(stderr, "Exception: %s at 0x%lX (size=%lu)\n",
				e.what(), e.data(), e.size());
		}
	});
	printf("Fork call time: %fms Return value: %ld\n", fork_tdiff*1e3, vm.return_value());
}
