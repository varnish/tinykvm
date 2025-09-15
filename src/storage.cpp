#include <tinykvm/machine.hpp>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include "assert.hpp"
#include "load_file.hpp"
#include "timing.hpp"

#include <tinykvm/rsp_client.hpp>
#define GUEST_MEMORY   1024UL * 1024 * 1024  /* 1024MB main memory */
#define GUEST_WORK_MEM 256UL * 1024 * 1024 /* 256MB working memory */
static const std::string ld_linux_so = "/lib64/ld-linux-x86-64.so.2";

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
	const std::string guest_binary_path = argv[1];
	auto original_guest_binary = load_file(guest_binary_path);
	const std::string storage_binary_path = argv[2];
	const auto storage_binary = load_file(storage_binary_path);
	printf(">>> Guest: %s  >>> Storage: %s\n", guest_binary_path.c_str(), storage_binary_path.c_str());
	std::string cwd;
	{
		char buf[PATH_MAX];
		if (getcwd(buf, sizeof(buf)) != nullptr)
			cwd = buf;
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

	std::vector<std::string> guest_args;
	std::vector<uint8_t> guest_binary;
	const tinykvm::DynamicElf guest_dyn_elf = tinykvm::is_dynamic_elf(
		std::string_view{(const char*)original_guest_binary.data(), original_guest_binary.size()});
	if (guest_dyn_elf.is_dynamic) {
		// Add ld-linux.so.2 as first argument
		guest_binary = load_file(ld_linux_so);
		guest_args.push_back(ld_linux_so);
	} else {
		guest_binary = original_guest_binary;
	}
	guest_args.push_back(guest_binary_path);
	guest_args.push_back("Hello Main World!");

	/* Setup */
	const tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = GUEST_WORK_MEM,
		.dylink_address_hint = 0x400000, // 4MB
		.verbose_loader = false,
		.executable_heap = guest_dyn_elf.is_dynamic,
		.mmap_backed_files = true,
	};
	tinykvm::Machine master_vm {guest_binary, options};
	master_vm.setup_linux(
		guest_args,
		{"LC_TYPE=C", "LC_ALL=C", "USER=root"});
	//master_vm.print_pagetables();
	master_vm.fds().set_open_readable_callback(
		[] (std::string&) -> bool {
		return true;
	});
	master_vm.set_verbose_system_calls(getenv("VERBOSE") != nullptr);

	std::vector<std::string> storage_args;
	storage_args.push_back(storage_binary_path);
	storage_args.push_back("Hello Storage World!");

	/* Create storage VM */
	const tinykvm::MachineOptions storage_options {
		.max_mem = 256ULL << 20, // MB
		.dylink_address_hint = 0x44000000, // 1GB + 64MB
		.vmem_base_address = 1ULL << 30, // 1GB
		.verbose_loader = false,
		.mmap_backed_files = true,
	};
	tinykvm::Machine storage_vm{storage_binary, storage_options};
	storage_vm.set_verbose_system_calls(getenv("VERBOSE") != nullptr);
	storage_vm.set_verbose_mmap_syscalls(getenv("VERBOSE") != nullptr);
	storage_vm.set_verbose_thread_syscalls(getenv("VERBOSE") != nullptr);
	storage_vm.fds().set_vfd_start(65536); // Avoid "collisions" with master VM
	storage_vm.fds().set_open_readable_callback(
		[] (std::string&) -> bool {
		return true;
	});
	storage_vm.fds().set_current_working_directory(cwd.c_str());
	storage_vm.setup_linux(
		storage_args,
		{"LC_TYPE=C", "LC_ALL=C", "USER=root"});
	storage_vm.run(5.0f);

	master_vm.remote_connect(storage_vm, false);

	static std::map<std::string, uint64_t> callback_address;
	master_vm.install_unhandled_syscall_handler(
	[] (tinykvm::vCPU& cpu, unsigned sysnum) {
		auto& regs = cpu.registers();
		switch (sysnum) {
			case 0x10001: { // Set callback address
					auto view = cpu.machine().string_or_view(regs.rsi, regs.rdx);
					const std::string name = view.to_string();
					callback_address[name] = regs.rdi;
					printf("Set callback '%s' to 0x%llX\n", name.c_str(), regs.rdi);
					return;
				}
			default:
				printf("Unhandled master VM syscall: %u\n", sysnum);
				regs.rax = -ENOSYS;
				cpu.set_registers(regs);
		}
	});

	auto tdiff = timed_action([&] {
		try {
			master_vm.run();
			return;
		} catch (const tinykvm::MemoryException& e) {
			fprintf(stderr, "Exception: %s at 0x%lX (size=%lu)\n",
				e.what(), e.data(), e.size());
			master_vm.print_registers();
		} catch (const tinykvm::MachineException& e) {
			fprintf(stderr, "Exception: %s with data 0x%lX\n",
				e.what(), e.data());
			master_vm.print_registers();
		}
		fprintf(stderr, "Error: Failed to initialize main VM, exiting\n");
		exit(1);
	});
	printf("Boot time: %.2fus Return value: %ld\n", tdiff*1e6, master_vm.return_value());

	/* Allow forking the master VM */
	master_vm.prepare_copy_on_write(GUEST_WORK_MEM, 1ULL << 30);

	/* Fork the master VM, and install remote memory */
	tinykvm::Machine vm{master_vm, options};
	assert(vm.has_remote());

	/* Measure call overhead */
	auto do_it = callback_address.find("do_nothing");
	if (do_it == callback_address.end()) {
		fprintf(stderr, "Error: no do_nothing() in guest\n");
		exit(1);
	}
	auto calc_it = callback_address.find("do_calculation");
	if (calc_it == callback_address.end()) {
		fprintf(stderr, "Error: no do_calculation() in guest\n");
		exit(1);
	}
	auto call_overhead = timed_action([&] {
		for (int i = 0; i < 100; i++)
			vm.vmcall(do_it->second, 5.0f, 21);
	}) / 100.0;
	printf("Call overhead: %.2fus\n", call_overhead * 1e6);

	/* Call 'do_calculation' with 21 as argument */
	printf("Calling do_calculation() @ 0x%lX\n", calc_it->second);
	for (int i = 0; i < 50; i++)
		vm.vmcall(calc_it->second, 21);
	auto fork_tdiff = timed_action([&] {
		for (int i = 0; i < 500; i++)
			vm.vmcall(calc_it->second, 21);
	}) / 500.0;
	if (vm.remote_connection_count() < 500) {
		fprintf(stderr, "Error: only %u remote connections were made, expected 500\n",
			vm.remote_connection_count());
		exit(1);
	}
	fork_tdiff -= call_overhead;
	printf("Remote call time: %.2fus Return value: %ld\n", fork_tdiff * 1e6, vm.return_value());
}
