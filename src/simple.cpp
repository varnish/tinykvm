#include <tinykvm/machine.hpp>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include "assert.hpp"
#include "load_file.hpp"

#include <tinykvm/rsp_client.hpp>
#define GUEST_MEMORY   0x80000000  /* 2GB memory */
#define GUEST_WORK_MEM 1024UL * 1024*1024 /* MB working mem */

inline timespec time_now();
inline long nanodiff(timespec start_time, timespec end_time);

// Use intercepted guest program base address, and the unrelocated symbol
// from the guest binary to resolve the actual symbol address
struct DynamicResolver {
	DynamicResolver(const std::vector<uint8_t>& binary, uint64_t guest_program_base)
		: m_binary{binary}, m_base_addr{guest_program_base}
	{
	}

	uint64_t resolve(std::string_view symbol) const noexcept
	{
		uint64_t addr = tinykvm::Machine::AddressOf(symbol, std::string_view{(const char*)m_binary.data(), m_binary.size()});
		if (addr != 0x0) {
			addr += m_base_addr;
		}
		return addr;
	}

private:
	const std::vector<uint8_t>& m_binary;
	uint64_t m_base_addr = 0;
};

int main(int argc, char** argv)
{
	if (argc < 2) {
		fprintf(stderr, "Missing argument: 64-bit ELF binary\n");
		exit(1);
	}
	std::vector<uint8_t> binary;
	std::vector<uint8_t> guest_binary;
	std::vector<std::string> args;
	std::string filename = argv[1];
	std::string guest_program_path; // Absolute path
	binary = load_file(filename);

	const tinykvm::DynamicElf dyn_elf = tinykvm::is_dynamic_elf(
		std::string_view{(const char*)binary.data(), binary.size()});
	if (dyn_elf.is_dynamic) {
		// Keep the guest binary for symbol resolution later
		guest_binary = std::move(binary);
		// Load the dynamic linker as the main program
		static const std::string ld_linux_so = "/lib64/ld-linux-x86-64.so.2";
		binary = load_file(ld_linux_so);
		args.push_back(ld_linux_so);

		// Absolute path for matching against /proc/self/fd
		char abs_path[PATH_MAX];
		if (realpath(filename.c_str(), abs_path) == nullptr) {
			fprintf(stderr, "Error resolving absolute path of '%s'\n", filename.c_str());
			exit(1);
		}
		guest_program_path = abs_path;
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
		.executable_heap = dyn_elf.is_dynamic,
	};
	tinykvm::Machine master_vm {binary, options};
	//master_vm.print_pagetables();
	uint64_t guest_program_base = 0;
	if (dyn_elf.is_dynamic) {
		static const std::vector<std::string> allowed_readable_paths({
			argv[1],
			// Add all common standard libraries to the list of allowed readable paths
			"/lib64/ld-linux-x86-64.so.2",
			"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
			"/lib/x86_64-linux-gnu/libgcc_s.so.1",
			"/lib/x86_64-linux-gnu/libc.so.6",
			"/lib/x86_64-linux-gnu/libm.so.6",
			"/lib/x86_64-linux-gnu/libpthread.so.0",
			"/lib/x86_64-linux-gnu/libdl.so.2",
			"/lib/x86_64-linux-gnu/libstdc++.so.6",
			"/lib/x86_64-linux-gnu/librt.so.1",
			"/lib/x86_64-linux-gnu/libz.so.1",
			"/lib/x86_64-linux-gnu/libexpat.so.1",
			"/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v2/libstdc++.so.6",
			"/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libstdc++.so.6",
			"/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v4/libstdc++.so.6",
		});
		master_vm.fds().set_open_readable_callback(
			[&] (std::string& path) -> bool {
				return std::find(allowed_readable_paths.begin(),
					allowed_readable_paths.end(), path) != allowed_readable_paths.end();
			}
		);

		// Match /proc/self/fd/<fd> to see if it points to our guest program
		master_vm.set_mmap_callback(
			[&] (tinykvm::vCPU& cpu, uint64_t, size_t, int, int, int fd, uint64_t offset)
			{
				if (fd < 0 || offset != 0 || guest_program_base != 0)
					return;
				char linkpath[64];
				snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", fd);
				char resolved[PATH_MAX];
				ssize_t len = readlink(linkpath, resolved, sizeof(resolved) - 1);
				if (len > 0) {
					resolved[len] = '\0';
					if (guest_program_path == resolved) {
						guest_program_base = cpu.registers().rax;
						printf("Guest program loaded at 0x%lX\n", guest_program_base);
					}
				}
			}
		);
	}

	master_vm.setup_linux(
		args,
		{"LC_TYPE=C", "LC_ALL=C", "USER=root"});

	/* Remote debugger session */
	if (getenv("DEBUG"))
	{
		tinykvm::RSP server {filename, master_vm, 2159};
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
				master_vm.print_registers();
			}
		} else {
			/* Resume execution normally */
			master_vm.run();
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

	DynamicResolver resolver{guest_binary, guest_program_base};
	uint64_t call_addr = 0x0;
	if (dyn_elf.is_dynamic) {
		call_addr = resolver.resolve("my_backend");
		if (call_addr != 0x0) {
			printf("Resolved 'my_backend' at 0x%lX (image_base 0x%lX, guest_base 0x%lX)\n",
				call_addr, master_vm.image_base(), guest_program_base);
		}
	} else {
		// For static executables, resolve symbols directly from the loaded binary.
		call_addr = master_vm.address_of("my_backend");
		printf("Resolved 'my_backend' at 0x%lX\n", call_addr);
	}

	if (call_addr == 0x0) {
		double t = nanodiff(t0, t1) / 1e9;
		printf("Time: %fs Return value: %ld\n", t, master_vm.return_value());
		return 0;
	}

	/* Fork master VM */
	master_vm.prepare_copy_on_write();
	tinykvm::Machine vm{master_vm, options};

	/* Make a VM function call */
	printf("Calling fork at 0x%lX\n", call_addr);
	struct MyStruct {
		int a;
		float b;
		char c;
	} arg2 {42, 3.14f, 'X'};
	vm.timed_vmcall(call_addr, 8.0f, "Hello from vmcall!", arg2, 42);

	/* Re-run */
	arg2 = {84, 2.718f, 'Y'};
	vm.reset_to(master_vm, options);

	vm.timed_vmcall(call_addr, 8.0f, "Second call after reset!", arg2, 84);
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
