#include <tinykvm/machine.hpp>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include "assert.hpp"
#include "load_file.hpp"

#include <tinykvm/rsp_client.hpp>
/* Main memory is MAP_NORESERVE: an address-space ceiling, not a commitment,
   as only touched pages are backed. Keep it generous, as guests that reserve
   huge PROT_NONE arenas up front push later mmaps past max_mem, where they
   fault on first touch. */
#define GUEST_MEMORY   (32ULL << 30)  /* 32GB address space */
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

	// Absolute path, for matching against /proc/self/fd and for resolving
	// the guest's /proc/self/exe symlink.
	char abs_path[PATH_MAX];
	if (realpath(filename.c_str(), abs_path) == nullptr) {
		fprintf(stderr, "Error resolving absolute path of '%s'\n", filename.c_str());
		exit(1);
	}
	guest_program_path = abs_path;

	const tinykvm::DynamicElf dyn_elf = tinykvm::is_dynamic_elf(
		std::string_view{(const char*)binary.data(), binary.size()});
	if (dyn_elf.is_dynamic) {
		// Keep the guest binary for symbol resolution later
		guest_binary = std::move(binary);
		// Load the dynamic linker as the main program
		static const std::string ld_linux_so = "/lib64/ld-linux-x86-64.so.2";
		binary = load_file(ld_linux_so);
		args.push_back(ld_linux_so);
	}

	for (int i = 1; i < argc; i++)
	{
		args.push_back(argv[i]);
	}

	/* Pass the host environment through to the guest, so eg. RUST_BACKTRACE=1
	   works. */
	std::vector<std::string> env {"LC_TYPE=C", "LC_ALL=C", "USER=root"};
	for (char** e = environ; *e != nullptr; e++)
	{
		std::string_view entry{*e};
		/* Keep the defaults set above. */
		if (entry.starts_with("LC_TYPE=") || entry.starts_with("LC_ALL=")
			|| entry.starts_with("USER="))
			continue;
		env.push_back(std::string(entry));
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
	master_vm.set_verbose_system_calls(getenv("VERBOSE") != nullptr);
	master_vm.set_verbose_mmap_syscalls(getenv("VERBOSE_MMAP") != nullptr);
	uint64_t guest_program_base = 0;

	/* simplekvm runs with the safeties off: the guest may open any path the
	   host user can, for reading and writing, and symlinks resolve against the
	   host filesystem. Embedders need a real policy here, see storage.cpp. */
	master_vm.fds().set_open_readable_callback(
		[] (std::string&) -> bool { return true; });
	master_vm.fds().set_open_writable_callback(
		[] (std::string&) -> bool { return true; });
	master_vm.fds().set_resolve_symlink_callback(
		[&] (std::string& path) -> bool {
			/* Point /proc/self/exe at the real program, so that eg. Rust
			   backtraces can find their own symbols. */
			if (path == "/proc/self/exe") {
				path = guest_program_path;
				return true;
			}
			char resolved[PATH_MAX];
			const ssize_t len = readlink(path.c_str(), resolved, sizeof(resolved) - 1);
			if (len <= 0)
				return false;
			resolved[len] = '\0';
			path = resolved;
			return true;
		}
	);

	if (dyn_elf.is_dynamic) {
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

	master_vm.setup_linux(args, env);

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
		if (getenv("BT")) {
			master_vm.print_remote_gdb_backtrace(filename,
				{.command = "bt", .verbose = false, .quit = true});
		}
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
