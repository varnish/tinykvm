#include <tinykvm/machine.hpp>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <sys/uio.h>
#include "assert.hpp"
#include "load_file.hpp"

#define GUEST_MEMORY   0x80000000  /* 2GB memory */
#define GUEST_WORK_MEM 1024UL * 1024*1024 /* MB working mem */

inline timespec time_now();
inline long nanodiff(timespec start_time, timespec end_time);

static void do_benchmark(tinykvm::Machine& sender_vm, tinykvm::Machine& receiver_vm,
		int pipefd[2],
		uint64_t& vmsplice_addr, uint64_t& vmsplice_size,
		uint64_t& input_addr, uint64_t& input_size,
		uint64_t receiver_addr, uint64_t sender_addr,
		bool with_vmsplice = true)
{
	// Receiver VM will do a "blocking" syscall (pause)
	receiver_vm.vmcall(receiver_addr);
	if (input_addr == 0 || input_size == 0) {
		fprintf(stderr, "Error: input_addr == 0 || input_size == 0\n");
		exit(1);
	}
	// Sender VM will do a syscall that starts a vmsplice()
	// and then we resume receiver_vm while sender_vm is "doing this"
	sender_vm.vmcall(sender_addr);
	if (vmsplice_addr == 0 || vmsplice_size == 0) {
		fprintf(stderr, "Error: vmsplice_addr == 0 || vmsplice_size == 0\n");
		exit(1);
	}
	// Map the pipe from source data
	std::vector<tinykvm::Machine::Buffer> bufs;
	sender_vm.gather_buffers_from_range(bufs, vmsplice_addr, vmsplice_size);
	if (with_vmsplice) {
		if (vmsplice(pipefd[1], (const struct iovec *)bufs.data(), bufs.size(), SPLICE_F_MOVE) == -1) {
			perror("vmsplice");
			exit(1);
		}
	}

	// Resume receiver_vm which now has data
	std::vector<tinykvm::Machine::WrBuffer> wbufs;
	receiver_vm.writable_buffers_from_range(wbufs, input_addr, input_size);
	// Do the final readv() into the VM memory
	if (with_vmsplice) {
		if (readv(pipefd[0], (const struct iovec *)wbufs.data(), wbufs.size()) == -1) {
			perror("readv");
			exit(1);
		}
	}
	receiver_vm.vmresume();
}
static double benchmark(bool with_vmsplice,
	tinykvm::Machine& vm1, tinykvm::Machine& vm2,
	int pipefd[2],
	uint64_t& vmsplice_addr, uint64_t& vmsplice_size,
	uint64_t& input_addr, uint64_t& input_size,
	uint64_t receiver_addr, uint64_t sender_addr)
{
	asm("" ::: "memory");
	timespec t0 = time_now();
	asm("" ::: "memory");

	// Benchmark the two VMs
	for (int i = 0; i < 1000; i++) {
		do_benchmark(vm1, vm2, pipefd,
			vmsplice_addr, vmsplice_size,
			input_addr, input_size,
			receiver_addr, sender_addr,
			with_vmsplice);
	}

	asm("" ::: "memory");
	timespec t1 = time_now();
	asm("" ::: "memory");

	// Results
	const double total_us = nanodiff(t0, t1) * 1e-3;
	const double avg_us = (double)total_us / 1000.0;
	printf("Average time for %s between two VMs: %.3f us\n",
		with_vmsplice ? "vmsplice()" : "(no vmsplice)",
		avg_us);
	return avg_us;
}

int main(int argc, char** argv)
{
	if (argc < 2) {
		fprintf(stderr, "Missing argument: 64-bit ELF binary\n");
		exit(1);
	}
	std::vector<uint8_t> binary;
	std::vector<std::string> args;
	std::string filename = argv[1];
	binary = load_file(filename);

	const tinykvm::DynamicElf dyn_elf = tinykvm::is_dynamic_elf(
		std::string_view{(const char*)binary.data(), binary.size()});
	if (dyn_elf.is_dynamic) {
		// Add ld-linux.so.2 as first argument
		static const std::string ld_linux_so = "/lib64/ld-linux-x86-64.so.2";
		binary = load_file(ld_linux_so);
		args.push_back(ld_linux_so);
	}

	for (int i = 1; i < argc; i++) {
		args.push_back(argv[i]);
	}

	tinykvm::Machine::init();

	/* Setup */
	const tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = GUEST_WORK_MEM,
		.reset_free_work_mem = 0,
		.verbose_loader = true,
		.executable_heap = dyn_elf.is_dynamic,
	};
	tinykvm::Machine master_vm {binary, options};
	//master_vm.print_pagetables();
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
	}

	master_vm.setup_linux(
		args,
		{"LC_TYPE=C", "LC_ALL=C", "USER=root"});

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

	/* Fork master VM */
	master_vm.prepare_copy_on_write();

	static uint64_t vmsplice_addr = 0;
	static uint64_t vmsplice_size = 0;
	static uint64_t input_addr = 0;
	static uint64_t input_size = 0;
	int pipefd[2];
	// Create a pipe to do the vmsplice() into
	if (pipe(pipefd) == -1) {
		perror("pipe");
		exit(1);
	}
	tinykvm::Machine::install_unhandled_syscall_handler(
	[] (tinykvm::vCPU& cpu, unsigned scall) {
		switch (scall) {
			case 0x10000:
				// A "blocking" syscall that does a vmsplice()
				vmsplice_addr = cpu.registers().rdi;
				vmsplice_size = cpu.registers().rsi;
				cpu.stop();
				cpu.registers().rip += 2; // Skip OUT instruction
				cpu.set_registers(cpu.registers());
				break;
			case 0x10001:
				// The input buffer address
				// now blocking, waiting for a resume
				input_addr = cpu.registers().rdi;
				input_size = cpu.registers().rsi;
				cpu.stop();
				cpu.registers().rip += 2; // Skip OUT instruction
				cpu.set_registers(cpu.registers());
				break;
			case 0x10707:
				throw "Unimplemented";
			default:
				printf("Unhandled system call: %u\n", scall);
				auto regs = cpu.registers();
				regs.rax = -ENOSYS;
				cpu.set_registers(regs);
		}
	});

	const uint64_t sender_addr = master_vm.address_of("caller");
	const uint64_t receiver_addr = master_vm.address_of("resumer");

	tinykvm::Machine vm1{master_vm, options};
	tinykvm::Machine vm2{master_vm, options};

	// Warmup run
	for (int i = 0; i < 10; i++) {
		do_benchmark(vm1, vm2, pipefd,
			vmsplice_addr, vmsplice_size,
			input_addr, input_size,
			receiver_addr, sender_addr);
	}

	// Benchmark with vmsplice()
	double vmsplice_time = benchmark(true, vm1, vm2, pipefd,
		vmsplice_addr, vmsplice_size,
		input_addr, input_size,
		receiver_addr, sender_addr);
	
	// Benchmark without vmsplice()
	double no_vmsplice_time = benchmark(false, vm1, vm2, pipefd,
		vmsplice_addr, vmsplice_size,
		input_addr, input_size,
		receiver_addr, sender_addr);

	// Results
	printf("vmsplice() overhead: %.3f us\n", vmsplice_time - no_vmsplice_time);

	// Cleanup
	close(pipefd[0]);
	close(pipefd[1]);
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
