#include <tinykvm/machine.hpp>
#include <cstring>
#include <sys/uio.h>
#include <sys/utsname.h>
#define ENABLE_GUEST_STDOUT
//#define ENABLE_GUEST_VERBOSE

void setup_vm_system_calls(tinykvm::Machine& vm)
{
	vm.install_unhandled_syscall_handler(
		[] (auto& machine, unsigned scall) {
			fprintf(stderr,	"Unhandled system call: %u\n", scall);
			auto regs = machine.registers();
			regs.rax = -1;
			machine.set_registers(regs);
		});
	vm.install_syscall_handler(
		1, [] (auto& machine) {
#ifdef ENABLE_GUEST_STDOUT
			auto regs = machine.registers();
			auto view = machine.memory_at(regs.rsi, regs.rdx);
			if (!view.empty()) {
				fwrite(view.begin(), view.size(), 1, stdout);
				fflush(stdout);
			} else {
				fprintf(stderr, "Invalid memory from guest: 0x%llX:%llu\n",
					regs.rsi, regs.rdx);
			}
#endif
		});
	vm.install_syscall_handler(
		5, [] (auto& machine) { // FSTAT
			auto regs = machine.registers();
			regs.rax = -ENOSYS;
			machine.set_registers(regs);
		});
	vm.install_syscall_handler(
		7, [] (auto& machine) { // POLL
			auto regs = machine.registers();

			struct pollfd {
				int   fd;         /* file descriptor */
				short events;     /* requested events */
				short revents;    /* returned events */
			};
			const size_t bytes = sizeof(pollfd) * regs.rsi;
			auto* fds = machine.template rw_memory_at<struct pollfd>(regs.rdi, bytes);
			for (size_t i = 0; i < regs.rsi; i++) {
				fds[i].revents = fds[i].events;
			}

			regs.rax = 0;
			machine.set_registers(regs);
		});
	vm.install_syscall_handler(
		9, [] (auto& machine) { // MMAP
			/* SYS mmap */
			auto regs = machine.registers();
			printf("mmap(0x%llX, %llu)\n",
				regs.rdi, regs.rsi);
			regs.rax = ~(uint64_t) 0; /* MAP_FAILED */
			regs.rax = machine.heap_address();
			machine.set_registers(regs);
		});
	vm.install_syscall_handler(
		10, [] (auto& machine) { // MPROTECT
			/* SYS mprotect */
			auto regs = machine.registers();
			printf("mprotect(0x%llX, %llu, 0x%llX)\n",
				regs.rdi, regs.rsi, regs.rdx);
			regs.rax = 0;
			machine.set_registers(regs);
		});
	vm.install_syscall_handler(
		12, [] (auto& machine) {
			/* SYS brk */
			auto regs = machine.registers();
			if (regs.rdi > machine.max_address()) {
				regs.rax = machine.max_address();
			} else if (regs.rdi < machine.heap_address()) {
				regs.rax = machine.heap_address();
			} else {
				regs.rax = regs.rdi;
			}
			machine.set_registers(regs);
		});
	vm.install_syscall_handler(
		16, [] (auto& machine) {
			/* SYS ioctl */
			auto regs = machine.registers();
			if (regs.rax > machine.max_address()) {
				regs.rax = machine.max_address();
			}
			machine.set_registers(regs);
		});
	vm.install_syscall_handler(
		20, [] (auto& machine) {
			/* SYS writev */
			auto regs = machine.registers();
			struct g_iovec {
				uint64_t iov_base;
				size_t   iov_len;
			};
			/* writev: Stdout, Stderr */
			if (regs.rdi == 1 || regs.rdi == 2)
			{
				const size_t bytes = sizeof(g_iovec) * regs.rdx;
				size_t written = 0;
				auto* vec = machine.template rw_memory_at<g_iovec>(regs.rsi, bytes);
				for (size_t i = 0; i < regs.rdx; i++) {
					// Ignore empty writes?
					if (vec[i].iov_len == 0)
						continue;
					auto sv = machine.memory_at(vec[i].iov_base, vec[i].iov_len);
#ifdef ENABLE_GUEST_STDOUT
					//printf(">>> Guest writes %zu bytes to %llu from iov %zu/%llu\n",
					//	sv.size(), regs.rdi, i, regs.rdx);
					static const char gw[] = ">>> Guest says: ";
					struct iovec vec[] = {
						{(void *)gw, sizeof(gw)-1},
						{(void *)sv.begin(), sv.size()}
					};
					writev(0, vec, 2);
#endif
					written += sv.size();
				}
				regs.rax = written;
			} else {
				regs.rax = -1;
			}
			machine.set_registers(regs);
		});
	vm.install_syscall_handler(
		21, [] (auto& machine) {
			auto regs = machine.registers();
			printf("SYSCALL access 0x%llX 0x%llX\n", regs.rdi, regs.rsi);
			regs.rax = -1;
			machine.set_registers(regs);
		});
	vm.install_syscall_handler(
		60, [] (auto& machine) {
			auto regs = machine.registers();
#ifdef ENABLE_GUEST_VERBOSE
			printf("Machine exited with return value 0x%llX\n", regs.rdi);
#endif
			machine.stop();
		});
	vm.install_syscall_handler(
		63, [] (tinykvm::Machine& machine) {
			auto regs = machine.registers();
			if (machine.memory_safe_at(regs.rdi, sizeof(struct utsname)))
			{
				auto* uts = machine.rw_memory_at<struct utsname>(regs.rdi, sizeof(struct utsname));
				strcpy(uts->sysname, "Linux");
				strcpy(uts->release, "3.2.0");
				regs.rax = 0;
				machine.set_registers(regs);
				return;
			}
			printf("SYSCALL utsname failed on 0x%llX\n", regs.rdi);
			regs.rax = -EFAULT;
			machine.set_registers(regs);
		});
	vm.install_syscall_handler(
		72, [] (auto& machine) { // FCNTL
			auto regs = machine.registers();
			regs.rax = -ENOSYS;
			machine.set_registers(regs);
		});
	vm.install_syscall_handler(
		218, [] (auto& machine) {
			/* SYS set_tid_address */
			auto regs = machine.registers();
#ifdef ENABLE_GUEST_VERBOSE
			printf("Set TID address: clear_child_tid=0x%llX\n", regs.rdi);
#endif
			regs.rax = 0;
			machine.set_registers(regs);
		});
	vm.install_syscall_handler(
		231, [] (auto& machine) {
			/* SYS exit_group */
			auto regs = machine.registers();
#ifdef ENABLE_GUEST_VERBOSE
			printf("Machine exits: _exit(%lld)\n", regs.rdi);
#endif
			machine.stop();
		});
}
