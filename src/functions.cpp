#include <tinykvm/machine.hpp>
#include <cstring>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
//#define ENABLE_GUEST_STDOUT
//#define ENABLE_GUEST_VERBOSE
//#define VERBOSE_MMAP
//#define VERBOSE_SYSCALLS



#ifdef VERBOSE_MMAP
#define PRINTMMAP(fmt, ...) printf(fmt, __VA_ARGS__);
#else
#define PRINTMMAP(fmt, ...) /* */
#endif

#ifdef VERBOSE_SYSCALLS
#define SYSPRINT(fmt, ...) printf(fmt, __VA_ARGS__);
#else
#define SYSPRINT(fmt, ...) /* */
#endif
using namespace tinykvm;

void setup_kvm_system_calls()
{
	Machine::install_unhandled_syscall_handler(
		[] (auto& machine, unsigned scall) {
			SYSPRINT("Unhandled system call: %u\n", scall);
			auto regs = machine.registers();
			regs.rax = -ENOSYS;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		0, [] (auto& machine) { // READ
			auto regs = machine.registers();
			fprintf(stderr, "READ to fd=%lld, data=0x%llX, size=%llu\n",
				regs.rdi, regs.rsi, regs.rdx);
			//auto data = machine.rw_memory_at(regs.rsi, regs.rdx);
			//regs.rax = regs.rdx;
			regs.rax = -ENOSYS;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		1, [] (auto& machine) { // WRITE
			auto regs = machine.registers();
			auto view = machine.memory_at(regs.rsi, regs.rdx);
			if (!view.empty()) {
#ifdef ENABLE_GUEST_STDOUT
				fwrite(view.begin(), view.size(), 1, stdout);
#endif
				regs.rax = regs.rsi;
			} else {
				fprintf(stderr, "Invalid memory from guest: 0x%llX:%llu\n",
					regs.rsi, regs.rdx);
				regs.rax = -EFAULT;
			}
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		5, [] (auto& machine) { // FSTAT
			auto regs = machine.registers();
			regs.rax = -ENOSYS;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		7, [] (Machine& machine) { // POLL
			auto regs = machine.registers();
			struct pollfd {
				int   fd;         /* file descriptor */
				short events;     /* requested events */
				short revents;    /* returned events */
			};
			const size_t bytes = sizeof(pollfd) * regs.rsi;
			auto* fds = machine.rw_memory_at<struct pollfd>(regs.rdi, bytes);
			for (size_t i = 0; i < regs.rsi; i++) {
				// stdout/stderr
				if (fds[i].fd == 0 || fds[i].fd == 2)
					fds[i].revents = fds[i].events;
				else
					fds[i].revents = 0;
			}
			regs.rax = 0;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		9, [] (auto& machine) { // MMAP
			auto regs = machine.registers();
			//regs.rax = ~(uint64_t) 0; /* MAP_FAILED */
			regs.rsi &= ~0xFFF;
			if (regs.rdi == 0xC000000000LL) {
				regs.rax = regs.rdi;
			}
			else {
				auto& mm = machine.mmap();
				if (mm < machine.heap_address()) mm = machine.heap_address();
				regs.rax = mm;
				// XXX: MAP_ANONYMOUS -->
				//memset(machine.rw_memory_at(regs.rax, regs.rsi), 0, regs.rsi);
				mm += regs.rsi;
			}
			PRINTMMAP("mmap(0x%llX, %llu) = 0x%llX\n",
				regs.rdi, regs.rsi, regs.rax);
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		10, [] (auto& machine) { // MPROTECT
			/* SYS mprotect */
			auto regs = machine.registers();
			PRINTMMAP("mprotect(0x%llX, %llu, 0x%llX)\n",
				regs.rdi, regs.rsi, regs.rdx);
			regs.rax = 0;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		11, [] (auto& machine) { // MUNMAP
			auto regs = machine.registers();
			PRINTMMAP("munmap(0x%llX, %llu)\n", regs.rdi, regs.rsi);
			regs.rax = 0;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		12, [] (auto& machine) { // BRK
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
	Machine::install_syscall_handler(
		13, [] (auto& machine) {
			/* SYS sigaction */
			auto regs = machine.registers();
			regs.rax = 0;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		14, [] (auto& machine) {
			/* SYS sigprocmask */
			auto regs = machine.registers();
			regs.rax = 0xfffffffffffff001;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		131, [] (auto& machine) {
			/* SYS sigaltstack */
			auto regs = machine.registers();
			regs.rax = 0xfffffffffffff001;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		16, [] (auto& machine) { // IOCTL
			/* SYS ioctl */
			auto regs = machine.registers();
			SYSPRINT("ioctl(0x%llX)\n", regs.rdi);
			regs.rax = 0;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		20, [] (auto& machine) { // WRITEV
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
					static constexpr char gw[] = ">>> Guest says: ";
					const struct iovec vec[] = {
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
	Machine::install_syscall_handler(
		21, [] (auto& machine) { // ACCESS
			auto regs = machine.registers();
			SYSPRINT("SYSCALL access 0x%llX 0x%llX\n", regs.rdi, regs.rsi);
			regs.rax = -1;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		28, [] (auto& machine) { // MADVISE
			auto regs = machine.registers();
			regs.rax = 0;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		35, [] (auto& machine) { // nanosleep
			auto regs = machine.registers();
			regs.rax = 0;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		39, [] (auto& machine) { // GETPID
			auto regs = machine.registers();
			regs.rax = 0;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		60, [] (auto& machine) { // EXIT
			auto regs = machine.registers();
#ifdef ENABLE_GUEST_VERBOSE
			printf("Machine exited with return value 0x%llX\n", regs.rdi);
#endif
			machine.stop();
		});
	Machine::install_syscall_handler(
		63, [] (tinykvm::Machine& machine) { // UTSNAME
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
			fprintf(stderr, "SYSCALL utsname failed on 0x%llX\n", regs.rdi);
			regs.rax = -EFAULT;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		72, [] (auto& machine) { // FCNTL
			auto regs = machine.registers();
			regs.rax = -ENOSYS;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		96, [] (auto& machine) { // gettimeofday
			auto regs = machine.registers();
			auto tv = (struct timeval *)machine.rw_memory_at(regs.rdi, sizeof(struct timeval));
			regs.rax = gettimeofday(tv, nullptr);
			if (regs.rax < 0) regs.rax = -errno;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		102, [] (auto& machine) { // GETUID
			auto regs = machine.registers();
			regs.rax = 0;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		158, [] (auto& machine) {
			auto regs = machine.registers();
			constexpr long ARCH_SET_GS = 0x1001;
			constexpr long ARCH_SET_FS = 0x1002;
			constexpr long ARCH_GET_FS = 0x1003;
			constexpr long ARCH_GET_GS = 0x1004;
			SYSPRINT("SYSCALL ARCH_PRCTL opt=0x%llX\n", regs.rdi);
			regs.rax = -22; // EINVAL
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		231, [] (auto& machine) {
			/* SYS exit_group */
			auto regs = machine.registers();
#ifdef ENABLE_GUEST_VERBOSE
			printf("Machine exits: _exit(%lld)\n", regs.rdi);
#endif
			machine.stop();
		});
	Machine::install_syscall_handler(
		302, [] (auto& machine) { // prlimit64
			auto regs = machine.registers();
			regs.rax = -ENOSYS;
			machine.set_registers(regs);
		});
	// Threads: clone, futex, block/tkill etc.
	Machine::setup_multithreading();
}
