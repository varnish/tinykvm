#include <tinykvm/machine.hpp>
#include <cstring>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
//#define VERBOSE_GUEST_EXITS
//#define VERBOSE_MMAP
//#define VERBOSE_SYSCALLS
static const uint64_t BRK_MAX = 0x100000;

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
			(void) scall;
			auto regs = machine.registers();
			regs.rax = -ENOSYS;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		0, [] (auto& machine) { // READ
			auto regs = machine.registers();
			SYSPRINT("READ to fd=%lld, data=0x%llX, size=%llu\n",
				regs.rdi, regs.rsi, regs.rdx);
			//auto data = machine.rw_memory_at(regs.rsi, regs.rdx);
			//regs.rax = regs.rdx;
			regs.rax = -ENOSYS;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		1, [] (auto& machine) { // WRITE
			auto regs = machine.registers();
			const int    fd = regs.rdi;
			const size_t bytes = regs.rdx;
			if (bytes > 4096) {
				/* Ignore too big a write */
				regs.rax = -1;
			} else if (fd != 1 && fd != 2) {
				/* Ignore writes outside of stdout and stderr */
				regs.rax = -1;
			}
			else {
				char buffer[bytes];
				machine.copy_from_guest(buffer, regs.rsi, bytes);
				machine.print(buffer, bytes);
				regs.rax = bytes;
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
				if (fds[i].fd == 1 || fds[i].fd == 2)
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
				const uint64_t mmap_start = machine.heap_address() + BRK_MAX;
				if (mm < mmap_start)
					mm = mmap_start;
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
			if (regs.rdi > machine.heap_address() + BRK_MAX) {
				regs.rax = machine.heap_address() + BRK_MAX;
			} else if (regs.rdi < machine.heap_address()) {
				regs.rax = machine.heap_address();
			} else {
				regs.rax = regs.rdi;
			}
			SYSPRINT("brk(0x%llX) = 0x%llX\n", regs.rdi, regs.rax);
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		13, [] (auto& machine) {
			/* SYS sigaction */
			auto regs = machine.registers();
			regs.rax = 0;
			SYSPRINT("sigaction(signum=%x, act=0x%llX, oldact=0x%llx) = 0x%llX\n",
				(int) regs.rdi, regs.rsi, regs.rdx, regs.rax);
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		14, [] (auto& machine) {
			/* SYS sigprocmask */
			auto regs = machine.registers();
			regs.rax = 0;
			SYSPRINT("sigprocmask(how=%x, set=0x%llX, oldset=0x%llx) = 0x%llX\n",
				(int) regs.rdi, regs.rsi, regs.rdx, regs.rax);
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		131, [] (auto& machine) {
			/* SYS sigaltstack */
			auto regs = machine.registers();
			regs.rax = 0xfffffffffffff001;
			SYSPRINT("sigaltstack(ss=0x%llX, old_ss=0x%llx) = 0x%llX\n",
				regs.rdi, regs.rsi, regs.rax);
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		16, [] (auto& machine) { // IOCTL
			auto regs = machine.registers();
			switch (regs.rsi) {
				case 0x5401: /* TCGETS */
					regs.rax = 0;
					break;
				case 0x5413: /* TIOCGWINSZ */
					regs.rax = 80;
					break;
				default:
					regs.rax = EINVAL;
			}
			SYSPRINT("ioctl(fd=0x%llX, req=0x%llx) = 0x%llX\n",
				regs.rdi, regs.rsi, regs.rax);
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
			const auto fd    = regs.rdi;
			const auto count = regs.rdx;

			if (count > 64) {
				/* Ignore too many entries */
				regs.rax = -1;
			}
			/* writev: Stdout, Stderr */
			else if (fd == 1 || fd == 2)
			{
				size_t written = 0;
				for (size_t i = 0; i < count; i++) {
					g_iovec vec;
					machine.copy_from_guest(&vec, regs.rsi + i * sizeof(g_iovec), sizeof(g_iovec));
					// Ignore empty writes? Max 4k writes.
					if (vec.iov_len == 0 || vec.iov_len > 4096)
						continue;
					const size_t bytes = vec.iov_len;
					char buffer[bytes];
					machine.copy_from_guest(buffer, vec.iov_base, bytes);
					machine.print(buffer, bytes);
					written += bytes;
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
		25, [] (auto& machine) { // MREMAP
			auto regs = machine.registers();
			const uint64_t mmap_start = machine.heap_address() + BRK_MAX;
			auto& mm = machine.mmap();
			uint64_t old_addr = regs.rdi & ~(uint64_t)0xFFF;
			uint64_t old_len = regs.rsi & ~(uint64_t)0xFFF;
			uint64_t new_len = regs.rdx & ~(uint64_t)0xFFF;
			if (old_addr + old_len == mm && mm >= mmap_start) {
				mm = old_addr + new_len;
				regs.rax = old_addr;
			} else {
				regs.rax = ~(uint64_t) 0; /* MAP_FAILED */
			}
			PRINTMMAP("mremap(0x%llX, %llu, %llu) = 0x%llX\n",
				regs.rdi, regs.rsi, regs.rdx, regs.rax);
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
#ifdef VERBOSE_GUEST_EXITS
			auto regs = machine.registers();
			printf("Machine exited with return value 0x%llX\n", regs.rdi);
#endif
			machine.stop();
		});
	Machine::install_syscall_handler(
		63, [] (tinykvm::Machine& machine) { // UTSNAME
			auto regs = machine.registers();
			if (machine.memory_safe_at(regs.rdi, sizeof(struct utsname)))
			{
				struct utsname uts {};
				strcpy(uts.sysname, "Linux");
				strcpy(uts.release, "3.2.0");
				machine.copy_to_guest(regs.rdi, &uts, sizeof(uts));
				regs.rax = 0;
			} else {
				fprintf(stderr,
					"SYSCALL utsname failed on 0x%llX\n", regs.rdi);
				regs.rax = -EFAULT;
			}
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		72, [] (auto& machine) { // FCNTL
			auto regs = machine.registers();
			regs.rax = -ENOSYS;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		89, [] (Machine& machine) { // READLINK
			auto regs = machine.registers();
			regs.rax = -ENOENT;
			SYSPRINT("READLINK 0x%llX, bufd=0x%llX, size=%llu = %lld\n",
				regs.rdi, regs.rsi, regs.rdx, regs.rax);
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		96, [] (auto& machine) { // gettimeofday
			auto regs = machine.registers();
			struct timeval tv;
			regs.rax = gettimeofday(&tv, nullptr);
			machine.copy_to_guest(regs.rdi, &tv, sizeof(tv));
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
			[[maybe_unused]] static constexpr long ARCH_SET_GS = 0x1001;
			[[maybe_unused]] static constexpr long ARCH_SET_FS = 0x1002;
			[[maybe_unused]] static constexpr long ARCH_GET_FS = 0x1003;
			[[maybe_unused]] static constexpr long ARCH_GET_GS = 0x1004;
			SYSPRINT("SYSCALL ARCH_PRCTL opt=0x%llX\n", regs.rdi);
			regs.rax = -22; // EINVAL
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		231, [] (auto& machine) {
			/* SYS exit_group */
#ifdef VERBOSE_GUEST_EXITS
			auto regs = machine.registers();
			printf("Machine exits: _exit(%lld)\n", regs.rdi);
#endif
			machine.stop();
		});
	Machine::install_syscall_handler(
		273, [] (auto& machine) {
			/* SYS set_robust_list */
			auto regs = machine.registers();
			regs.rax = -ENOSYS;
			machine.set_registers(regs);
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
