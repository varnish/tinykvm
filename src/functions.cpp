#include <tinykvm/machine.hpp>
#include <cstring>
#include <sys/random.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/utsname.h>
//#define VERBOSE_GUEST_EXITS
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
static constexpr uint64_t PageMask = vMemory::PageSize()-1;

void setup_kvm_system_calls()
{
	Machine::install_unhandled_syscall_handler(
		[] (auto& cpu, unsigned scall) {
			SYSPRINT("Unhandled system call: %u\n", scall);
			(void) scall;
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		0, [] (auto& cpu) { // READ
			auto& regs = cpu.registers();
			SYSPRINT("READ to fd=%lld, data=0x%llX, size=%llu\n",
				regs.rdi, regs.rsi, regs.rdx);
			//auto data = machine.rw_memory_at(regs.rsi, regs.rdx);
			//regs.rax = regs.rdx;
			regs.rax = -ENOSYS;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		1, [] (auto& cpu) { // WRITE
			auto& regs = cpu.registers();
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
				cpu.machine().copy_from_guest(buffer, regs.rsi, bytes);
				cpu.machine().print(buffer, bytes);
				regs.rax = bytes;
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		5, [] (auto& cpu) { // FSTAT
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		7, [] (auto& cpu) { // POLL
			auto& regs = cpu.registers();
			struct pollfd {
				int   fd;         /* file descriptor */
				short events;     /* requested events */
				short revents;    /* returned events */
			};
			const size_t bytes = sizeof(pollfd) * regs.rsi;
			auto* fds = cpu.machine().template rw_memory_at<struct pollfd>(regs.rdi, bytes);
			for (size_t i = 0; i < regs.rsi; i++) {
				// stdout/stderr
				if (fds[i].fd == 1 || fds[i].fd == 2)
					fds[i].revents = fds[i].events;
				else
					fds[i].revents = 0;
			}
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		9, [] (auto& cpu) { // MMAP
			auto& regs = cpu.registers();
			if (UNLIKELY(regs.rdi % vMemory::PageSize() != 0 || regs.rsi == 0)) {
				regs.rax = ~0LL; /* MAP_FAILED */
			} else {
				// Round up to nearest power-of-two
				regs.rsi = (regs.rsi + PageMask) & ~PageMask;
				if (regs.rdi == 0xC000000000LL) {
					regs.rax = regs.rdi;
				}
				else {
					auto& mm = cpu.machine().mmap();
					regs.rax = mm;
					// XXX: MAP_ANONYMOUS -->
					//memset(machine.rw_memory_at(regs.rax, regs.rsi), 0, regs.rsi);
					mm += regs.rsi;
				}
			}
			PRINTMMAP("mmap(0x%llX, %llu, prot=%llX, flags=%llX) = 0x%llX\n",
				regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		10, [] (auto& cpu) { // MPROTECT
			/* SYS mprotect */
			auto& regs = cpu.registers();
			PRINTMMAP("mprotect(0x%llX, %llu, 0x%llX)\n",
				regs.rdi, regs.rsi, regs.rdx);
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		11, [] (auto& cpu) { // MUNMAP
			auto& regs = cpu.registers();
			PRINTMMAP("munmap(0x%llX, %llu)\n", regs.rdi, regs.rsi);
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		12, [] (auto& cpu) { // BRK
			auto& regs = cpu.registers();
			if (regs.rdi > cpu.machine().heap_address() + Machine::BRK_MAX) {
				regs.rax = cpu.machine().heap_address() + Machine::BRK_MAX;
			} else if (regs.rdi < cpu.machine().heap_address()) {
				regs.rax = cpu.machine().heap_address();
			} else {
				regs.rax = regs.rdi;
			}
			SYSPRINT("brk(0x%llX) = 0x%llX\n", regs.rdi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		13, [] (auto& cpu) {
			/* SYS rt_sigaction */
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("rt_sigaction(signum=%x, act=0x%llX, oldact=0x%llx) = 0x%llX\n",
				(int) regs.rdi, regs.rsi, regs.rdx, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		14, [] (auto& cpu) {
			/* SYS rt_sigprocmask */
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("rt_sigprocmask(how=%x, set=0x%llX, oldset=0x%llx, size=%llu) = 0x%llX\n",
					 (int)regs.rdi, regs.rsi, regs.rdx, regs.rcx, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		131, [] (auto& cpu) {
			/* SYS sigaltstack */
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("sigaltstack(ss=0x%llX, old_ss=0x%llx) = 0x%llX\n",
				regs.rdi, regs.rsi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		16, [] (auto& cpu) { // IOCTL
			auto& regs = cpu.registers();
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
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		20, [] (auto& cpu) { // WRITEV
			/* SYS writev */
			auto& regs = cpu.registers();
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
				ssize_t written = 0;
				for (size_t i = 0; i < count; i++) {
					g_iovec vec;
					cpu.machine().copy_from_guest(&vec, regs.rsi + i * sizeof(g_iovec), sizeof(g_iovec));
					// Ignore empty writes? Max 4k writes.
					if (vec.iov_len == 0)
						continue;
					if (vec.iov_len > 4096) {
						written = -ENOMEM;
						continue;
					}
					const size_t bytes = vec.iov_len;
					char buffer[bytes];
					cpu.machine().copy_from_guest(buffer, vec.iov_base, bytes);
					cpu.machine().print(buffer, bytes);
					written += bytes;
				}
				regs.rax = written;
			} else {
				regs.rax = -EPERM;
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		21, [] (auto& cpu) { // ACCESS
			auto& regs = cpu.registers();
			SYSPRINT("SYSCALL access 0x%llX 0x%llX\n", regs.rdi, regs.rsi);
			regs.rax = -1;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		25, [] (auto& cpu) { // MREMAP
			auto& regs = cpu.registers();
			auto& mm = cpu.machine().mmap();
			uint64_t old_addr = regs.rdi & ~(uint64_t)0xFFF;
			uint64_t old_len = regs.rsi & ~(uint64_t)0xFFF;
			uint64_t new_len = regs.rdx & ~(uint64_t)0xFFF;
			if (old_addr + old_len == mm) {
				mm = old_addr + new_len;
				regs.rax = old_addr;
			} else {
				regs.rax = ~(uint64_t) 0; /* MAP_FAILED */
			}
			PRINTMMAP("mremap(0x%llX, %llu, %llu) = 0x%llX\n",
				regs.rdi, regs.rsi, regs.rdx, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		28, [] (auto& cpu) { // MADVISE
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		35, [] (auto& cpu) { // nanosleep
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		39, [] (auto& cpu) { // GETPID
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		60, [] (auto& cpu) { // EXIT
#ifdef VERBOSE_GUEST_EXITS
			auto& regs = cpu.registers();
			printf("Machine exited with return value 0x%llX\n", regs.rdi);
#endif
			cpu.stop();
		});
	Machine::install_syscall_handler(
		63, [] (auto& cpu) { // UTSNAME
			auto& regs = cpu.registers();
			if (cpu.machine().memory_safe_at(regs.rdi, sizeof(struct utsname)))
			{
				struct utsname uts {};
				strcpy(uts.sysname, "Linux");
				strcpy(uts.release, "3.2.0");
				cpu.machine().copy_to_guest(regs.rdi, &uts, sizeof(uts));
				regs.rax = 0;
			} else {
				fprintf(stderr,
					"SYSCALL utsname failed on 0x%llX\n", regs.rdi);
				regs.rax = -EFAULT;
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		72, [] (auto& cpu) { // FCNTL
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		89, [] (auto& cpu) { // READLINK
			auto& regs = cpu.registers();
			regs.rax = -ENOENT;
			SYSPRINT("READLINK 0x%llX, bufd=0x%llX, size=%llu = %lld\n",
				regs.rdi, regs.rsi, regs.rdx, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		96, [] (auto& cpu) { // gettimeofday
			auto& regs = cpu.registers();
			struct timeval tv;
			regs.rax = gettimeofday(&tv, nullptr);
			cpu.machine().copy_to_guest(regs.rdi, &tv, sizeof(tv));
			if (regs.rax < 0) regs.rax = -errno;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		102, [] (auto& cpu) { // GETUID
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		158, [] (auto& cpu) {
			auto& regs = cpu.registers();
			[[maybe_unused]] static constexpr long ARCH_SET_GS = 0x1001;
			[[maybe_unused]] static constexpr long ARCH_SET_FS = 0x1002;
			[[maybe_unused]] static constexpr long ARCH_GET_FS = 0x1003;
			[[maybe_unused]] static constexpr long ARCH_GET_GS = 0x1004;
			SYSPRINT("SYSCALL ARCH_PRCTL opt=0x%llX\n", regs.rdi);
			regs.rax = -22; // EINVAL
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		200, [] (auto&) { // tkill
			/* Normally, we would invoke signal w/altstack here */
			throw MachineException("TKILL system call received");
		});
	Machine::install_syscall_handler(
		201, [] (auto& cpu) { // time
			auto& regs = cpu.registers();
			regs.rax = time(NULL);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		228, [] (auto& cpu) { // clock_gettime
			auto& regs = cpu.registers();
			struct timespec ts;
			regs.rax = clock_gettime(CLOCK_MONOTONIC, &ts);
			cpu.machine().copy_to_guest(regs.rsi, &ts, sizeof(ts));
			if (regs.rax < 0)
				regs.rax = -errno;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		231, [] (auto& cpu) {
			/* SYS exit_group */
#ifdef VERBOSE_GUEST_EXITS
			auto& regs = cpu.registers();
			printf("Machine exits: _exit(%lld)\n", regs.rdi);
#endif
			cpu.stop();
		});
	Machine::install_syscall_handler(
		273, [] (auto& cpu) {
			/* SYS set_robust_list */
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		302, [] (auto& cpu) { // prlimit64
			auto& regs = cpu.registers();
			struct
			{
				uint64_t cur = 0;
				uint64_t max = 0;
			} lim;
			const auto oldptr = regs.rdx;

			SYSPRINT("prlimit64(res=%lld old=0x%llX) = 0\n", regs.rsi, oldptr);
			switch (regs.rsi) {
			case 0: // RLIMIT_CPU
				regs.rax = -ENOSYS;
				break;
			case 3: // RLIMIT_STACK
				/* TODO: We currently do not accept new limits. */
				if (oldptr != 0x0) {
					lim.cur = cpu.machine().stack_address() - 0x200000;
					lim.max = cpu.machine().stack_address();
					cpu.machine().copy_to_guest(oldptr, &lim, sizeof(lim));
				}
				regs.rax = 0;
				break;
			default:
				regs.rax = -ENOSYS;
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		318, [] (auto& cpu) { // getrandom
			auto& regs = cpu.registers();
			const uint64_t g_buf = regs.rdi;
			const uint32_t bytes = regs.rsi;
			const int      flags = regs.rdx;
			(void) flags;

			/* Max 64kb randomness. */
			if (bytes <= 0x10000) {
				char buffer[bytes];
				ssize_t actual = getrandom(buffer, bytes, 0);
				if (actual > 0)
					cpu.machine().copy_to_guest(g_buf, buffer, actual);
				regs.rax = actual;
			} else {
				regs.rax = -1;
			}
			SYSPRINT("getrandom(buf=0x%lX bytes=%u flags=%X) = %lld\n",
					 g_buf, bytes, flags, regs.rax);
			cpu.set_registers(regs);
		});
	// Threads: clone, futex, block/tkill etc.
	Machine::setup_multithreading();
}
