#include <tinykvm/machine.hpp>
#include <tinykvm/threads.hpp>
#include <cstring>
#include <signal.h>
#include <sys/mman.h>
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
			if (bytes > 8192) {
				/* Ignore too big a write */
				regs.rax = -1;
			} else if (fd != 1 && fd != 2) {
				/* Ignore writes outside of stdout and stderr */
				regs.rax = -1;
			}
			else {
				char buffer[8192];
				cpu.machine().copy_from_guest(buffer, regs.rsi, bytes);
				cpu.machine().print(buffer, bytes);
				regs.rax = bytes;
			}
			SYSPRINT("write(%d, 0x%llX, %zu) = %lld\n",
					 fd, regs.rsi, bytes, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		3, [] (auto& cpu) {
			/* SYS close */
			auto& regs = cpu.registers();
			const int fd = regs.rdi;
			(void)fd;
			regs.rax = 0;
			SYSPRINT("close(%d) = %lld\n",
					 fd, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		5, [] (auto& cpu) { // FSTAT
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			SYSPRINT("fstat(...) = %lld\n",
					 regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		262, [] (auto& cpu) { // NEW_FSTATAT
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			SYSPRINT("new_fstatat(...) = %lld\n",
					 regs.rax);
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
			SYSPRINT("poll(0x%llX, %llu) = %lld\n",
					 regs.rsi, regs.rdi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		9, [] (auto& cpu) { // MMAP
			auto& regs = cpu.registers();
			const uint64_t address = regs.rdi & ~PageMask;
			const uint64_t length = (regs.rsi + PageMask) & ~PageMask;
			const auto flags = regs.r10;
			if (UNLIKELY(address % vMemory::PageSize() != 0 || length == 0)) {
				// Size not matching a 4K page size
				regs.rax = ~0LL; /* MAP_FAILED */
			} else if (UNLIKELY(int(regs.r8) >= 0)) {
				// mmap to file fd (*NOT* supported)
				regs.rax = ~0LL; /* MAP_FAILED */
			} else if ((flags & 0x4) != 0) {
				// Executable mappings are supported if there is an execute-range in vMemory
				auto& memory = cpu.machine().main_memory();
				if (memory.vmem_exec_begin != 0x0) {
					regs.rax = memory.vmem_exec_begin;
					memory.vmem_exec_begin += length;
				} else {
					regs.rax = ~0LL; /* MAP_FAILED */
				}
			} else if (address != 0x0 && !cpu.machine().relocate_fixed_mmap()) {
				regs.rax = address;
			} else if (address != 0x0 && address >= cpu.machine().heap_address() && address < cpu.machine().mmap_start()) {
				// Existing range already mmap'ed
				regs.rax = address;
			} else {
				if constexpr (true) {
					auto range = cpu.machine().mmap_cache().find(length);
					// Not found in cache, allocate new range
					if (range.empty()) {
						regs.rax = cpu.machine().mmap_allocate(length);
					}
					else
					{
						//PRINTMMAP("Found existing range: 0x%lX -> 0x%lX\n",
						//	range.addr, range.addr + range.size);
						regs.rax = range.addr;
					}
				} else {
					regs.rax = cpu.machine().mmap_allocate(length);
				}
			}
			/* If MAP_ANON is set, the memory must be zeroed. memzero() will only
			   zero the pages that are dirty, preventing RSS from exploding. */
			if ((flags & MAP_ANON) != 0 && regs.rax != ~0ULL) {
				cpu.machine().memzero(regs.rax, length);
			}
			PRINTMMAP("mmap(0x%llX, %llu, prot=%llX, flags=%llX) = 0x%llX\n",
				address, length, regs.rdx, regs.r10, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		10, [] (auto& cpu) { // MPROTECT
			/* SYS mprotect */
			auto& regs = cpu.registers();
			PRINTMMAP("mprotect(0x%llX, %llu, 0x%llX)\n",
				regs.rdi, regs.rsi, regs.rdx);
			// mprotect(...) is unsupported, however it would be nice if we could
			// support it on the identity-mapped main VM, during startup.
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		11, [] (vCPU& cpu) { // MUNMAP
			auto& regs = cpu.registers();
			// We don't support MMAP fully, but we can try to relax the mapping.
			const uint64_t old_base = regs.rdi;
			const uint64_t old_size = regs.rsi;
			[[maybe_unused]] bool relaxed =
				cpu.machine().mmap_unmap(old_base, old_size);
			PRINTMMAP("munmap(0x%lX, %lu, relaxed=%d)\n", old_base, old_size, relaxed);
			// Because we do not support MMAP fully, we will just return 0 here.
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
			const int sig = regs.rdi;

			/* Silently ignore signal 0 */
			if (sig == 0) {
				regs.rax = 0;
				cpu.set_registers(regs);
				SYSPRINT("rt_sigaction(signum=%x, act=0x%llX, oldact=0x%llx) = 0x%llX (ignored)\n",
					sig, regs.rsi, regs.rdx, regs.rax);
				return;
			}

			auto& sigact = cpu.machine().sigaction(sig);

			struct kernel_sigaction {
				uint64_t handler;
				uint64_t flags;
				uint64_t mask;
			} sa {};
			/* Old action */
			if (regs.rdx != 0x0) {
				sa.handler = sigact.handler & ~0xFLL;
				sa.flags   = (sigact.altstack ? SA_ONSTACK : 0x0);
				sa.mask    = sigact.mask;
				cpu.machine().copy_to_guest(regs.rdx, &sa, sizeof(sa));
			}
			/* New action */
			if (regs.rsi != 0x0) {
				cpu.machine().copy_from_guest(&sa, regs.rsi, sizeof(sa));
				SYSPRINT("rt_sigaction(action handler=0x%lX  flags=0x%lX  mask=0x%lX)\n",
					sa.handler, sa.flags, sa.mask);
				sigact.handler  = sa.handler;
				sigact.altstack = (sa.flags & SA_ONSTACK) != 0;
				sigact.mask     = sa.mask;
			}
			regs.rax = 0;
			SYSPRINT("rt_sigaction(signum=%x, act=0x%llX, oldact=0x%llx) = 0x%llX\n",
				sig, regs.rsi, regs.rdx, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		14, [] (auto& cpu) {
			/* SYS rt_sigprocmask */
			auto& regs = cpu.registers();
			const int how = regs.rdi;
			const uint64_t g_set = regs.rsi;
			const uint64_t g_oldset = regs.rdx;
			const unsigned size = regs.r10;
			(void)how;
			(void)g_set;
			(void)size;

			struct kernel_sigset_t {
				unsigned long sig[1];
			};

			if (g_oldset != 0x0) {
				kernel_sigset_t oldset {};
				__builtin_memset(&oldset, 0xFF, sizeof(oldset));
				cpu.machine().copy_to_guest(g_oldset, &oldset, sizeof(oldset));
			}

			regs.rax = 0;
			SYSPRINT("rt_sigprocmask(how=%x, set=0x%lX, oldset=0x%lx, size=%u) = 0x%llX\n",
					 how, g_set, g_oldset, size, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		131, [] (auto& cpu) {
			/* SYS sigaltstack */
			auto& regs = cpu.registers();

			if (regs.rdi != 0x0) {
				auto& ss = cpu.machine().signals().per_thread(cpu.machine().threads().gettid()).stack;
				cpu.machine().copy_from_guest(&ss, regs.rdi, sizeof(ss));

				SYSPRINT("sigaltstack(altstack SP=0x%lX  flags=0x%X  size=0x%lX)\n",
					ss.ss_sp, ss.ss_flags, ss.ss_size);
			}

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
			const int  fd    = regs.rdi;
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
					if (vec.iov_len > 8192) {
						written = -ENOMEM;
						break;
					}
					const size_t bytes = vec.iov_len;
					char buffer[8192];
					cpu.machine().copy_from_guest(buffer, vec.iov_base, bytes);
					cpu.machine().print(buffer, bytes);
					written += bytes;
				}
				regs.rax = written;
			} else {
				regs.rax = -EPERM;
			}
			SYSPRINT("writev(%d) = %lld\n",
					 fd, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		21, [] (auto& cpu) { // ACCESS
			auto& regs = cpu.registers();
			regs.rax = -EPERM;
			SYSPRINT("access(0x%llX 0x%llX) = %lld\n",
				regs.rdi, regs.rsi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		293, [] (auto& cpu) { // PIPE2
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("pipe(0x%llX, 0x%X) = %lld\n",
				regs.rdi, int(regs.rsi), regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		25, [] (auto& cpu) { // MREMAP
			auto& regs = cpu.registers();
			auto& mm = cpu.machine().mmap();
			uint64_t old_addr = regs.rdi & ~(uint64_t)0xFFF;
			uint64_t old_len = (regs.rsi + 0xFFF) & ~(uint64_t)0xFFF;
			uint64_t new_len = (regs.rdx + 0xFFF) & ~(uint64_t)0xFFF;
			unsigned flags = regs.rcx;

			if (old_addr + old_len == mm) {
				mm = old_addr + new_len;
				regs.rax = old_addr;
			} else if (flags & MREMAP_FIXED) {
				// We don't support MREMAP_FIXED
				regs.rax = ~0LL; /* MAP_FAILED */
			} else if (flags & MREMAP_MAYMOVE) {
				uint64_t new_addr = cpu.machine().mmap_allocate(new_len);
				regs.rax = new_addr;
				// Copy the old data to the new location
				cpu.machine().foreach_memory(old_addr, old_len,
					[&cpu, &new_addr] (std::string_view buffer)
					{
						cpu.machine().copy_to_guest(new_addr, buffer.data(), buffer.size());
						new_addr += buffer.size();
					});
				// Unmap the old range
				cpu.machine().mmap_unmap(old_addr, old_len);
			} else {
				// We don't support other flags
				regs.rax = ~0LL; /* MAP_FAILED */
			}
			PRINTMMAP("mremap(0x%llX, %llu, %llu, flags=0x%X) = 0x%llX\n",
				regs.rdi, regs.rsi, regs.rdx, flags, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		28, [] (auto& cpu) { // MADVISE
			auto& regs = cpu.registers();
			regs.rax = 0;
			PRINTMMAP("madvise(0x%llX, %llu, 0x%llx) = %lld\n",
				regs.rdi, regs.rsi, regs.rdx, regs.rax);
			if (regs.rdx == MADV_DONTNEED) {
				// MADV_DONTNEED
				/// XXX: TODO: Memdiscard the pages
				//cpu.machine().memzero(regs.rdi, regs.rsi);
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		35, [] (auto& cpu) { // nanosleep
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("nanosleep(...) = %lld\n",
				regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		39, [] (auto& cpu) { // GETPID
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("getpid() = %lld\n", regs.rax);
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
				SYSPRINT("SYSCALL utsname failed on 0x%llX\n", regs.rdi);
				regs.rax = -EFAULT;
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		72, [] (auto& cpu) { // FCNTL
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("fcntl(...) = %lld\n",
				regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		89, [] (auto& cpu) { // READLINK
			auto& regs = cpu.registers();
			regs.rax = -ENOENT;
			SYSPRINT("readlink(0x%llX, bufd=0x%llX, size=%llu) = %lld\n",
				regs.rdi, regs.rsi, regs.rdx, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		96, [] (auto& cpu) { // gettimeofday
			auto& regs = cpu.registers();
			struct timeval tv;
			regs.rax = gettimeofday(&tv, nullptr);
			if (regs.rax < 0) {
				regs.rax = -errno;
			} else {
				cpu.machine().copy_to_guest(regs.rdi, &tv, sizeof(tv));
			}
			SYSPRINT("gettimeofday(buf=0x%llX) = %lld\n",
				regs.rdi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		102, [] (auto& cpu) { // GETUID
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler( // sched_getparam
		143, [] (auto& cpu) {
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("sched_getparam(...) = %lld\n", regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler( // sched_getscheduler
		145, [] (auto& cpu) {
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("sched_getscheduler(...) = %lld\n", regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		157, [] (auto& cpu) {
			/* SYS prctl */
			auto& regs = cpu.registers();
			const int option = regs.rdi;
			(void)option;

			regs.rax = 0;
			SYSPRINT("prctl(opt=%d) = %lld\n", option, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		158, [] (auto& cpu) {
			/* SYS arch_prctl */
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
			SYSPRINT("time(NULL) = %lld\n", regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		204, [] (auto& cpu) { // sched_getaffinity
			/* SYS sched_getaffinity */
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("sched_getaffinity() = %lld\n", regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		228, [] (auto& cpu) { // clock_gettime
			auto& regs = cpu.registers();
			struct timespec ts;
			regs.rax = clock_gettime(CLOCK_MONOTONIC, &ts);
			if (regs.rax < 0)
				regs.rax = -errno;
			else
				cpu.machine().copy_to_guest(regs.rsi, &ts, sizeof(ts));
			SYSPRINT("clock_gettime(clk=%lld, buf=0x%llX) = %lld\n",
				regs.rdi, regs.rsi, regs.rax);
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
			SYSPRINT("set_robust_list(...) = %lld\n", regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		290, [] (auto& cpu) {
			/* SYS eventfd2 */
			auto& regs = cpu.registers();
			regs.rax = 42;
			SYSPRINT("eventfd2(...) = %lld\n", regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		291, [] (auto& cpu) {
			/* SYS epoll_create1 */
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("epoll_create1(...) = %lld\n", regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		230, [] (auto& cpu) {
			/* SYS nanosleep */
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("nanosleep(...) = %lld\n", regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		233, [] (auto& cpu) {
			/* SYS epoll_ctl */
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("epoll_ctl(...) = %lld\n", regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		302, [] (auto& cpu) { // prlimit64
			auto& regs = cpu.registers();
			struct rlimit64 {
				__u64 cur = 0;
				__u64 max = 0;
			} __attribute__((packed));
			const auto newptr = regs.rcx;
			const auto oldptr = regs.rdx;

			switch (regs.rsi) {
			case 0: // RLIMIT_CPU
				regs.rax = -ENOSYS;
				break;
			case 3: // RLIMIT_STACK
				/* TODO: We currently do not accept new limits. */
				if (oldptr != 0x0) {
					struct rlimit64 lim {};
					lim.cur = cpu.machine().stack_address() - (4UL << 20);
					lim.max = cpu.machine().stack_address();
					cpu.machine().copy_to_guest(oldptr, &lim, sizeof(lim));
				} else if (newptr != 0x0) {
					//struct rlimit64 lim {};
					//cpu.machine().copy_from_guest(&lim, newptr, sizeof(lim));
				}
				regs.rax = 0;
				break;
			default:
				regs.rax = -ENOSYS;
			}
			SYSPRINT("prlimit64(res=%lld new=0x%llX old=0x%llX) = %lld\n",
				regs.rsi, newptr, oldptr, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		318, [] (auto& cpu) { // getrandom
			auto& regs = cpu.registers();
			const uint64_t g_buf = regs.rdi;
			const uint32_t bytes = regs.rsi;
			const int      flags = regs.rdx;
			(void) flags;

			/* Max 256b randomness. */
			if (bytes <= 256) {
				char buffer[256];
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
	Machine::install_syscall_handler(
		334, [] (auto& cpu) { // faccessat
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			SYSPRINT("faccessat(...) = %lld\n",
					 regs.rax);
			cpu.set_registers(regs);
		});

	// Threads: clone, futex, block/tkill etc.
	Machine::setup_multithreading();
}
