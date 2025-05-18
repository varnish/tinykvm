#include "../machine.hpp"
#include "threads.hpp"
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <unistd.h>
// #define VERBOSE_GUEST_EXITS
#define SYSPRINT(fmt, ...) \
	if (UNLIKELY(cpu.machine().m_verbose_system_calls)) { \
		fprintf(stderr, fmt, __VA_ARGS__); \
		if (int(regs.rax) < 0) fprintf(stderr, "*** ERROR: %d %s\n", int(regs.rax), strerror(-int(regs.rax))); \
	}
#define PRINTMMAP(fmt, ...) \
	if (UNLIKELY(cpu.machine().m_verbose_mmap_syscalls)) fprintf(stderr, fmt, __VA_ARGS__);

namespace tinykvm {
static constexpr uint64_t PageMask = vMemory::PageSize() - 1;
static constexpr size_t MMAP_COLLISION_TRESHOLD = 512ULL << 20; // 512MB
struct GuestIOvec
{
	uint64_t iov_base;
	uint64_t iov_len;
};

void Machine::setup_linux_system_calls()
{
	Machine::install_unhandled_syscall_handler(
		[](vCPU& cpu, unsigned scall)
		{
			auto& regs = cpu.registers();
			(void)scall;
			regs.rax = -ENOSYS;
			SYSPRINT("Unhandled system call: %u\n", scall);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_read, [] (vCPU& cpu) { // READ
			auto& regs = cpu.registers();
			const int vfd = int(regs.rdi);
			int fd = cpu.machine().fds().translate(vfd);

			static constexpr size_t MAX_READ_BUFFERS = 128;
			tinykvm::Machine::WrBuffer buffers[MAX_READ_BUFFERS];

			/* Writable readv buffers */
			auto bufcount = cpu.machine().writable_buffers_from_range(
				MAX_READ_BUFFERS, buffers,
				regs.rsi, regs.rdx);

			ssize_t result = 0;
			if (bufcount == 1) {
				result = read(fd, buffers[0].ptr, buffers[0].len);
			} else {
				result = readv(fd, (struct iovec *)&buffers[0], bufcount);
			}
			if (UNLIKELY(result < 0)) {
				regs.rax = -errno;
			} else {
				regs.rax = result;
			}
			cpu.set_registers(regs);
			SYSPRINT("read(fd=%d (%d), data=0x%llX, size=%llu) = %lld\n",
				fd, vfd, regs.rsi, regs.rdx, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_write, [] (vCPU& cpu) { // WRITE
			auto& regs = cpu.registers();
			const int    vfd = regs.rdi;
			const size_t bytes = regs.rdx;
			SYSPRINT("write(vfd=%d, data=0x%llX, size=%zu)\n",
				vfd, regs.rsi, bytes);
			// TODO: Make proper tenant setting for write limits?
			if (vfd == 1 || vfd == 2) {
				if (UNLIKELY(bytes > 1024*64)) {
					regs.rax = -1;
					cpu.set_registers(regs);
					SYSPRINT("write(fd=%d (%d), data=0x%llX, size=%zu) = %lld\n",
						vfd, vfd, regs.rsi, bytes, regs.rax);
					return;
				}
			}
			else if (UNLIKELY(bytes > (64UL << 20))) {
				regs.rax = -1;
				cpu.set_registers(regs);
				SYSPRINT("write(fd=%d (%d), data=0x%llX, size=%zu) = %lld\n",
					vfd, vfd, regs.rsi, bytes, regs.rax);
				return;
			}
			if (vfd != 1 && vfd != 2) {
				/* Use gather-buffers and writev */
				static constexpr size_t WRITEV_BUFFERS = 64;
				tinykvm::Machine::Buffer buffers[WRITEV_BUFFERS];
				const auto bufcount =
					cpu.machine().gather_buffers_from_range(WRITEV_BUFFERS, buffers, regs.rsi, bytes);

				/* Complain about writes outside of existing FDs */
				const int fd = cpu.machine().fds().translate_writable_vfd(regs.rdi);
				if (bufcount > 1) {
					regs.rax = writev(fd, (const struct iovec *)buffers, bufcount);
				} else {
					regs.rax = write(fd, buffers[0].ptr, buffers[0].len);
				}
				SYSPRINT("write(fd=%d (%d), data=0x%llX, size=%zu) = %lld\n",
					vfd, fd, regs.rsi, bytes, regs.rax);
			}
			else {
				const auto g_buf = regs.rsi;
				cpu.machine().foreach_memory(g_buf, bytes,
					[&cpu] (std::string_view buffer)
					{
						cpu.machine().print(buffer.begin(), buffer.size());
					});
				regs.rax = bytes;
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_close, [] (vCPU& cpu) { // CLOSE
			auto& regs = cpu.registers();
			const int vfd = regs.rdi;
			int real_fd = -1;
			if (UNLIKELY(vfd >= 0 && vfd < 3)) {
				/* Silently ignore close on stdin/stdout/stderr */
				real_fd = vfd;
				regs.rax = 0;
			} else {
				auto opt_entry = cpu.machine().fds().entry_for_vfd(vfd);
				if (opt_entry.has_value()) {
					auto& entry = *opt_entry;
					real_fd = entry->real_fd;
					if (!entry->is_forked) {
						const int real_fd = entry->real_fd;
						if (cpu.machine().fds().free(vfd))
							return;
						const int res = ::close(real_fd);
						if (UNLIKELY(res < 0))
							regs.rax = -errno;
						else
							regs.rax = 0;
					} else {
						// Closing an fd on a fork shouldn't actually close the real fd
						// but we will pretend it does.
						regs.rax = 0;
					}
				} else {
					regs.rax = -EBADF;
				}
			}
			cpu.set_registers(regs);
			SYSPRINT("CLOSE(fd=%d (%d)) = %lld\n",
				vfd, real_fd, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_stat, [] (vCPU& cpu) { // STAT
			auto& regs = cpu.registers();
			const auto vpath = regs.rdi;

			std::string path = cpu.machine().memcstring(vpath, PATH_MAX);
			if (UNLIKELY(!cpu.machine().fds().is_readable_path(path))) {
				regs.rax = -EACCES;
				cpu.set_registers(regs);
				SYSPRINT("STAT to path=%s, data=0x%llX = %lld\n",
					path.c_str(), regs.rsi, regs.rax);
				return;
			}

			struct stat vstat;
			regs.rax = stat(path.c_str(), &vstat);
			SYSPRINT("STAT to path=%s, data=0x%llX = %lld\n",
				path.c_str(), regs.rsi, regs.rax);
			if (regs.rax == 0) {
				cpu.machine().copy_to_guest(regs.rsi, &vstat, sizeof(vstat));
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_fstat, [] (vCPU& cpu) { // FSTAT
			auto& regs = cpu.registers();

			int fd = regs.rdi;
			try {
				fd = cpu.machine().fds().translate(regs.rdi);
				struct stat vstat;
				regs.rax = fstat(fd, &vstat);
				if (regs.rax == 0) {
					cpu.machine().copy_to_guest(regs.rsi, &vstat, sizeof(vstat));
				} else {
					regs.rax = -errno;
				}
			} catch (...) {
				regs.rax = -EBADF;
			}
			cpu.set_registers(regs);
			SYSPRINT("FSTAT to vfd=%lld, fd=%d, data=0x%llX = %lld\n",
				regs.rdi, fd, regs.rsi, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_lstat, [] (vCPU& cpu) { // LSTAT
			auto& regs = cpu.registers();
			const auto vpath = regs.rdi;
			std::string path = cpu.machine().memcstring(vpath, PATH_MAX);
			if (UNLIKELY(!cpu.machine().fds().is_readable_path(path))) {
				regs.rax = -EPERM;
			} else {
				struct stat vstat;
				const int result = lstat(path.c_str(), &vstat);
				if (result == 0) {
					cpu.machine().copy_to_guest(regs.rsi, &vstat, sizeof(vstat));
					regs.rax = 0;
				} else {
					regs.rax = -errno;
				}
			}
			cpu.set_registers(regs);
			SYSPRINT("LSTAT to path=%s, data=0x%llX = %lld\n",
				path.c_str(), regs.rsi, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_lseek, [] (vCPU& cpu) { // LSEEK
			auto& regs = cpu.registers();
			int fd = regs.rdi;
			try {
				fd = cpu.machine().fds().translate(regs.rdi);
				regs.rax = lseek(fd, regs.rsi, regs.rdx);
				if (int(regs.rax) < 0) {
					regs.rax = -errno;
				}
			} catch (...) {
				regs.rax = -EBADF;
			}
			cpu.set_registers(regs);
			SYSPRINT("lseek(vfd=%lld, fd=%d, offset=%lld, whence=%lld) = %lld\n",
				regs.rdi, fd, regs.rsi, regs.rdx, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_poll, [](vCPU& cpu) { // POLL
			auto& regs = cpu.registers();
			const unsigned guest_count = regs.rsi;
			const size_t bytes = sizeof(pollfd) * guest_count;
			auto *fds = cpu.machine().template rw_memory_at<struct pollfd>(regs.rdi, bytes);
			std::array<struct pollfd, 256> host_fds;
			std::array<unsigned, 256> host_fds_indexes;
			unsigned host_fds_count = 0;
			for (unsigned i = 0; i < guest_count; i++)
			{
				// stdout/stderr
				if (fds[i].fd == 1 || fds[i].fd == 2)
					fds[i].revents = fds[i].events;
				else {
					// Translate the fd
					const int fd = cpu.machine().fds().translate(fds[i].fd);
					if (fd < 0) {
						// Invalid fd, set revents to POLLNVAL
						fds[i].revents = POLLNVAL;
						continue;
					}
					host_fds.at(host_fds_count) = pollfd{fd, fds[i].events, 0};
					host_fds_indexes.at(host_fds_count) = i;
					host_fds_count++;
				}
			}
			if (host_fds_count == 0) {
				regs.rax = 0;
			} else {
				// Call poll on the host
				regs.rax = poll(host_fds.data(), host_fds_count, 250);
				if (int(regs.rax) < 0) {
					regs.rax = -errno;
				} else {
					// Copy back the results
					const size_t count = std::min(size_t(regs.rax), size_t(host_fds_count));
					for (size_t i = 0; i < count; i++)
					{
						const unsigned index = host_fds_indexes.at(i);
						fds[index].revents = host_fds[i].revents;
					}
				}
			}
			cpu.set_registers(regs);
			SYSPRINT("poll(fds=0x%llX, count=%u, timeout=%u) = %lld\n",
				regs.rdi, guest_count, unsigned(regs.rdx), regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_mmap, [](vCPU& cpu) { // MMAP
			auto& regs = cpu.registers();
			const uint64_t address = regs.rdi & ~PageMask;
			const uint64_t length = (regs.rsi + PageMask) & ~PageMask;
			const int prot = regs.rdx;
			const auto flags = regs.r10;
			if (UNLIKELY(address % vMemory::PageSize() != 0 || length == 0))
			{
				// Size not matching a 4K page size
				regs.rax = ~0LL; /* MAP_FAILED */
			}
			else if (UNLIKELY(int(regs.r8) >= 0))
			{
				// mmap to file fd
				const int vfd = int(regs.r8);
				const int64_t voff = regs.r9;
				const int real_fd = cpu.machine().fds().translate(vfd);

				uint64_t dst = 0x0;
				if (address != 0x0 && (address + length) > cpu.machine().mmap_start()) {
					dst = address;
					// If the mapping is within a certain range, we should adjust
					// the current mmap address to the end of the new mapping. This is
					// to avoid future collisions when allocating.
					if ((address + length) > cpu.machine().mmap_current())
					{
						PRINTMMAP("Adjusting mmap current address from 0x%lX to 0x%lX\n",
							cpu.machine().mmap(), address + length);
						cpu.machine().mmap() = address + length;
					} else {
						PRINTMMAP("Not adjusting mmap current address to 0x%lX from 0x%lX\n",
							address + length, cpu.machine().mmap());
					}
				}
				else if (address != 0x0 && address < cpu.machine().heap_address()) {
					dst = address;
				}
				else {
					dst = cpu.machine().mmap_allocate(length);
				}
				// Readv into the area
				const uint64_t read_length = regs.rsi; // Don't align the read length
				std::array<Machine::WrBuffer, 256> buffers;
				const size_t cnt =
					cpu.machine().writable_buffers_from_range(buffers.size(), buffers.data(), dst, read_length);
				// Seek to the given offset in the file and read the contents into guest memory
				if (preadv64(real_fd, (const iovec *)&buffers[0], cnt, voff) < 0) {
					PRINTMMAP("preadv64 failed: %s for %zu buffers at offset %ld\n",
						strerror(errno), cnt, voff);
					for (size_t i = 0; i < cnt; i++)
					{
						PRINTMMAP("  %zu: iov_base=%p, iov_len=%zu\n",
							i, buffers[i].ptr, buffers[i].len);
					}
					regs.rax = ~0LL; /* MAP_FAILED */
				} else {
					regs.rax = dst;
				}
				// Zero the remaining area
				const size_t zero_length = length - read_length;
				if (zero_length > 0)
				{
					cpu.machine().memzero(dst + read_length, zero_length);
				}
				cpu.set_registers(regs);
				cpu.machine().do_mmap_callback(cpu,
					address, length, flags, prot, real_fd, voff);
				PRINTMMAP("mmap(0x%lX (0x%llX), %lu, prot=%llX, flags=%llX, vfd=%d) = 0x%llX -> 0x%lX\n",
						  address, regs.rdi, read_length, regs.rdx, regs.r10, int(regs.r8),
						  regs.rax, cpu.machine().mmap_current());
				return;
			}
			else if (address != 0x0 && address >= cpu.machine().heap_address() && address + length <= cpu.machine().mmap_current())
			{
				// Existing range already mmap'ed
				regs.rax = address;
			}
			else if (address != 0x0 && address >= cpu.machine().mmap_current() && !cpu.machine().relocate_fixed_mmap())
			{
				// Force mmap to a specific address
				regs.rax = address;
				// If the mapping is within a certain range, we should adjust
				// the current mmap address to the end of the new mapping. This is
				// to avoid future collisions when allocating.
				if (address + length <= cpu.machine().mmap_current() + MMAP_COLLISION_TRESHOLD)
				{
					PRINTMMAP("Adjusting mmap current address to 0x%lX\n",
						address + length);
					cpu.machine().mmap() = address + length;
				} else {
					PRINTMMAP("Not adjusting mmap current address to 0x%lX\n",
						address + length);
				}
			}
			else
			{
				regs.rax = cpu.machine().mmap_allocate(length);
			}
			/* If MAP_ANON is set, the memory must be zeroed. memzero() will only
			   zero the pages that are dirty, preventing RSS from exploding. */
			if ((flags & MAP_ANON) != 0 && regs.rax != ~0ULL)
			{
				cpu.machine().memzero(regs.rax, length);
			}
			cpu.set_registers(regs);
			cpu.machine().do_mmap_callback(cpu, address, length, flags, prot, -1, 0);
			PRINTMMAP("mmap(0x%lX, %lu, prot=%llX, flags=%llX, vfd=%d) = 0x%llX\n",
					  address, length, regs.rdx, regs.r10, int(regs.r8), regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_mprotect, [](vCPU& cpu) { // MPROTECT
			/* SYS mprotect */
			auto& regs = cpu.registers();
			const int prot = regs.rdx;
			// mprotect(...) is unsupported, however it would be nice if we could
			// support it on the identity-mapped main VM, during startup.
			regs.rax = 0;
			cpu.set_registers(regs);
			cpu.machine().do_mmap_callback(cpu,
				regs.rdi, regs.rsi, 0, prot, -1, 0);
			PRINTMMAP("mprotect(0x%llX, %llu, 0x%X) = %lld\n",
				regs.rdi, regs.rsi, prot, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_munmap, [](vCPU &cpu) { // MUNMAP
			auto& regs = cpu.registers();
			// We don't support MMAP fully, but we can try to relax the mapping.
			const uint64_t old_base = regs.rdi & ~PageMask;
			const uint64_t old_size = (regs.rsi + PageMask) & ~PageMask;
			[[maybe_unused]] bool relaxed =
				cpu.machine().mmap_unmap(old_base, old_size);
			// Because we do not support MMAP fully, we will just return 0 here.
			regs.rax = 0;
			cpu.set_registers(regs);
			PRINTMMAP("munmap(0x%lX, %lu, relaxed=%d)\n", old_base, old_size, relaxed);
		});
	Machine::install_syscall_handler(
		SYS_brk, [](vCPU& cpu) { // BRK
			auto& regs = cpu.registers();
			const uint64_t old_brk = cpu.machine().brk_address();
			uint64_t new_brk = regs.rdi;
			if (new_brk < old_brk) {
				// brk() to a lower address, keep the old one
				// We can only grow the heap, not shrink it.
				regs.rax = old_brk;
			} else {
				// clamp brk() outside to the heap range
				new_brk = std::min(new_brk, cpu.machine().brk_end_address());
				cpu.machine().set_brk_address(new_brk);
				regs.rax = new_brk;
			}
			cpu.set_registers(regs);
			SYSPRINT("brk(0x%llX) = 0x%llX\n", regs.rdi, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_rt_sigaction, [](vCPU& cpu)
		{
			/* SYS rt_sigaction */
			auto& regs = cpu.registers();
			const int sig = regs.rdi;
			const uint64_t g_act = regs.rsi;
			const uint64_t g_oldact = regs.rdx;
			//const int flags = regs.r10;

			/* Silently ignore signal 0 */
			if (sig == 0) {
				regs.rax = 0;
				cpu.set_registers(regs);
				SYSPRINT("rt_sigaction(signum=%x, act=0x%lX, oldact=0x%lx) = 0x%llX (ignored)\n",
					sig, g_act, g_oldact, regs.rax);
				return;
			}

			auto& sigact = cpu.machine().sigaction(sig);

			struct kernel_sigaction {
				uint64_t handler;
				uint64_t flags;
				uint64_t restorer;
				uint64_t mask;
			} sa {};
			/* Old action */
			if (g_oldact != 0x0) {
				sa.handler = sigact.handler & ~0xFLL;
				sa.flags   = (sigact.altstack ? SA_ONSTACK : 0x0);
				sa.mask    = sigact.mask;
				sa.restorer = sigact.restorer;
				cpu.machine().copy_to_guest(g_oldact, &sa, sizeof(sa));
			}
			/* New action */
			if (g_act != 0x0) {
				cpu.machine().copy_from_guest(&sa, g_act, sizeof(sa));
				SYSPRINT("rt_sigaction(action handler=0x%lX  flags=0x%lX  mask=0x%lX)\n",
					sa.handler, sa.flags, sa.mask);
				sigact.handler  = sa.handler;
				sigact.altstack = (sa.flags & SA_ONSTACK) != 0;
				sigact.mask     = sa.mask;
				sigact.restorer = sa.restorer;
			}
			regs.rax = 0;
			SYSPRINT("rt_sigaction(signum=%x, act=0x%lX, oldact=0x%lx) = 0x%llX\n",
				sig, g_act, g_oldact, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_rt_sigprocmask, [](vCPU& cpu)
		{
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
			cpu.set_registers(regs);
			SYSPRINT("rt_sigprocmask(how=%x, set=0x%lX, oldset=0x%lx, size=%u) = 0x%llX\n",
					 how, g_set, g_oldset, size, regs.rax);
		});
	Machine::install_syscall_handler(  // sigaltstack
		SYS_sigaltstack, [](vCPU& cpu)
		{
			auto& regs = cpu.registers();
			if (regs.rdi != 0x0) {
				auto& ss = cpu.machine().signals().per_thread(cpu.machine().threads().gettid()).stack;
				cpu.machine().copy_from_guest(&ss, regs.rdi, sizeof(ss));

				SYSPRINT("sigaltstack(altstack SP=0x%lX  flags=0x%X  size=0x%lX)\n",
					ss.ss_sp, ss.ss_flags, ss.ss_size);
			}
			regs.rax = 0;
			cpu.set_registers(regs);
			SYSPRINT("sigaltstack(ss=0x%llX, old_ss=0x%llx) = 0x%llX\n",
				regs.rdi, regs.rsi, regs.rax);
		});
	Machine::install_syscall_handler( // ioctl
		SYS_ioctl, [](vCPU& cpu) {
			auto& regs = cpu.registers();
			const int fd = cpu.machine().fds().translate(regs.rdi);
			switch (regs.rsi) {
			case TCGETS: // Get terminal attributes
				if (int(regs.rdi) >= 0 && int(regs.rdi) < 3)
				{
					// TODO: Construct fake termios
					regs.rax = 0;
				} else {
					regs.rax = -EPERM;
				}
				break;
			case TCSETS: { // Set terminal attributes
					// Ignore
					regs.rax = 0;
					break;
				}
			case TIOCGWINSZ: // Get window size
				regs.rax = 80;
				break;
			case TIOCGPTN: { // Get PTY number
					const int value = 1; // Fake PTY number
					cpu.machine().copy_to_guest(regs.rdx, &value, sizeof(value));
					regs.rax = 0;
				}
				break;
			case FIONBIO: // Set non-blocking I/O
				if (int(regs.rdi) >= 0 && int(regs.rdi) < 3)
				{
					// Ignore
					regs.rax = 0;
				} else {
					int arg = 0;
					cpu.machine().copy_from_guest(&arg, regs.rsi, sizeof(arg));
					if (arg != 0)
						fcntl(fd, F_SETFL, O_NONBLOCK);
					else
						fcntl(fd, F_SETFL, ~O_NONBLOCK);
					regs.rax = 0;
				}
				break;
			case FIONREAD: {
					// Get number of bytes available for reading
					const uint64_t g_bytes = regs.rdx;
					int bytes = 0;
					if (int(regs.rdi) >= 0 && int(regs.rdi) < 3) {
						cpu.machine().copy_to_guest(g_bytes, &bytes, sizeof(bytes));
						regs.rax = 0;
					} else {
						const int result = ioctl(fd, FIONREAD, &bytes);
						if (result < 0) {
							regs.rax = -errno;
						} else {
							cpu.machine().copy_to_guest(g_bytes, &bytes, sizeof(bytes));
							regs.rax = bytes;
						}
					}
				}
				break;
			default:
				regs.rax = -EINVAL;
			}
			cpu.set_registers(regs);
			SYSPRINT("ioctl(vfd=%lld fd=%d, req=0x%llx) = 0x%llX\n",
					 regs.rdi, fd, regs.rsi, regs.rax);
		});
	Machine::install_syscall_handler( // pread64
		SYS_pread64, [](vCPU& cpu) {
			auto& regs = cpu.registers();
			const int vfd = regs.rdi;
			const auto g_buf = regs.rsi;
			const auto bytes = regs.rdx;
			const auto offset = regs.r10;
			const int fd = cpu.machine().fds().translate(vfd);

			// Readv into the area
			static constexpr size_t READV_BUFFERS = 128;
			tinykvm::Machine::WrBuffer buffers[READV_BUFFERS];
			const auto bufcount =
				cpu.machine().writable_buffers_from_range(READV_BUFFERS, buffers, g_buf, bytes);

			ssize_t result =
				preadv64(fd, (const iovec *)&buffers[0], bufcount, offset);
			if (result < 0) {
				regs.rax = -errno;
			}
			else {
				regs.rax = result;
			}
			cpu.set_registers(regs);
			SYSPRINT("pread64(fd=%d, buf=0x%llX, size=%llu, offset=%llu) = %lld\n",
					 vfd, g_buf, bytes, offset, regs.rax);
		});
	Machine::install_syscall_handler( // pwrite64
		SYS_pwrite64, [](vCPU& cpu) {
			auto& regs = cpu.registers();
			const int vfd = regs.rdi;
			const auto g_buf = regs.rsi;
			const auto bytes = regs.rdx;
			const auto offset = regs.r10;
			const int fd = cpu.machine().fds().translate_writable_vfd(vfd);

			// writev into the area
			static constexpr size_t WRITEV_BUFFERS = 64;
			tinykvm::Machine::Buffer buffers[WRITEV_BUFFERS];
			const auto bufcount =
				cpu.machine().gather_buffers_from_range(WRITEV_BUFFERS, buffers, g_buf, bytes);

			if (pwritev64(fd, (const iovec *)&buffers[0], bufcount, offset) < 0) {
				regs.rax = -errno;
			}
			else {
				regs.rax = bytes;
			}
			cpu.set_registers(regs);
			SYSPRINT("pwrite64(fd=%d, buf=0x%llX, size=%llu, offset=%llu) = %lld\n",
					 vfd, g_buf, bytes, offset, regs.rax);
		});
	Machine::install_syscall_handler( // writev
		SYS_writev, [](vCPU& cpu) {
			auto& regs = cpu.registers();
			struct g_iovec
			{
				uint64_t iov_base;
				size_t iov_len;
			};
			const int vfd = regs.rdi;
			const unsigned count = regs.rdx;
			int fd = -1;

			if (count > 64)
			{
				/* Ignore too many entries */
				regs.rax = -1;
			}
			/* writev: Stdout, Stderr */
			else if (vfd == 1 || vfd == 2)
			{
				ssize_t written = 0;
				for (size_t i = 0; i < count; i++)
				{
					g_iovec vec;
					cpu.machine().copy_from_guest(&vec, regs.rsi + i * sizeof(g_iovec), sizeof(g_iovec));
					// Ignore empty writes? Max 4k writes.
					if (vec.iov_len == 0)
						continue;
					if (vec.iov_len > 8192)
					{
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
				fd = vfd;
			}
			else
			{
				fd = cpu.machine().fds().translate_writable_vfd(vfd);
				if (fd > 0)
				{
					std::array<g_iovec, 64> vecs;
					cpu.machine().copy_from_guest(vecs.data(), regs.rsi, count * sizeof(g_iovec));
					ssize_t written = 0;
					std::array<Machine::Buffer, 256> buffers;

					for (size_t i = 0; i < count; i++)
					{
						const size_t n = cpu.machine().gather_buffers_from_range(
								buffers.size(), buffers.data(),
								vecs[i].iov_base, vecs[i].iov_len);

						ssize_t result = writev(fd,
							(const struct iovec *)buffers.data(), n);
						if (result < 0)
						{
							written = -errno;
							break;
						}
						written += result;
					}
					regs.rax = written;
				}
				else
				{
					regs.rax = -EBADF;
				}
			}
			cpu.set_registers(regs);
			SYSPRINT("writev(%d (%d), 0x%llX, %u) = %lld\n",
					 vfd, fd, regs.rsi, count, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_access, [](vCPU& cpu) { // ACCESS
			auto& regs = cpu.registers();
			const uint64_t vpath = regs.rdi;
			std::string path = cpu.machine().memcstring(vpath, PATH_MAX);
			const int mode = regs.rsi;
			if (UNLIKELY(!cpu.machine().fds().is_readable_path(path)))
			{
				regs.rax = -EACCES;
			}
			else if (UNLIKELY(access(path.c_str(), mode) < 0))
			{
				regs.rax = -errno;
			}
			else
			{
				regs.rax = 0;
			}
			cpu.set_registers(regs);
			SYSPRINT("access(path=%s (0x%lX), mode=0x%X) = %lld\n",
					 path.c_str(), vpath, mode, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_pipe2, [](vCPU& cpu) { // PIPE2
			auto& regs = cpu.registers();
			// int pipe2(int pipefd[2], int flags);
			const uint64_t g_pipefd = regs.rdi;
			const int flags = regs.rsi;
			int pipefd[2];
			if (UNLIKELY(pipe2(pipefd, flags) < 0))
			{
				regs.rax = -errno;
			}
			else
			{
				// Manage the new fds as writable
				const int vfd1 = cpu.machine().fds().manage(pipefd[0], false, true);
				const int vfd2 = cpu.machine().fds().manage(pipefd[1], false, true);
				// Copy the vfds to the guest
				pipefd[0] = vfd1;
				pipefd[1] = vfd2;
				cpu.machine().copy_to_guest(g_pipefd, pipefd, sizeof(pipefd));
				regs.rax = 0;
				// Record the pipe pair so it can be reconstructed in forks
				cpu.machine().fds().add_socket_pair({vfd1, vfd2, FileDescriptors::SocketType::PIPE2});
			}
			cpu.set_registers(regs);
			SYSPRINT("pipe2(0x%llX, 0x%X) = %lld\n",
					 regs.rdi, int(regs.rsi), regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_mremap, [](vCPU& cpu) { // MREMAP
			auto& regs = cpu.registers();
			auto& mm = cpu.machine().mmap();
			uint64_t old_addr = regs.rdi & ~(uint64_t)0xFFF;
			uint64_t old_len = (regs.rsi + 0xFFF) & ~(uint64_t)0xFFF;
			uint64_t new_len = (regs.rdx + 0xFFF) & ~(uint64_t)0xFFF;
			unsigned flags = regs.r10;

			if (false && old_addr + old_len == mm)
			{
				if (old_addr + new_len < old_addr)
					throw MachineException("mremap: overflow");
				mm = old_addr + new_len;
				regs.rax = old_addr;
			}
			else if (flags & MREMAP_FIXED)
			{
				// We don't support MREMAP_FIXED
				regs.rax = ~0LL; /* MAP_FAILED */
			}
			else
			{
				// We don't support other flags
				regs.rax = ~0LL; /* MAP_FAILED */
			}
			cpu.set_registers(regs);
			PRINTMMAP("mremap(0x%llX, %llu, %llu, flags=0x%X) = 0x%llX\n",
					  regs.rdi, regs.rsi, regs.rdx, flags, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_mincore, [](vCPU& cpu) { // mincore
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			cpu.set_registers(regs);
			SYSPRINT("mincore(0x%llX, %llu, 0x%llX) = %lld\n",
					 regs.rdi, regs.rsi, regs.rdx, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_madvise, [](vCPU& cpu) { // MADVISE
			auto& regs = cpu.registers();
			regs.rax = 0;
			if (regs.rdx == MADV_DONTNEED)
			{
				cpu.machine().memzero(regs.rdi, regs.rsi);
			}
			cpu.set_registers(regs);
			PRINTMMAP("madvise(0x%llX, %llu, 0x%llx) = %lld\n",
					  regs.rdi, regs.rsi, regs.rdx, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_dup, [](vCPU& cpu) { // DUP
			auto& regs = cpu.registers();
			int fd = regs.rdi;
			try {
				fd = cpu.machine().fds().translate(fd);
				const int new_fd = dup(fd);
				if (new_fd < 0)
				{
					regs.rax = -errno;
				}
				else
				{
					regs.rax = cpu.machine().fds().manage(new_fd, false, false);
				}
			} catch (...) {
				regs.rax = -EBADF;
			}
			cpu.set_registers(regs);
			SYSPRINT("dup(vfd=%lld fd=%d) = %lld\n",
					 regs.rdi, fd, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_dup2, [](vCPU& cpu) { // DUP2
			auto& regs = cpu.registers();
			const int vfd = regs.rdi;
			const int new_vfd = regs.rsi;
			if (vfd == new_vfd)
			{
				// No need to dup2() to the same fd
				regs.rax = new_vfd;
				cpu.set_registers(regs);
				SYSPRINT("dup2(vfd=%d (%d), new_vfd=%d (%d)) = %lld\n",
						 vfd, vfd, new_vfd, new_vfd, regs.rax);
				return;
			}
			int fd = -1;
			int new_fd = -1;
			try {
				fd = cpu.machine().fds().translate(vfd);
				new_fd = cpu.machine().fds().translate(new_vfd);
				// Close the new fd if it is open
				if (new_fd > 2)
				{
					close(new_fd);
					cpu.machine().fds().free(new_vfd);
				}

				const int result = dup(fd);
				if (result < 0)
				{
					regs.rax = -errno;
				}
				else
				{
					cpu.machine().fds().manage_as(new_vfd, new_fd, false, false);
					regs.rax = new_vfd;
				}
			} catch (...) {
				regs.rax = -EBADF;
			}
			cpu.set_registers(regs);
			SYSPRINT("dup2(vfd=%d (%d), new_vfd=%d (%d)) = %lld\n",
					 vfd, fd, new_vfd, new_fd, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_nanosleep, [](vCPU& cpu) { // nanosleep
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
			SYSPRINT("nanosleep(...) = %lld\n",
					 regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_getpid, [](vCPU& cpu) { // GETPID
			auto& regs = cpu.registers();
			regs.rax = 0; // Changing to PID=1 breaks Golang!?
			cpu.set_registers(regs);
			SYSPRINT("getpid() = %lld\n", regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_capget, [](vCPU& cpu) { // CAPGET
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			cpu.set_registers(regs);
			SYSPRINT("capget(0x%llX, 0x%llX) = %lld\n",
					 regs.rdi, regs.rsi, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_socket, [](vCPU& cpu) { // SOCKET
			auto& regs = cpu.registers();
			// int socket(int domain, int type, int protocol);
			const int domain = regs.rdi;
			const int type = regs.rsi;
			const int protocol = regs.rdx;
			const int fd = socket(domain, type, protocol);
			if (UNLIKELY(fd < 0))
			{
				regs.rax = -errno;
			}
			else
			{
				regs.rax = cpu.machine().fds().manage(fd, true, true);
			}
			cpu.set_registers(regs);
			SYSPRINT("socket(%d, %d, %d) = %d (%lld)\n",
					 domain, type, protocol, fd, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_setsockopt, [](vCPU& cpu) { // SETSOCKOPT
			auto& regs = cpu.registers();
			// int setsockopt(int sockfd, int level, int optname,
			//                const void *optval, socklen_t optlen);
			const int fd = cpu.machine().fds().translate(regs.rdi);
			const int level = regs.rsi;
			const int optname = regs.rdx;
			const uint64_t g_optval = regs.r10;
			const size_t optlen = regs.r8;
			std::array<uint8_t, 256> optval;
			if (UNLIKELY(optlen > optval.size()))
			{
				regs.rax = -EINVAL;
			} else {
				cpu.machine().copy_from_guest(optval.data(), g_optval, optlen);
				if (setsockopt(fd, level, optname, optval.data(), optlen) < 0) {
					regs.rax = -errno;
				} else {
					regs.rax = 0;
				}
			}
			cpu.set_registers(regs);
			SYSPRINT("setsockopt(fd=%d, level=%d, optname=%d, optval=0x%lX, optlen=%zu) = %lld\n",
					 fd, level, optname, g_optval, optlen, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_getsockopt, [](vCPU& cpu) { // GETSOCKOPT
			auto& regs = cpu.registers();
			// int getsockopt(int sockfd, int level, int optname,
			//                void *optval, socklen_t *optlen);
			const int fd = cpu.machine().fds().translate(regs.rdi);
			const int level = regs.rsi;
			const int optname = regs.rdx;
			const uint64_t g_optval = regs.r10;
			const uint64_t g_optlen = regs.r8;
			std::array<uint8_t, 256> optval;
			socklen_t optlen_out = sizeof(optval);
			if (UNLIKELY(getsockopt(fd, level, optname, optval.data(), &optlen_out) < 0)) {
				regs.rax = -errno;
			} else {
				regs.rax = 0;
				if (g_optval) {
					cpu.machine().copy_to_guest(g_optval, optval.data(), optlen_out);
				}
				if (g_optlen) {
					cpu.machine().copy_to_guest(g_optlen, &optlen_out, sizeof(optlen_out));
				}
			}
			cpu.set_registers(regs);
			SYSPRINT("getsockopt(fd=%d, level=%d, optname=%d, optval=0x%lX, optlen=0x%lX) = %lld\n",
					 fd, level, optname, g_optval, g_optlen, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_connect, [](vCPU& cpu) { // CONNECT
			auto& regs = cpu.registers();
			// int connect(int sockfd, const struct sockaddr *addr,
			//             socklen_t addrlen);
			const int fd = cpu.machine().fds().translate(regs.rdi);
			const uint64_t g_addr = regs.rsi;
			const size_t addrlen = regs.rdx;
			struct sockaddr_storage addr {};
			if (UNLIKELY(addrlen > sizeof(addr)))
			{
				SYSPRINT("connect(fd=%d, addr=0x%lX, addrlen=%zu) = %lld (EINVAL, addrlen too large)\n",
						 fd, g_addr, addrlen, regs.rax);
				regs.rax = -EINVAL;
			} else {
				cpu.machine().copy_from_guest(&addr, g_addr, addrlen);
				// Validate the address
				if (UNLIKELY(!cpu.machine().fds().validate_socket_address(fd, addr)))
				{
					regs.rax = -EPERM;
				} else {
					if (UNLIKELY(connect(fd, (struct sockaddr *)&addr, addrlen) < 0)) {
						regs.rax = -errno;
					}
					else {
						regs.rax = 0;
					}
				}
			}
			cpu.set_registers(regs);
			if (UNLIKELY(cpu.machine().m_verbose_system_calls)) {
				const std::string addr_str = cpu.machine().fds().sockaddr_to_string(addr);
				SYSPRINT("connect(fd=%d, addr=0x%lX, addrlen=%zu) = %lld (%s)\n",
							fd, g_addr, addrlen, regs.rax,
							addr_str.c_str());
			}
		});
	Machine::install_syscall_handler(
		SYS_bind, [](vCPU& cpu) { // BIND
			auto& regs = cpu.registers();
			// int bind(int sockfd, const struct sockaddr *addr,
			//           socklen_t addrlen);
			const int fd = cpu.machine().fds().translate(regs.rdi);
			const uint64_t g_addr = regs.rsi;
			const size_t addrlen = regs.rdx;
			struct sockaddr_storage addr {};
			if (UNLIKELY(addrlen > sizeof(addr)))
			{
				regs.rax = -EINVAL;
			}
			else
			{
				cpu.machine().copy_from_guest(&addr, g_addr, addrlen);
				// Validate the address
				if (UNLIKELY(!cpu.machine().fds().validate_socket_address(fd, addr)))
				{
					regs.rax = -EPERM;
				} else {
					if (bind(fd, (struct sockaddr *)&addr, addrlen) < 0) {
						regs.rax = -errno;
					}
					else {
						regs.rax = 0;
					}
				}
			}
			cpu.set_registers(regs);
			if (UNLIKELY(cpu.machine().m_verbose_system_calls)) {
				const std::string addr_str = cpu.machine().fds().sockaddr_to_string(addr);
				SYSPRINT("bind(fd=%d, addr=0x%lX, addrlen=%zu) = %lld (%s)\n",
					 fd, g_addr, addrlen, regs.rax,
					 addr_str.c_str());
			}
		});
	Machine::install_syscall_handler(
		SYS_listen, [](vCPU& cpu) { // LISTEN
			auto& regs = cpu.registers();
			// int listen(int sockfd, int backlog);
			const int vfd = regs.rdi;
			const int fd = cpu.machine().fds().translate_writable_vfd(vfd);
			const int backlog = regs.rsi;
			if (UNLIKELY(listen(fd, backlog) < 0))
			{
				regs.rax = -errno;
			}
			else
			{
				if (auto& callback = cpu.machine().fds().listening_socket_callback;
					callback != nullptr)
				{
					callback(vfd, fd);
				}
				regs.rax = 0;
			}
			cpu.set_registers(regs);
			SYSPRINT("listen(fd=%d (%d), backlog=%d) = %lld\n",
					 vfd, fd, backlog, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_accept4, [](vCPU& cpu) { // ACCEPT4
			auto& regs = cpu.registers();
			// int accept4(int sockfd, struct sockaddr *addr,
			//             socklen_t *addrlen, int flags);
			const int vfd = regs.rdi;
			const int fd = cpu.machine().fds().translate_writable_vfd(vfd);
			const uint64_t g_addr = regs.rsi;
			const size_t g_addrlen = regs.rdx;
			const int flags = regs.r10;
			struct sockaddr_storage addr {};
			socklen_t addrlen = sizeof(addr);
			if (!cpu.machine().fds().accepting_connections()) {
				SYSPRINT("accept4: fd %d (%d) is not accepting connections\n", vfd, fd);
				regs.rax = -EAGAIN;
				cpu.set_registers(regs);
				return;
			}
			const int result = accept4(fd, (struct sockaddr *)&addr, &addrlen, flags);
			if (UNLIKELY(result < 0))
			{
				regs.rax = -errno;
			}
			else
			{
				if (g_addr != 0x0) {
					cpu.machine().copy_to_guest(g_addr, &addr, addrlen);
				}
				if (g_addrlen != 0x0) {
					cpu.machine().copy_to_guest(g_addrlen, &addrlen, sizeof(addrlen));
				}
				if (cpu.machine().fds().accept_socket_callback)
				{
					regs.rax = cpu.machine().fds().accept_socket_callback(vfd, fd, result, addr, addrlen);
				}
				else
				{
					regs.rax = cpu.machine().fds().manage(result, true, true);
				}
			}
			cpu.set_registers(regs);
			SYSPRINT("accept4(fd=%d (%d), addr=0x%lX, addrlen=0x%lX, flags=%d) = %lld\n",
					 vfd, fd, g_addr, g_addrlen, flags, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_getsockname, [](vCPU& cpu) { // GETSOCKNAME
			auto& regs = cpu.registers();
			// int getsockname(int sockfd, struct sockaddr *addr,
			//                  socklen_t *addrlen);
			const int fd = cpu.machine().fds().translate(regs.rdi);
			const uint64_t g_addr = regs.rsi;
			const size_t g_addrlen = regs.rdx;
			struct sockaddr_storage addr {};
			socklen_t addrlen = sizeof(addr);
			if (UNLIKELY(getsockname(fd, (struct sockaddr *)&addr, &addrlen) < 0))
			{
				regs.rax = -errno;
			}
			else
			{
				if (g_addr != 0x0) {
					cpu.machine().copy_to_guest(g_addr, &addr, addrlen);
				}
				if (g_addrlen != 0x0) {
					cpu.machine().copy_to_guest(g_addrlen, &addrlen, sizeof(addrlen));
				}
				regs.rax = 0;
			}
			cpu.set_registers(regs);
			SYSPRINT("getsockname(fd=%d, addr=0x%lX, addrlen=0x%lX) = %lld\n",
					 fd, g_addr, g_addrlen, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_getpeername, [](vCPU& cpu) { // GETPEERNAME
			auto& regs = cpu.registers();
			// int getpeername(int sockfd, struct sockaddr *addr,
			//                  socklen_t *addrlen);
			const int fd = cpu.machine().fds().translate(regs.rdi);
			const uint64_t g_addr = regs.rsi;
			const size_t g_addrlen = regs.rdx;
			struct sockaddr_storage addr {};
			socklen_t addrlen = sizeof(addr);
			if (UNLIKELY(getpeername(fd, (struct sockaddr *)&addr, &addrlen) < 0))
			{
				regs.rax = -errno;
			}
			else
			{
				if (g_addr != 0x0) {
					cpu.machine().copy_to_guest(g_addr, &addr, addrlen);
				}
				if (g_addrlen != 0x0) {
					cpu.machine().copy_to_guest(g_addrlen, &addrlen, sizeof(addrlen));
				}
				regs.rax = 0;
			}
			cpu.set_registers(regs);
			SYSPRINT("getpeername(fd=%d, addr=0x%lX, addrlen=0x%lX) = %lld\n",
					 fd, g_addr, g_addrlen, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_socketpair, [](vCPU& cpu) { // SOCKETPAIR
			auto& regs = cpu.registers();
			// int socketpair(int domain, int type, int protocol, int sv[2]);
			const uint64_t g_sv = regs.r10;
			int sv[2] = { 0, 0 };
			const int res = socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0, sv);
			if (UNLIKELY(res < 0))
			{
				regs.rax = -errno;
			}
			else
			{
				sv[0] = cpu.machine().fds().manage(sv[0], true, true);
				sv[1] = cpu.machine().fds().manage(sv[1], true, true);
				cpu.machine().copy_to_guest(g_sv, sv, sizeof(sv));
				regs.rax = 0;
				// Manage the socketpair so it can be reconstructed later
				cpu.machine().fds().add_socket_pair({sv[0], sv[1], FileDescriptors::SocketType::SOCKETPAIR});
			}
			SYSPRINT("socketpair(AF_UNIX, SOCK_STREAM, 0, 0x%lX) = %lld {%d, %d}\n",
				g_sv, regs.rax, sv[0], sv[1]);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_exit, [](vCPU& cpu) { // EXIT
#ifdef VERBOSE_GUEST_EXITS
			auto& regs = cpu.registers();
			printf("Machine exited with return value 0x%llX\n", regs.rdi);
#endif
			cpu.stop();
		});
	Machine::install_syscall_handler(
		SYS_shutdown, [] (vCPU& cpu) { // SHUTDOWN
			auto& regs = cpu.registers();
			// int shutdown(int sockfd, int how);
			const int vfd = regs.rdi;
			int fd = -1;
			try {
				if (vfd >= 0 && vfd < 3)
				{
					fd = vfd;
					regs.rax = 0;
				}
				else
				{
					fd = cpu.machine().fds().translate(vfd);
					regs.rax = ::shutdown(fd, regs.rsi);
					if (int(regs.rax) < 0)
						regs.rax = -errno;
				}
			} catch (...) {
				regs.rax = -EBADF;
			}
			cpu.set_registers(regs);
			SYSPRINT("SHUTDOWN(fd=%d (%d), how=0x%llX) = %lld\n",
					 fd, vfd, regs.rsi, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_sendto, [] (vCPU& cpu) { // SENDTO
			auto& regs = cpu.registers();
			// int sendto(int sockfd, const void *buf, size_t len, int flags,
			//            const struct sockaddr *dest_addr, socklen_t addrlen);
			const int vfd = regs.rdi;
			const uint64_t g_buf = regs.rsi;
			const uint64_t bytes = regs.rdx;
			const int flags = regs.r10;
			const uint64_t g_addr = regs.r8;
			const socklen_t addrlen = regs.r9;
			int fd = -1;
			try {
				if (UNLIKELY(bytes > 512UL << 20)) // 512MB
				{
					// Ignore too large buffers
					regs.rax = -ENOMEM;
				}
				else if (UNLIKELY(addrlen > sizeof(struct sockaddr)))
				{
					regs.rax = -EINVAL;
				}
				else
				{
					fd = cpu.machine().fds().translate_writable_vfd(vfd);
					// Gather memory buffers from the guest
					std::array<tinykvm::Machine::Buffer, 256> buffers;
					const auto bufcount =
						cpu.machine().gather_buffers_from_range(buffers.size(), buffers.data(), g_buf, bytes);

					struct sockaddr addr;
					struct msghdr msg {};
					msg.msg_name = nullptr;
					msg.msg_namelen = 0;
					msg.msg_iov = (struct iovec *)&buffers[0];
					msg.msg_iovlen = bufcount;
					msg.msg_control = nullptr;
					msg.msg_controllen = 0;
					msg.msg_flags = MSG_NOSIGNAL; // Ignore SIGPIPE

					if (addrlen > 0 && g_addr != 0x0) {
						cpu.machine().copy_from_guest(&addr, g_addr, addrlen);
						msg.msg_name = &addr;
						msg.msg_namelen = addrlen;
					}

					ssize_t result = sendmsg(fd, &msg, flags);
					if (UNLIKELY(result < 0)) {
						regs.rax = -errno;
					}
					else {
						regs.rax = result;
					}
				}
			} catch (...) {
				regs.rax = -EBADF;
			}
			cpu.set_registers(regs);
			SYSPRINT("sendto(fd=%d (%d), buf=0x%lX, len=%lu, flags=0x%X, dest_addr=0x%lX, addrlen=%u) = %lld\n",
					 vfd, fd, g_buf, bytes, flags, g_addr, addrlen, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_recvfrom, [] (vCPU& cpu) { // RECVFROM
			auto& regs = cpu.registers();
			// int recvfrom(int sockfd, void *buf, size_t len, int flags,
			//			  struct sockaddr *src_addr, socklen_t *addrlen);
			const int vfd = regs.rdi;
			const uint64_t g_buf = regs.rsi;
			const uint64_t bytes = regs.rdx;
			const int flags = regs.r10;
			const uint64_t g_addr = regs.r8;
			const uint64_t g_addrlen = regs.r9;
			int fd = -1;
			try {
				if (UNLIKELY(bytes > 64UL << 20)) // 64MB
				{
					// Ignore too large buffers
					regs.rax = -ENOMEM;
				}
				else
				{
					fd = cpu.machine().fds().translate(vfd);
					std::array<tinykvm::Machine::WrBuffer, 256> buffers;
					const auto bufcount =
						cpu.machine().writable_buffers_from_range(buffers.size(), buffers.data(), g_buf, bytes);
					// We can't use recvfrom here, but there is recvmsg()
					// All the guest data is in the buffers, which is compatible with iovec
					struct sockaddr addr {};
					struct msghdr msg {};
					msg.msg_name = &addr;
					msg.msg_namelen = sizeof(addr);
					msg.msg_iov = (struct iovec *)&buffers[0];
					msg.msg_iovlen = bufcount;
					msg.msg_control = nullptr;
					msg.msg_controllen = 0;
					msg.msg_flags = 0;
					ssize_t result = recvmsg(fd, &msg, flags);
					if (UNLIKELY(result < 0))
					{
						regs.rax = -errno;
					}
					else
					{
						if (g_addrlen != 0x0) {
							socklen_t addrlen = msg.msg_namelen;
							cpu.machine().copy_to_guest(g_addrlen, &addrlen, sizeof(addrlen));
							cpu.machine().copy_to_guest(g_addr, &addr, addrlen);
						}
						regs.rax = result;
					}
				}
			} catch (...) {
				regs.rax = -EBADF;
			}
			cpu.set_registers(regs);
			SYSPRINT("recvfrom(fd=%d (%d), buf=0x%lX, len=%lu, flags=0x%X, src_addr=0x%lX, addrlen=0x%lX) = %lld\n",
					 vfd, fd, g_buf, bytes, flags, g_addr, g_addrlen, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_recvmsg, [] (vCPU& cpu) { // RECVMSG
			auto& regs = cpu.registers();
			// int recvmsg(int sockfd, struct msghdr *msg, int flags);
			const int vfd = regs.rdi;
			const uint64_t g_msg = regs.rsi;
			const int flags = regs.rdx;
			int fd = -1;
			try {
				fd = cpu.machine().fds().translate(vfd);
				struct msghdr msg {};
				cpu.machine().copy_from_guest(&msg, g_msg, sizeof(msg));
				std::array<GuestIOvec, 128> iovecs;
				if (msg.msg_iovlen > iovecs.size())
				{
					regs.rax = -EINVAL;
					cpu.set_registers(regs);
					SYSPRINT("recvmsg(fd=%d (%d), msg=0x%lX, flags=0x%X) = %lld (EINVAL, iovlen too large)\n",
							 vfd, fd, g_msg, flags, regs.rax);
					return;
				}
				// Copy the iovecs from guest memory
				const uint64_t g_iov = (uintptr_t)msg.msg_iov;
				cpu.machine().copy_from_guest(iovecs.data(), g_iov, msg.msg_iovlen * sizeof(GuestIOvec));
				// Gather iovec information from the guest
				std::array<tinykvm::Machine::Buffer, 256> buffers;
				size_t bufcount = 0;
				for (size_t i = 0; i < msg.msg_iovlen; i++)
				{
					const uint64_t g_base = iovecs.at(i).iov_base;
					const size_t   g_len = iovecs[i].iov_len;
					const auto this_bufcount =
						cpu.machine().gather_buffers_from_range(
							buffers.size() - bufcount, buffers.data() + bufcount,
							g_base, g_len);
					bufcount += this_bufcount;
				}
				struct sockaddr addr {};
				struct msghdr msg_recv {};
				msg_recv.msg_name = &addr;
				msg_recv.msg_namelen = sizeof(addr);
				msg_recv.msg_iov = (struct iovec *)&buffers[0];
				msg_recv.msg_iovlen = bufcount;
				msg_recv.msg_control = nullptr;
				msg_recv.msg_controllen = 0;
				msg_recv.msg_flags = msg.msg_flags | MSG_NOSIGNAL; // Ignore SIGPIPE
				// Check if there is a control message
				std::array<uint8_t, 256> control;
				if (msg.msg_control != nullptr && msg.msg_controllen > 0 &&
					msg.msg_controllen <= control.size())
				{
					// Copy the control message from guest memory
					cpu.machine().copy_from_guest(control.data(), (uint64_t)msg.msg_control, msg.msg_controllen);
					msg_recv.msg_control = control.data();
					msg_recv.msg_controllen = msg.msg_controllen;
				}
				// Perform the recvmsg
				ssize_t result = recvmsg(fd, &msg_recv, flags);
				if (UNLIKELY(result < 0)) {
					regs.rax = -errno;
				} else {
					regs.rax = result;
				}
			} catch (const std::exception& e) {
				regs.rax = -EBADF;
			}
			cpu.set_registers(regs);
			SYSPRINT("recvmsg(fd=%d (%d), msg=0x%lX, flags=0x%X) = %lld\n",
					 vfd, fd, g_msg, flags, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_sendmsg, [] (vCPU& cpu) { // SENDMSG
			auto& regs = cpu.registers();
			// int sendmsg(int sockfd, const struct msghdr *msg, int flags);
			const int vfd = regs.rdi;
			const uint64_t g_msg = regs.rsi;
			const int flags = regs.rdx;
			int fd = -1;
			try {
				fd = cpu.machine().fds().translate_writable_vfd(vfd);
				struct msghdr msg {};
				cpu.machine().copy_from_guest(&msg, g_msg, sizeof(msg));
				std::array<tinykvm::Machine::Buffer, 256> buffers;
				std::array<GuestIOvec, 128> iovecs;
				if (msg.msg_iovlen > iovecs.size())
				{
					regs.rax = -EINVAL;
					cpu.set_registers(regs);
					SYSPRINT("sendmsg(fd=%d (%d), msg=0x%lX, flags=0x%X) = %lld (EINVAL, iovlen too large)\n",
							 vfd, fd, g_msg, flags, regs.rax);
					return;
				}
				// Copy the iovecs from guest memory
				const uint64_t g_iov = (uintptr_t)msg.msg_iov;
				cpu.machine().copy_from_guest(iovecs.data(), g_iov, msg.msg_iovlen * sizeof(GuestIOvec));
				// Gather iovec information from the guest
				size_t bufcount = 0;
				for (size_t i = 0; i < msg.msg_iovlen; i++)
				{
					const uint64_t g_base = iovecs.at(i).iov_base;
					const size_t   g_len = iovecs[i].iov_len;
					const auto this_bufcount =
						cpu.machine().gather_buffers_from_range(
							buffers.size() - bufcount, buffers.data() + bufcount,
							g_base, g_len);
					bufcount += this_bufcount;
				}
				struct sockaddr addr {};
				struct msghdr msg_send {};
				msg_send.msg_name = &addr;
				msg_send.msg_namelen = sizeof(addr);
				msg_send.msg_iov = (struct iovec *)&buffers[0];
				msg_send.msg_iovlen = bufcount;
				msg_send.msg_control = nullptr;
				msg_send.msg_controllen = 0;
				msg_send.msg_flags = MSG_NOSIGNAL; // Ignore SIGPIPE
				// Perform the sendmsg
				ssize_t result = sendmsg(fd, &msg_send, flags);
				if (UNLIKELY(result < 0)) {
					regs.rax = -errno;
				} else {
					regs.rax = result;
				}
			} catch (...) {
				regs.rax = -EBADF;
			}
			cpu.set_registers(regs);
			SYSPRINT("sendmsg(fd=%d (%d), msg=0x%lX, flags=0x%X) = %lld\n",
					 vfd, fd, g_msg, flags, regs.rax);
			throw std::runtime_error("sendmsg not implemented");
		});
	Machine::install_syscall_handler(
		SYS_uname, [](vCPU& cpu) { // UNAME
			auto& regs = cpu.registers();
			if (cpu.machine().memory_safe_at(regs.rdi, sizeof(struct utsname)))
			{
				struct utsname uts{};
				strcpy(uts.sysname, "Linux");
				strcpy(uts.release, "3.5.0");
				strcpy(uts.machine, "x86_64");
				strcpy(uts.nodename, "tinykvm");
				cpu.machine().copy_to_guest(regs.rdi, &uts, sizeof(uts));
				regs.rax = 0;
			}
			else
			{
				regs.rax = -EFAULT;
			}
			cpu.set_registers(regs);
			SYSPRINT("uname(0x%llX) = %lld\n",
					 regs.rdi, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_fcntl, [](vCPU& cpu) { // FCNTL
			auto& regs = cpu.registers();
			const int vfd = regs.rdi;
			const int cmd = regs.rsi;
			int fd = -1;
			try {
				fd = cpu.machine().fds().translate(vfd);
				regs.rax = 0;
				if (fd < 0)
				{
					regs.rax = -EBADF;
				}
				else if (cmd == F_GETFD)
				{
					//const int flags = fcntl(fd, cmd);
					regs.rax = 0x1;
				}
				else if (cmd == F_SETFD)
				{
					// Ignore the new flags
					regs.rax = 0;
				}
				else if (cmd == F_GETFL)
				{
					const int writable_fd = cpu.machine().fds().translate_writable_vfd(vfd);
					const int flags = fcntl(writable_fd, cmd);
					if (flags < 0)
						regs.rax = -errno;
					else
						regs.rax = flags;
				}
				else if (cmd == F_SETFL)
				{
					const int writable_fd = cpu.machine().fds().translate_writable_vfd(vfd);
					const int flags = fcntl(writable_fd, cmd, regs.rdx);
					if (flags < 0)
						regs.rax = -errno;
					else
						regs.rax = 0;
				}
				else if (cmd == F_GETLK64)
				{
					const int writable_fd = cpu.machine().fds().translate_writable_vfd(vfd);
					struct flock64 fl{};
					int res = fcntl(writable_fd, F_GETLK64, &fl);
					if (res < 0) {
						regs.rax = -errno;
					}
					else {
						cpu.machine().copy_to_guest(regs.rdx, &fl, sizeof(fl));
						regs.rax = 0;
					}
				}
				else if (cmd == F_SETLK64)
				{
					const int writable_fd = cpu.machine().fds().translate_writable_vfd(vfd);
					struct flock64 fl{};
					cpu.machine().copy_from_guest(&fl, regs.rdx, sizeof(fl));
					int res = fcntl(writable_fd, F_SETLK64, &fl);
					if (res < 0) {
						regs.rax = -errno;
					}
					else {
						regs.rax = 0;
					}
				}
				else if (cmd == F_SETLK)
				{
					throw std::runtime_error("fcntl: F_SETLK not implemented");
				}
				else if (cmd == F_GETLK)
				{
					throw std::runtime_error("fcntl: F_GETLK not implemented");
				}
				else if (cmd == F_GETOWN)
				{
					regs.rax = 0;
				}
				else if (cmd == F_SETOWN)
				{
					regs.rax = 0;
				}
				else if (cmd == F_GETSIG)
				{
					regs.rax = 0;
				}
				else if (cmd == F_SETSIG)
				{
					regs.rax = 0;
				}
				else if (cmd == F_DUPFD_CLOEXEC)
				{
					if (fd > 2)
					{
						auto opt_entry = cpu.machine().fds().entry_for_vfd(vfd);
						if (!opt_entry)
						{
							regs.rax = -EBADF;
							cpu.set_registers(regs);
							SYSPRINT("fcntl(%d (%d), cmd=0x%X (%d), ...) = %lld (EBADF)\n",
									fd, vfd, cmd, cmd, regs.rax);
							return;
						}
						// The duplicate inherits writable, socket etc.
						const bool is_writable = (*opt_entry)->is_writable;
						const bool is_socket   = cpu.machine().fds().is_socket_vfd(vfd);
						const int new_fd = dup(fd);
						const int new_vfd = cpu.machine().fds().manage_duplicate(vfd, new_fd, is_socket, is_writable);
						regs.rax = new_vfd;
					} else if (fd >= 0) {
						const int new_fd = dup(fd);
						const int new_vfd = cpu.machine().fds().manage_duplicate(vfd, new_fd, false, true);
						regs.rax = new_vfd;
					} else {
						regs.rax = -EBADF;
					}
				}
				else
				{
					SYSPRINT("fcntl(%d (%d), cmd=0x%X (%d), ...) is not implemented\n",
							 fd, vfd, cmd, cmd);
				}
			} catch (...) {
				regs.rax = -EBADF;
			}
			cpu.set_registers(regs);
			SYSPRINT("fcntl(%d (%d), 0x%X, ...) = %lld\n",
					 fd, vfd, cmd, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_fsync, [](vCPU& cpu) { // FSYNC
			auto& regs = cpu.registers();
			const int vfd = regs.rdi;
			try {
				const int fd = cpu.machine().fds().translate(vfd);
				if (fd >= 0)
				{
					regs.rax = fsync(fd);
					if (int(regs.rax) < 0)
						regs.rax = -errno;
				}
				else
				{
					regs.rax = -EBADF;
				}
			} catch (...) {
				regs.rax = -EBADF;
			}
			SYSPRINT("fsync(%d) = %lld\n",
					 vfd, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_getcwd, [](vCPU& cpu) { // GETCWD
			auto& regs = cpu.registers();
			const uint64_t g_buf = regs.rdi;
			const size_t buflen = regs.rsi;

			const std::string& cwd = cpu.machine().fds().current_working_directory();
			if (cwd.size()+1 <= buflen) {
				// Copy the current working directory to the guest, including
				// the null terminator.
				cpu.machine().copy_to_guest(g_buf, cwd.c_str(), cwd.size()+1);
				regs.rax = g_buf;
			} else {
				regs.rax = 0;
			}
			cpu.set_registers(regs);
			SYSPRINT("getcwd(buf=0x%lX (%s), buflen=%zu) = %lld\n",
					 g_buf, cwd.c_str(), buflen, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_mkdir, [](vCPU& cpu) { // MKDIR
			auto& regs = cpu.registers();
			std::string path = cpu.machine().memcstring(regs.rdi, PATH_MAX);
			// Check if the path is writable (path can be modified)
			if (cpu.machine().fds().is_writable_path(path))
			{
				// Create the directory
				if (mkdir(path.c_str(), 0755) < 0) {
					regs.rax = -errno;
				}
				else {
					regs.rax = 0;
				}
			}
			else
			{
				regs.rax = -EPERM;
			}
			cpu.set_registers(regs);
			SYSPRINT("mkdir(%s (0x%llX), 0x%llX) = %lld\n",
					 path.c_str(), regs.rdi, regs.rsi, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_rename, [](vCPU& cpu) { // RENAME
			auto& regs = cpu.registers();
			std::string from_path = cpu.machine().memcstring(regs.rdi, PATH_MAX);
			std::string to_path = cpu.machine().memcstring(regs.rsi, PATH_MAX);
			// Check if *BOTH* paths are writable (paths can be modified)
			if (cpu.machine().fds().is_writable_path(from_path)
				&& cpu.machine().fds().is_writable_path(to_path))
			{
				// Rename the file
				if (rename(from_path.c_str(), to_path.c_str()) < 0) {
					regs.rax = -errno;
				}
				else {
					regs.rax = 0;
				}
			}
			else
			{
				regs.rax = -EPERM;
			}
			cpu.set_registers(regs);
			SYSPRINT("rename(%s (0x%llX), %s (0x%llX)) = %lld\n",
					 from_path.c_str(), regs.rdi, to_path.c_str(), regs.rsi, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_readlink, [](vCPU& cpu) { // READLINK
			auto& regs = cpu.registers();
			// int readlink(const char *path, char *buf, size_t bufsiz);
			std::string path = cpu.machine().memcstring(regs.rdi, PATH_MAX);
			const uint64_t g_buf = regs.rsi;
			const size_t bufsiz = regs.rdx;
			std::array<char, PATH_MAX> buf;
			// Check if the symlink resolves to anything
			if (cpu.machine().fds().resolve_symlink(path))
			{
				// The path has now been resolved, so we can use that as the
				// return buffer to the guest.
				cpu.machine().copy_to_guest(g_buf, path.c_str(), path.size());
				regs.rax = path.size();
			} else if (bufsiz > buf.size()) {
				regs.rax = -EINVAL;
			} else if (UNLIKELY(!cpu.machine().fds().is_readable_path(path))) {
				// This should be a permission error or EACCES, but some run-times
				// like to recurse from root up to the path, which we don't want to
				// allow. So instead we return EINVAL to pretend the path is not a link.
				regs.rax = -EINVAL;
			} else {
				// Read the link
				ssize_t result = readlink(path.c_str(), buf.data(), bufsiz);
				if (result < 0)
				{
					regs.rax = -errno;
				}
				else
				{
					cpu.machine().copy_to_guest(g_buf, buf.data(), result);
					regs.rax = result;
				}
			}
			cpu.set_registers(regs);
			SYSPRINT("readlink(%s (0x%llX), buf=0x%lX, bufsiz=%zu) = %lld\n",
					 path.c_str(), regs.rdi, g_buf, bufsiz, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_fchmod, [](vCPU& cpu) { // FCHMOD
			auto& regs = cpu.registers();
			// int fchmod(int fd, mode_t mode);
			const int fd = cpu.machine().fds().translate_writable_vfd(regs.rdi);
			const mode_t mode = regs.rsi;
			if (fd >= 0)
			{
				if (fchmod(fd, mode) < 0)
				{
					regs.rax = -errno;
				}
				else
				{
					regs.rax = 0;
				}
			}
			else
			{
				regs.rax = -EBADF;
			}
			cpu.set_registers(regs);
			SYSPRINT("fchmod(fd=%d, mode=0x%X) = %lld\n",
					 fd, mode, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_unlink, [](vCPU& cpu) { // UNLINK
			auto& regs = cpu.registers();
			std::string path = cpu.machine().memcstring(regs.rdi, PATH_MAX);
			// Check if the path is writable (path can be modified)
			if (cpu.machine().fds().is_writable_path(path))
			{
				// Unlink the file
				if (unlink(path.c_str()) < 0) {
					regs.rax = -errno;
				}
				else {
					regs.rax = 0;
				}
			}
			else
			{
				regs.rax = -EPERM;
			}
			cpu.set_registers(regs);
			SYSPRINT("unlink(%s (0x%llX)) = %lld\n",
					 path.c_str(), regs.rdi, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_unlinkat, [](vCPU& cpu) { // UNLINKAT
			auto& regs = cpu.registers();
			// int unlinkat(int dirfd, const char *pathname, int flags);
			const int vdirfd = regs.rdi;
			const int flags = regs.rsi | AT_SYMLINK_NOFOLLOW;
			const uint64_t g_path = regs.rdx;
			std::string path;
			// Check if the path is writable (path can be modified)
			if (cpu.machine().fds().is_writable_path(path))
			{
				int dirfd = cpu.machine().fds().current_working_directory_fd();
				if (vdirfd != AT_FDCWD)
				{
					dirfd = cpu.machine().fds().translate_writable_vfd(vdirfd);
				}

				if (g_path != 0x0)
				{
					path = cpu.machine().memcstring(g_path, PATH_MAX);
				}

				// Unlink the file, relative to the dirfd
				if (unlinkat(dirfd, path.c_str(), flags) < 0) {
					regs.rax = -errno;
				}
				else {
					regs.rax = 0;
				}
			}
			else
			{
				regs.rax = -EPERM;
			}
			cpu.set_registers(regs);
			SYSPRINT("unlinkat(%d, %s (0x%llX), %d) = %lld\n",
					 vdirfd, path.c_str(), regs.rdx, flags, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_gettimeofday, [](vCPU& cpu) { // gettimeofday
			auto& regs = cpu.registers();
			const uint64_t g_buf = regs.rdi;
			const uint64_t g_tzbuf = regs.rsi;
			struct timeval tv;
			regs.rax = gettimeofday(&tv, nullptr);
			if (int(regs.rax) < 0)
			{
				regs.rax = -errno;
			}
			else
			{
				cpu.machine().copy_to_guest(regs.rdi, &tv, sizeof(tv));
			}
			cpu.set_registers(regs);
			SYSPRINT("gettimeofday(buf=0x%lX, tzbuf=0x%lX) = %lld\n",
					 g_buf, g_tzbuf, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_getgid, [](vCPU& cpu) { // GETGID
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_getuid, [](vCPU& cpu) { // GETUID
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_geteuid, [](vCPU& cpu) { // GETEUID
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_getegid, [](vCPU& cpu) { // GETEGID
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_getppid, [](vCPU& cpu) { // GETPPID
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
			SYSPRINT("getppid(...) = %lld\n", regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_getpgrp, [](vCPU& cpu) { // GETPGRP
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
			SYSPRINT("getpgrp(...) = %lld\n", regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_getgroups, [](vCPU& cpu) { // GETGROUPS
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			cpu.set_registers(regs);
			SYSPRINT("getgroups(...) = %lld\n", regs.rax);
		});
	Machine::install_syscall_handler( // sched_getparam
		SYS_sched_getparam, [](vCPU& cpu)
		{
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
			SYSPRINT("sched_getparam(...) = %lld\n", regs.rax);
		});
	Machine::install_syscall_handler( // sched_getscheduler
		SYS_sched_getscheduler, [](vCPU& cpu)
		{
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
			SYSPRINT("sched_getscheduler(...) = %lld\n", regs.rax);
		});
	Machine::install_syscall_handler( // prctl
		SYS_prctl, [](vCPU& cpu)
		{
			auto& regs = cpu.registers();
			const int option = regs.rdi;
			if (option == PR_GET_NAME)
			{
				const uint64_t g_buf = regs.rsi;
				const size_t buflen = regs.rdx;
				if (buflen > 16)
					regs.rax = -EINVAL;
				else
				{
					const char *name = "tinykvm";
					cpu.machine().copy_to_guest(g_buf, name, buflen);
					regs.rax = 0;
				}
			}
			else if (option == PR_SET_NAME)
			{
				const uint64_t g_buf = regs.rsi;
				std::string name = cpu.machine().memcstring(g_buf, 16);
				SYSPRINT("PR_SET_NAME(%s)\n", name.c_str());
				regs.rax = 0;
			}
			else
			{
				regs.rax = -EINVAL;
			}
			cpu.set_registers(regs);
			SYSPRINT("prctl(opt=%d) = %lld\n", option, regs.rax);
		});
	Machine::install_syscall_handler( // arch_prctl
		SYS_arch_prctl, [](vCPU& cpu)
		{
			auto& regs = cpu.registers();
			[[maybe_unused]] static constexpr long ARCH_SET_GS = 0x1001;
			[[maybe_unused]] static constexpr long ARCH_SET_FS = 0x1002;
			[[maybe_unused]] static constexpr long ARCH_GET_FS = 0x1003;
			[[maybe_unused]] static constexpr long ARCH_GET_GS = 0x1004;
			regs.rax = -22; // EINVAL
			cpu.set_registers(regs);
			SYSPRINT("arch_prctl(opt=%lld, addr=0x%llX) = %lld\n",
					 regs.rdi, regs.rsi, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_tkill, [](auto &) { // tkill
			/* Normally, we would invoke signal w/altstack here */
			throw MachineException("TKILL system call received");
		});
	Machine::install_syscall_handler(
		SYS_time, [](vCPU& cpu) { // time
			auto& regs = cpu.registers();
			regs.rax = time(NULL);
			cpu.set_registers(regs);
			SYSPRINT("time(NULL) = %lld\n", regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_sched_getaffinity, [](vCPU& cpu) { // sched_getaffinity
			/* SYS sched_getaffinity */
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
			SYSPRINT("sched_getaffinity() = %lld\n", regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_getdents64, [](vCPU& cpu) { // GETDENTS64
			auto& regs = cpu.registers();

			int fd = cpu.machine().fds().translate(regs.rdi);

			char buffer[2048];
			regs.rax = syscall(SYS_getdents64, fd, buffer, sizeof(buffer));
			if (regs.rax > 0)
			{
				cpu.machine().copy_to_guest(regs.rsi, buffer, regs.rax);
			}
			cpu.set_registers(regs);
			SYSPRINT("GETDENTS64 to vfd=%lld, fd=%d, data=0x%llX = %lld\n",
				regs.rdi, fd, regs.rsi, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_clock_gettime, [](vCPU& cpu) { // clock_gettime
			auto& regs = cpu.registers();
			struct timespec ts;
			clockid_t clk_id = regs.rdi;
			if (UNLIKELY(clk_id != CLOCK_REALTIME))
				clk_id = CLOCK_MONOTONIC;
			regs.rax = clock_gettime(clk_id, &ts);
			if (int(regs.rax) < 0)
				regs.rax = -errno;
			else {
				cpu.machine().copy_to_guest(regs.rsi, &ts, sizeof(ts));
			}
			cpu.set_registers(regs);
			SYSPRINT("clock_gettime(clk=%lld, buf=0x%llX) = %lld\n",
					 regs.rdi, regs.rsi, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_clock_getres, [](vCPU& cpu) { // clock_getres
			auto& regs = cpu.registers();
			regs.rax = clock_getres(CLOCK_MONOTONIC, nullptr);
			cpu.set_registers(regs);
			SYSPRINT("clock_getres(clk=%lld) = %lld\n",
					 regs.rdi, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_clock_nanosleep, [](vCPU& cpu) { // clock_nanosleep
			auto& regs = cpu.registers();
			const uint64_t g_buf = regs.rdx;
			const uint64_t g_rem = regs.r10;
			struct timespec ts;
			struct timespec ts_rem {};
			cpu.machine().copy_from_guest(&ts, g_buf, sizeof(ts));
			const int result =
				clock_nanosleep(CLOCK_MONOTONIC, regs.rsi, &ts, &ts_rem);
			if (result < 0) {
				regs.rax = -errno;
			} else {
				if (g_rem != 0x0)
					cpu.machine().copy_to_guest(g_rem, &ts_rem, sizeof(ts_rem));
				regs.rax = 0;
			}
			cpu.set_registers(regs);
			SYSPRINT("clock_nanosleep(clk=%lld, flags=%lld, req=0x%llX, rem=%lld) = %lld\n",
					 regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_exit_group, [](vCPU& cpu)
		{
	/* SYS exit_group */
#ifdef VERBOSE_GUEST_EXITS
			auto& regs = cpu.registers();
			printf("Machine exits: _exit(%lld)\n", regs.rdi);
#endif
			cpu.stop();
		});
	Machine::install_syscall_handler(
		SYS_openat, [] (vCPU& cpu) { // OPENAT
			auto& regs = cpu.registers();
			const int vfd = regs.rdi;
			const auto vpath = regs.rsi;
			int flags = regs.rdx | AT_SYMLINK_NOFOLLOW;

			std::string path = cpu.machine().memcstring(vpath, PATH_MAX);
			std::string real_path;
			bool write_flags = (flags & (O_WRONLY | O_RDWR)) != 0x0;
			if (!write_flags)
			{
				try {
					int pfd = cpu.machine().fds().current_working_directory_fd();
					if (vfd != AT_FDCWD) {
						pfd = cpu.machine().fds().translate(vfd);
					}
					real_path = path;
					if (UNLIKELY(!cpu.machine().fds().is_readable_path(real_path))) {
						SYSPRINT("OPENAT fd=%ld path was not readable: %s\n", vfd, real_path.c_str());
						regs.rax = -EPERM;
						cpu.set_registers(regs);
						return;
					}

					int fd = openat(pfd, real_path.c_str(), flags);
					if (fd > 0) {
						regs.rax = cpu.machine().fds().manage(fd, false);
					} else {
						regs.rax = -errno;
					}
					SYSPRINT("OPENAT fd=%lld path=%s (real_path=%s) = %d (%lld)\n",
						regs.rdi, path.c_str(), real_path.c_str(), fd, regs.rax);
					cpu.set_registers(regs);
					return;
				} catch (const std::exception& e) {
					SYSPRINT("OPENAT failed: %s\n", e.what());
					SYSPRINT("OPENAT fd=%lld path=%s flags=%X = %d\n",
						regs.rdi, path.c_str(), flags, -1);
					regs.rax = -1;
				}
			}
			if (write_flags || regs.rax == (__u64)-1)
			{
				try {
					int pfd = cpu.machine().fds().current_working_directory_fd();
					if (vfd != AT_FDCWD) {
						pfd = cpu.machine().fds().translate(vfd);
					}

					real_path = path;
					if (!cpu.machine().fds().is_writable_path(real_path)) {
						SYSPRINT("OPENAT fd=%ld path was not writable: %s\n", vfd, real_path.c_str());
						regs.rax = -EPERM;
						cpu.set_registers(regs);
						return;
					}

					int fd = openat(pfd, real_path.c_str(), flags, S_IWUSR | S_IRUSR);
					SYSPRINT("OPENAT where=%lld path=%s (real_path=%s) flags=%X = fd %d\n",
						regs.rdi, path.c_str(), real_path.c_str(), flags, fd);

					if (fd > 0) {
						regs.rax = cpu.machine().fds().manage(fd, false, true);
					} else {
						regs.rax = -errno;
					}
				} catch (...) {
					regs.rax = -1;
				}
			}
			cpu.set_registers(regs);
			SYSPRINT("OPENAT vfd=%lld path=%s flags=%X = %lld\n",
				regs.rdi, path.c_str(), flags, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_newfstatat, [] (vCPU& cpu) { // NEWFSTATAT
			auto& regs = cpu.registers();
			const auto vpath  = regs.rsi;
			const auto buffer = regs.rdx;
			int flags  = AT_SYMLINK_NOFOLLOW; // regs.r10;
			const int vfd = regs.rdi;
			int fd = cpu.machine().fds().current_working_directory_fd();
			std::string path;

			try {
				path = cpu.machine().memcstring(vpath, PATH_MAX);

				if (vfd != AT_FDCWD) {
					// Use existing vfd
					fd = cpu.machine().fds().translate(int(regs.rdi));
				}

				if (UNLIKELY(!cpu.machine().fds().is_readable_path(path) && !path.empty())) {
					// Path is not readable, however, if this is a "readlink" attempt,
					// we should pretend the path is not a link instead.
					if (regs.r10 & AT_SYMLINK_NOFOLLOW) {
						// Create a fictional stat structure, pretending it's a directory
						struct stat64 vstat {};
						vstat.st_mode = S_IFDIR | 0644;
						vstat.st_blksize = 512;
						cpu.machine().copy_to_guest(buffer, &vstat, sizeof(vstat));
						regs.rax = 0;
					} else {
						regs.rax = -EPERM;
					}
				} else {
					// If path is empty, use AT_EMPTY_PATH to operate on the fd
					flags = (path.empty() && vfd != AT_FDCWD) ? AT_EMPTY_PATH : 0;

					struct stat64 vstat {};
					// Path is in allow-list
					const int result = fstatat64(fd, path.c_str(), &vstat, flags);
					if (result == 0) {
						cpu.machine().copy_to_guest(buffer, &vstat, sizeof(vstat));
						regs.rax = 0;
					} else {
						regs.rax = -errno;
					}
				}
			} catch (...) {
				regs.rax = -1;
			}
			cpu.set_registers(regs);
			SYSPRINT("NEWFSTATAT to vfd=%lld, fd=%d, path=%s, data=0x%llX, flags=0x%X = %lld\n",
				regs.rdi, fd, path.c_str(), buffer, flags, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_set_robust_list, [](vCPU& cpu)
		{
			/* SYS set_robust_list */
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			cpu.set_registers(regs);
			SYSPRINT("set_robust_list(...) = %lld\n", regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_eventfd2, [](vCPU& cpu)
		{
			/* SYS eventfd2 */
			auto& regs = cpu.registers();
			const int real_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
			const int vfd = cpu.machine().fds().manage(real_fd, false, true);
			if (UNLIKELY(vfd < 0)) {
				regs.rax = -errno;
			}
			else {
				regs.rax = vfd;
				// Record the eventfd2 in the socket pairs
				cpu.machine().fds().add_socket_pair({vfd, -1, FileDescriptors::SocketType::EVENTFD});
			}
			cpu.set_registers(regs);
			SYSPRINT("eventfd2(...) = %d (%lld)\n",
				real_fd, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_timerfd_create, [](vCPU& cpu)
		{
			auto& regs = cpu.registers();
			const int clockid = regs.rdi;
			const int real_fd = timerfd_create(clockid, TFD_CLOEXEC | TFD_NONBLOCK);
			const int vfd = cpu.machine().fds().manage(real_fd, false, true);
			if (UNLIKELY(vfd < 0)) {
				regs.rax = -errno;
			}
			else {
				regs.rax = vfd;
				// TODO: Record the timerfd in the socket pairs
				//cpu.machine().fds().add_socket_pair({vfd, -1, FileDescriptors::SocketType::EVENTFD});
			}
			cpu.set_registers(regs);
			SYSPRINT("timerfd_create(%d, ...) = %d (%lld)\n",
				clockid, real_fd, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_epoll_create1, [](vCPU& cpu)
		{
			/* SYS epoll_create1 */
			auto& regs = cpu.registers();
			const int fd = epoll_create1(0);
			if (UNLIKELY(fd < 0))
			{
				regs.rax = -errno;
			}
			else
			{
				const int vfd = cpu.machine().fds().manage(fd, false);
				regs.rax = vfd;
			}
			cpu.set_registers(regs);
			SYSPRINT("epoll_create1() = %d (%lld)\n", fd, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_nanosleep, [](vCPU& cpu)
		{
			/* SYS nanosleep */
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
			SYSPRINT("nanosleep(...) = %lld\n", regs.rax);
		});
	Machine::install_syscall_handler( // epoll_ctl
		SYS_epoll_ctl, [](vCPU& cpu)
		{
			auto& regs = cpu.registers();
			const int epollfd = cpu.machine().fds().translate(regs.rdi);
			const int op = regs.rsi;
			const int vfd = int(regs.rdx);
			const int fd = cpu.machine().fds().translate(vfd);
			const uint64_t g_event = regs.r10;
			struct epoll_event event {};
			if (epollfd > 0 && fd >= 0)
			{
				if (g_event != 0x0) {
					cpu.machine().copy_from_guest(&event, g_event, sizeof(event));
				}
				if (UNLIKELY(epoll_ctl(epollfd, op, fd, &event) < 0)) {
					regs.rax = -errno;
				}
				else
				{
					auto& ee = cpu.machine().fds().get_epoll_entry_for_vfd(regs.rdi);
					if (op == EPOLL_CTL_ADD) {
						ee.epoll_fds[vfd] = event;
					} else if (op == EPOLL_CTL_DEL) {
						ee.epoll_fds.erase(vfd);
					}
					regs.rax = 0;
				}
			} else {
				regs.rax = -ENOENT;
			}
			cpu.set_registers(regs);
			if (UNLIKELY(cpu.machine().m_verbose_system_calls))
			{
				std::string event_str;
				if (event.events & EPOLLIN) {
					event_str += "EPOLLIN ";
				}
				if (event.events & EPOLLOUT) {
					event_str += "EPOLLOUT ";
				}
				if (event.events & EPOLLERR) {
					event_str += "EPOLLERR ";
				}
				if (event.events & EPOLLHUP) {
					event_str += "EPOLLHUP ";
				}
				if (event.events & EPOLLRDHUP) {
					event_str += "EPOLLRDHUP ";
				}
				if (event.events & EPOLLET) {
					event_str += "EPOLLET ";
				}
				if (event.events & EPOLLONESHOT) {
					event_str += "EPOLLONESHOT ";
				}
				SYSPRINT("epoll_ctl(epollfd=%lld (%d), op=%d, fd=%d (%d), event=0x%lX) = %lld "
					" event = {events=[%s], data={fd=%d, u32=0x%X, u64=0x%lX}}\n",
					regs.rdi, epollfd, op, fd, vfd, g_event, regs.rax,
					event_str.c_str(), event.data.fd, event.data.u32, event.data.u64);
			}
		});
	Machine::install_syscall_handler( // epoll_wait
		SYS_epoll_wait, [](vCPU& cpu)
		{
			auto& regs = cpu.registers();
			std::array<struct epoll_event, 128> guest_events;
			const int vfd = regs.rdi;
			const uint64_t g_events = regs.rsi;
			const int maxevents = std::min(size_t(regs.rdx), guest_events.size());
			const int timeout = regs.r10;
			const int epollfd = cpu.machine().fds().translate(vfd);
			if (const auto& callback = cpu.machine().fds().epoll_wait_callback; callback) {
				if (!callback(vfd, epollfd, timeout))
					return;
			}
			int result = -1;
			if (cpu.machine().fds().preempt_epoll_wait()) {
				// Only wait for 250us, as we are *not* pre-empting the guest
				const struct timespec ts {
					.tv_sec = 0,
					.tv_nsec = 25000000,
				};
				result = epoll_pwait2(epollfd, guest_events.data(), maxevents, &ts, nullptr);
			}
			else
			{
				// Wait for as long as the timeout
				result = epoll_wait(epollfd, guest_events.data(), maxevents, timeout);
			}
			if (cpu.timed_out()) {
				throw MachineTimeoutException("epoll_wait timed out");
			}
			// Copy events back to guest
			if (result > 0)
			{
				if (cpu.machine().m_verbose_system_calls) {
					for (int i = 0; i < result; ++i)
					{
						std::string event_str;
						if (guest_events[i].events & EPOLLIN) {
							event_str += "EPOLLIN ";
						}
						if (guest_events[i].events & EPOLLOUT) {
							event_str += "EPOLLOUT ";
						}
						if (guest_events[i].events & EPOLLERR) {
							event_str += "EPOLLERR ";
						}
						if (guest_events[i].events & EPOLLHUP) {
							event_str += "EPOLLHUP ";
						}
						if (guest_events[i].events & EPOLLRDHUP) {
							event_str += "EPOLLRDHUP ";
						}
						if (guest_events[i].events & EPOLLET) {
							event_str += "EPOLLET ";
						}
						if (guest_events[i].events & EPOLLONESHOT) {
							event_str += "EPOLLONESHOT ";
						}
						SYSPRINT("epoll_wait: event[%d] = [%s] (i32=%d u32=0x%X u64=0x%lX)\n",
							i, event_str.c_str(), guest_events[i].data.fd,
							guest_events[i].data.u32, guest_events[i].data.u64);
					}
				}
				cpu.machine().copy_to_guest(g_events, guest_events.data(),
					result * sizeof(struct epoll_event));
				regs.rax = result;
			}
			else if (UNLIKELY(result < 0))
			{
				if (errno == EINTR) {
					throw MachineTimeoutException("epoll_wait interrupted");
				}
				regs.rax = -errno;
			}
			else
			{
				// With infinite timeout, we shouldn't exit the epoll wait
				// loop, so we need to re-trigger the syscall when we return.
				if (timeout == -1 && cpu.machine().fds().preempt_epoll_wait()) {
					//regs.rip -= 2; // Make sure we re-trigger the syscall
					cpu.machine().threads().suspend_and_yield(SYS_epoll_wait);
				} else {
					regs.rax = 0;
				}
			}
			cpu.set_registers(regs);
			SYSPRINT("epoll_wait(fd=%d (%d), g_events=0x%lX, maxevents=%d, timeout=%d) = %lld\n",
				vfd, epollfd, g_events, maxevents, timeout, regs.rax);
		});
	Machine::install_syscall_handler( // epoll_pwait
		SYS_epoll_pwait, Machine::get_syscall_handler(SYS_epoll_wait));
	Machine::install_syscall_handler(
		SYS_getrlimit, [](vCPU& cpu) { // getrlimit
			auto& regs = cpu.registers();
			[[maybe_unused]] const auto g_rlim = regs.rsi;
			regs.rax = -ENOSYS;
			cpu.set_registers(regs);
			SYSPRINT("getrlimit(0x%llX) = %lld\n", g_rlim, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_prlimit64, [](vCPU& cpu) { // prlimit64
			auto& regs = cpu.registers();
			const auto oldptr = regs.rdx;
			const auto newptr = regs.r10;

			switch (regs.rsi)
			{
			case 0: // RLIMIT_CPU
				regs.rax = -ENOSYS;
				break;
			case 3: // RLIMIT_STACK
				if (oldptr != 0x0)
				{
					struct rlimit64 lim{};
					lim.rlim_cur = 4UL << 20;
					lim.rlim_max = 4UL << 20;
					SYSPRINT("prlimit64: current stack limit 0x%lX max 0x%lX\n",
						lim.rlim_cur, lim.rlim_max);
					cpu.machine().copy_to_guest(oldptr, &lim, sizeof(lim));
				}
				else if (newptr != 0x0)
				{
#ifdef VERBOSE_SYSCALLS
					struct rlimit64 lim {};
					cpu.machine().copy_from_guest(&lim, newptr, sizeof(lim));
					SYSPRINT("prlimit64: new stack limit 0x%lX max 0x%lX\n",
						lim.rlim_cur, lim.rlim_max);
#endif
				}
				regs.rax = 0;
				break;
			case 7: // RLIMIT_NOFILE
				if (oldptr != 0x0)
				{
					struct rlimit64 lim{};
					lim.rlim_cur = 16384;
					lim.rlim_max = 16384;
					SYSPRINT("prlimit64: current nofile limit 0x%lX max 0x%lX\n",
						lim.rlim_cur, lim.rlim_max);
					cpu.machine().copy_to_guest(oldptr, &lim, sizeof(lim));
					regs.rax = 0;
				}
				if (newptr != 0x0)
				{
					struct rlimit64 lim {};
					cpu.machine().copy_from_guest(&lim, newptr, sizeof(lim));
					SYSPRINT("prlimit64: new nofile limit 0x%lX max 0x%lX\n",
						lim.rlim_cur, lim.rlim_max);
					if (lim.rlim_cur > 0xFFFF) {
						regs.rax = -EINVAL;
					}
					else {
						regs.rax = 0;
					}
				}
				break;
			default:
				regs.rax = -ENOSYS;
			}
			cpu.set_registers(regs);
			SYSPRINT("prlimit64(res=%lld new=0x%llX old=0x%llX) = %lld\n",
					 regs.rsi, newptr, oldptr, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_sendmmsg, [](vCPU& cpu) { // sendmmsg
			auto& regs = cpu.registers();
			const int fd = cpu.machine().fds().translate_writable_vfd(regs.rdi);
			const uint64_t g_buf = regs.rsi;
			const int vcnt = regs.rdx;
			if (fd > 0 && vcnt > 0)
			{
				std::array<struct mmsghdr, 1024> guest_msgs;
				std::array<GuestIOvec, 1024> guest_iovecs;
				std::array<Machine::Buffer, 1024> buffers;
				// Fetch the mmsghdrs from the guest
				cpu.machine().copy_from_guest(guest_msgs.data(), g_buf, vcnt * sizeof(struct mmsghdr));
				// For each mmsghdr, fetch the iovec and sockaddr
				ssize_t messages_sent = 0;
				for (int i = 0; i < vcnt; ++i)
				{
					const uint64_t g_iov = (uintptr_t)guest_msgs[i].msg_hdr.msg_iov;
					const size_t  iovlen = guest_msgs[i].msg_hdr.msg_iovlen;
					const uint64_t g_addr =  (uintptr_t)guest_msgs[i].msg_hdr.msg_name;
					const int addrlen = guest_msgs[i].msg_hdr.msg_namelen;
					// Fetch the iovec array from the guest
					if (iovlen > guest_iovecs.size())
					{
						SYSPRINT("sendmmsg: iovlen %zu > %zu\n", iovlen, guest_iovecs.size());
						regs.rax = -EINVAL;
						break;
					}
					cpu.machine().copy_from_guest(guest_iovecs.data(), g_iov, iovlen * sizeof(GuestIOvec));
					// Fetch the sockaddr from the guest
					if (addrlen > 0)
					{
						throw MachineException("sendmmsg: sockaddr not supported");
						// cpu.machine().copy_from_guest(guest_msgs[i].msg_hdr.msg_name, g_addr, addrlen);
					}
					// For each message, emulate sendto using writev
					ssize_t total = 0;
					for (size_t j = 0; j < iovlen; ++j)
					{
						auto& iov = guest_iovecs.at(j);
						const size_t cnt =
							cpu.machine().gather_buffers_from_range(
								buffers.size(), buffers.data(), iov.iov_base, iov.iov_len);
						ssize_t result = writev(fd, (const iovec *)&buffers[0], cnt);
						if (result < 0)
						{
							total = -errno;
							break;
						} else {
							total += result;
						}
					} // each iovec
					// Update the msg_len field
					guest_msgs[i].msg_len = total;
					if (total > 0)
					{
						messages_sent++;
					}
				}
				// Copy the mmsghdrs back to the guest
				cpu.machine().copy_to_guest(g_buf, guest_msgs.data(), vcnt * sizeof(struct mmsghdr));
				regs.rax = messages_sent;
			}
			else
			{
				regs.rax = -EBADF;
			}
			cpu.set_registers(regs);
			SYSPRINT("sendmmsg(fd=%d, buf=0x%lX, count=%d) = %lld\n",
					 fd, g_buf, vcnt, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_getrandom, [](vCPU& cpu) { // getrandom
			auto& regs = cpu.registers();
			const uint64_t g_buf = regs.rdi;
			const uint32_t bytes = regs.rsi;
			const int flags = regs.rdx;
			(void)flags;

			/* Max 256b randomness. */
			if (bytes <= 256)
			{
				char buffer[256];
				ssize_t actual = getrandom(buffer, bytes, 0);
				if (actual > 0)
					cpu.machine().copy_to_guest(g_buf, buffer, actual);
				regs.rax = actual;
			}
			else
			{
				regs.rax = -1;
			}
			cpu.set_registers(regs);
			SYSPRINT("getrandom(buf=0x%lX bytes=%u flags=%X) = %lld\n",
					 g_buf, bytes, flags, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_statx, [] (vCPU& cpu) { // STATX
			auto& regs = cpu.registers();
			const int vfd = regs.rdi;
			const auto vpath  = regs.rsi;
			const auto flags  = regs.rdx | AT_SYMLINK_NOFOLLOW;
			const auto mask   = regs.r10;
			const auto buffer = regs.r8;
			std::string path;
			int fd = cpu.machine().fds().current_working_directory_fd();

			try {
				path = cpu.machine().memcstring(vpath, PATH_MAX);
				if (!path.empty()) {
					if (UNLIKELY(!cpu.machine().fds().is_readable_path(path))) {
						regs.rax = -EPERM;
					}
				}
				// Translate from vfd when fd != AT_FDCWD
				if (vfd != AT_FDCWD)
					fd = cpu.machine().fds().translate(vfd);

				struct statx vstat;
				const int result =
					statx(fd, path.c_str(), flags, mask, &vstat);
				if (result == 0) {
					cpu.machine().copy_to_guest(buffer, &vstat, sizeof(vstat));
					regs.rax = 0;
				} else {
					regs.rax = -errno;
				}
			} catch (...) {
				regs.rax = -1;
			}
			cpu.set_registers(regs);
			SYSPRINT("STATX to vfd=%lld, fd=%d, path=%s, data=0x%llX, flags=0x%llX, mask=0x%llX = %lld\n",
				regs.rdi, fd, path.c_str(), buffer, flags, mask, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_readlinkat, [](vCPU& cpu) { // READLINKAT
			auto& regs = cpu.registers();
			const int  vfd      = regs.rdi;
			const auto vpath    = regs.rsi;
			const auto g_buffer = regs.rdx;
			std::string path;
			try {
				path = cpu.machine().memcstring(vpath, PATH_MAX);
				// Check if the path is a symlink
				if (cpu.machine().fds().resolve_symlink(path)) {
					// Copy the resolved path to the guest
					cpu.machine().copy_to_guest(g_buffer, path.c_str(), path.size());
					regs.rax = path.size();
				}
				else if (UNLIKELY(!cpu.machine().fds().is_readable_path(path))) {
					// Pretend the path is not a link
					regs.rax = -EINVAL;
				} else {
					int fd = cpu.machine().fds().current_working_directory_fd();
					// Translate from vfd when fd != AT_FDCWD
					if (vfd != AT_FDCWD)
						fd = cpu.machine().fds().translate(vfd);
					// Path is in allow-list
					regs.rax = readlinkat(fd, path.c_str(), (char *)g_buffer, regs.rdx);
					if (regs.rax > 0) {
						cpu.machine().copy_to_guest(g_buffer, path.c_str(), regs.rax);
					} else {
						regs.rax = -errno;
					}
				}
			} catch (...) {
				regs.rax = -1;
			}
			cpu.set_registers(regs);
			SYSPRINT("readlinkat(0x%llX, bufd=0x%llX, size=%llu) = %lld\n",
					 regs.rdi, regs.rsi, regs.rdx, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_utimensat, [](vCPU& cpu) { // utimensat
			auto& regs = cpu.registers();
			// int utimensat(int dirfd, const char *pathname,
			// const struct timespec times[2], int flags);
			const int vfd = regs.rdi;
			const uint64_t g_path = regs.rsi;
			const uint64_t g_times = regs.rdx;
			const int flags = regs.r10;
			(void)flags;
			std::string path;
			struct timespec times[2];
			if (g_times != 0x0)
			{
				cpu.machine().copy_from_guest(times, g_times, sizeof(times));
			} else {
				times[0].tv_sec = 0;
				times[0].tv_nsec = UTIME_NOW;
				times[1].tv_sec = 0;
				times[1].tv_nsec = UTIME_NOW;
			}
			// Translate from vfd when fd != AT_FDCWD
			int fd = cpu.machine().fds().current_working_directory_fd();
			if (vfd != AT_FDCWD)
				fd = cpu.machine().fds().translate_writable_vfd(vfd);
			// Path is in allow-list
			if (fd > 0)
			{
				if (g_path != 0x0)
				{
					path = cpu.machine().memcstring(g_path, PATH_MAX);
					if (!cpu.machine().fds().is_writable_path(path)) {
						regs.rax = -EPERM;
					} else {
						regs.rax = utimensat(fd, path.c_str(), times, flags);
						if (int(regs.rax) < 0)
							regs.rax = -errno;
					}
				} else {
					// Use fd
					regs.rax = futimens(fd, times);
					if (int(regs.rax) < 0)
						regs.rax = -errno;
				}
			}
			else
			{
				regs.rax = -EBADF;
			}
			cpu.set_registers(regs);
			SYSPRINT("utimensat(fd=%d, path=%s, times=0x%lX, flags=%d) = %lld\n",
					 fd, path.c_str(), g_times, flags, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_faccessat, [](vCPU& cpu) { // faccessat
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			cpu.set_registers(regs);
			SYSPRINT("faccessat(...) = %lld\n",
					 regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_fchown, [](vCPU& cpu) { // fchown
			auto& regs = cpu.registers();
			const int vfd = regs.rdi;
			regs.rax = 0;
			cpu.set_registers(regs);
			SYSPRINT("fchown(fd=%d, uid=%lld, gid=%lld) = %lld\n",
					 vfd, regs.rsi, regs.rdx, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_ftruncate, [](vCPU& cpu) { // ftruncate
			auto& regs = cpu.registers();
			const int vfd = regs.rdi;
			const int fd = cpu.machine().fds().translate_writable_vfd(vfd);
			if (fd > 0)
			{
				regs.rax = ftruncate(fd, regs.rsi);
				if (int(regs.rax) < 0)
					regs.rax = -errno;
			}
			else {
				regs.rax = -EBADF;
			}
			cpu.set_registers(regs);
			SYSPRINT("ftruncate(fd=%d, size=%lld) = %lld\n",
					 vfd, regs.rsi, regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_rseq, [](vCPU& cpu) { // rseq
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
			SYSPRINT("rseq(...) = %lld\n",
					 regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_sysinfo, [](vCPU& cpu) { // sysinfo
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			cpu.set_registers(regs);
			SYSPRINT("sysinfo(...) = %lld\n",
					 regs.rax);
		});
	Machine::install_syscall_handler(
		SYS_io_uring_setup, [](vCPU& cpu) { // io_uring_setup
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			cpu.set_registers(regs);
			SYSPRINT("io_uring_setup(...) = %lld\n",
					 regs.rax);
		});

	// Threads: clone, futex, block/tkill etc.
	Machine::setup_multithreading();
}

} // tinykvm
