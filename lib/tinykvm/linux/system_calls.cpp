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
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <unistd.h>
// #define VERBOSE_GUEST_EXITS
// #define VERBOSE_MMAP
// #define VERBOSE_SYSCALLS

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
			SYSPRINT("Unhandled system call: %u\n", scall);
			(void)scall;
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_read, [] (vCPU& cpu) { // READ
			auto& regs = cpu.registers();
			SYSPRINT("READ to fd=%lld, data=0x%llX, size=%llu\n",
				regs.rdi, regs.rsi, regs.rdx);
			int fd = cpu.machine().fds().translate(regs.rdi);

			static constexpr size_t MAX_READ_BUFFERS = 128;
			tinykvm::Machine::WrBuffer buffers[MAX_READ_BUFFERS];

			/* Writable readv buffers */
			auto bufcount = cpu.machine().writable_buffers_from_range(
				MAX_READ_BUFFERS, buffers,
				regs.rsi, regs.rdx);

			regs.rax = readv(fd, (struct iovec *)&buffers[0], bufcount);
			if (int(regs.rax) < 0)
				regs.rax = -errno;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_write, [] (vCPU& cpu) { // WRITE
			auto& regs = cpu.registers();
			const int    fd = regs.rdi;
			const size_t bytes = regs.rdx;
			SYSPRINT("WRITE to fd=%lld, data=0x%llX, size=%llu\n",
				regs.rdi, regs.rsi, regs.rdx);
			// TODO: Make proper tenant setting for file sizes
			if (fd == 1 || fd == 2) {
				if (bytes > 1024*64) {
					regs.rax = -1;
					cpu.set_registers(regs);
					return;
				}
			}
			else if (bytes > 1024*1024*4) {
				regs.rax = -1;
				cpu.set_registers(regs);
				return;
			}
			if (fd != 1 && fd != 2) {
				/* Use gather-buffers and writev */
				static constexpr size_t WRITEV_BUFFERS = 64;
				tinykvm::Machine::Buffer buffers[WRITEV_BUFFERS];
				const auto bufcount =
					cpu.machine().gather_buffers_from_range(WRITEV_BUFFERS, buffers, regs.rsi, bytes);

				/* Complain about writes outside of existing FDs */
				const int fd = cpu.machine().fds().translate(regs.rdi);
				regs.rax = writev(fd, (const struct iovec *)buffers, bufcount);
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
			if (regs.rdi >= 0 && regs.rdi < 3) {
				/* Silently ignore close on stdin/stdout/stderr */
				regs.rax = 0;
			} else {
				auto opt_entry = cpu.machine().fds().entry_for_vfd(regs.rdi);
				if (opt_entry.has_value()) {
					auto& entry = *opt_entry;
					if (!entry->is_forked) {
						const int res = close(entry->real_fd);
						cpu.machine().fds().free(regs.rdi);
						if (res < 0)
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
			SYSPRINT("CLOSE(fd=%lld) = %lld\n", regs.rdi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_stat, [] (vCPU& cpu) { // STAT
			auto& regs = cpu.registers();
			const auto vpath = regs.rdi;

			std::string path = cpu.machine().memcstring(vpath, PATH_MAX);
			if (!cpu.machine().fds().is_readable_path(path)) {
				regs.rax = -EACCES;
				SYSPRINT("STAT to path=%s, data=0x%llX = %lld\n",
					path.c_str(), regs.rsi, regs.rax);
				cpu.set_registers(regs);
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
			SYSPRINT("FSTAT to vfd=%lld, fd=%d, data=0x%llX = %lld\n",
				regs.rdi, fd, regs.rsi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_lstat, [] (vCPU& cpu) { // LSTAT
			auto& regs = cpu.registers();
			const auto vpath = regs.rdi;
			std::string path = cpu.machine().memcstring(vpath, PATH_MAX);
			if (!cpu.machine().fds().is_readable_path(path)) {
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
			SYSPRINT("LSTAT to path=%s, data=0x%llX = %lld\n",
				path.c_str(), regs.rsi, regs.rax);
			cpu.set_registers(regs);
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
		});
	Machine::install_syscall_handler(
		SYS_poll, [](vCPU& cpu) { // POLL
			auto& regs = cpu.registers();
			const size_t bytes = sizeof(pollfd) * regs.rsi;
			auto *fds = cpu.machine().template rw_memory_at<struct pollfd>(regs.rdi, bytes);
			std::vector<struct pollfd> host_pollfds;
			std::vector<unsigned> host_pollfd_indexes;
			for (size_t i = 0; i < regs.rsi; i++)
			{
				// stdout/stderr
				if (fds[i].fd == 1 || fds[i].fd == 2)
					fds[i].revents = fds[i].events;
				else {
					// Translate the fd
					const int fd = cpu.machine().fds().translate(fds[i].fd);
					host_pollfds.push_back({fd, fds[i].events, 0});
					host_pollfd_indexes.push_back(i);
				}
			}
			if (host_pollfds.empty()) {
				regs.rax = 0;
			} else {
				// Call poll on the host
				regs.rax = poll(host_pollfds.data(), host_pollfds.size(), 50);
				if (int(regs.rax) < 0) {
					regs.rax = -errno;
				} else {
					// Copy back the results
					const size_t count = std::min(size_t(regs.rax), size_t(host_pollfds.size()));
					for (size_t i = 0; i < count; i++)
					{
						const unsigned index = host_pollfd_indexes.at(i);
						fds[index].revents = host_pollfds[i].revents;
					}
				}
			}
			SYSPRINT("poll(0x%llX, %llu) = %lld\n",
					 regs.rsi, regs.rdi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_mmap, [](vCPU& cpu) { // MMAP
			auto& regs = cpu.registers();
			const uint64_t address = regs.rdi & ~PageMask;
			const uint64_t length = (regs.rsi + PageMask) & ~PageMask;
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
				if (address != 0x0 && address >= cpu.machine().mmap_start()) {
					dst = address;
					// If the mapping is within a certain range, we should adjust
					// the current mmap address to the end of the new mapping. This is
					// to avoid future collisions when allocating.
					if (address >= cpu.machine().mmap_current() && address + length <= cpu.machine().mmap_current() + MMAP_COLLISION_TRESHOLD)
					{
						PRINTMMAP("Adjusting mmap current address to 0x%lX\n",
							address + length);
						cpu.machine().mmap() = address + length;
					} else {
						PRINTMMAP("Not adjusting mmap current address to 0x%lX\n",
							address + length);
					}
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
				PRINTMMAP("mmap(0x%lX (0x%llX), %lu, prot=%llX, flags=%llX) = 0x%llX\n",
						  address, regs.rdi, read_length, regs.rdx, regs.r10, regs.rax);
				cpu.set_registers(regs);
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
				if constexpr (true)
				{
					auto range = cpu.machine().mmap_cache().find(length);
					// Not found in cache, allocate new range
					if (range.empty())
					{
						regs.rax = cpu.machine().mmap_allocate(length);
					}
					else
					{
						// PRINTMMAP("Found existing range: 0x%lX -> 0x%lX\n",
						//	range.addr, range.addr + range.size);
						regs.rax = range.addr;
					}
				}
				else
				{
					regs.rax = cpu.machine().mmap_allocate(length);
				}
			}
			/* If MAP_ANON is set, the memory must be zeroed. memzero() will only
			   zero the pages that are dirty, preventing RSS from exploding. */
			if ((flags & MAP_ANON) != 0 && regs.rax != ~0ULL)
			{
				cpu.machine().memzero(regs.rax, length);
			}
			PRINTMMAP("mmap(0x%lX, %lu, prot=%llX, flags=%llX) = 0x%llX\n",
					  address, length, regs.rdx, regs.r10, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_mprotect, [](vCPU& cpu) { // MPROTECT
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
		SYS_munmap, [](vCPU &cpu) { // MUNMAP
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
			SYSPRINT("brk(0x%llX) = 0x%llX\n", regs.rdi, regs.rax);
			cpu.set_registers(regs);
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
			SYSPRINT("rt_sigprocmask(how=%x, set=0x%lX, oldset=0x%lx, size=%u) = 0x%llX\n",
					 how, g_set, g_oldset, size, regs.rax);
			cpu.set_registers(regs);
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
			SYSPRINT("sigaltstack(ss=0x%llX, old_ss=0x%llx) = 0x%llX\n",
				regs.rdi, regs.rsi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler( // ioctl
		SYS_ioctl, [](vCPU& cpu) {
			auto& regs = cpu.registers();
			const int fd = cpu.machine().fds().translate(regs.rdi);
			switch (regs.rsi) {
			case 0x5401: /* TCGETS */
				if (int(regs.rdi) >= 0 && int(regs.rdi) < 3)
					regs.rax = 0;
				else
					regs.rax = -EPERM;
				break;
			case 0x5413: /* TIOCGWINSZ */
				regs.rax = 80;
				break;
			case FIONREAD:
				{
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
				regs.rax = EINVAL;
			}
			SYSPRINT("ioctl(vfd=%lld fd=%d, req=0x%llx) = 0x%llX\n",
					 regs.rdi, fd, regs.rsi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_pread64, [](vCPU& cpu) {
			auto& regs = cpu.registers();
			const int vfd = regs.rdi;
			const auto g_buf = regs.rsi;
			const auto bytes = regs.rdx;
			const auto offset = regs.r10;
			const int fd = cpu.machine().fds().translate(vfd);

			// Readv into the area
			static constexpr size_t READV_BUFFERS = 64;
			tinykvm::Machine::WrBuffer buffers[READV_BUFFERS];
			const auto bufcount =
				cpu.machine().writable_buffers_from_range(READV_BUFFERS, buffers, g_buf, bytes);

			if (preadv64(fd, (const iovec *)&buffers[0], bufcount, offset) < 0) {
				regs.rax = -errno;
			}
			else {
				regs.rax = bytes;
			}
			SYSPRINT("pread64(fd=%d, buf=0x%llX, size=%llu, offset=%llu) = %lld\n",
					 vfd, g_buf, bytes, offset, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_writev, [](vCPU& cpu) {
			/* SYS writev */
			auto& regs = cpu.registers();
			struct g_iovec
			{
				uint64_t iov_base;
				size_t iov_len;
			};
			const int vfd = regs.rdi;
			const auto count = regs.rdx;

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
			}
			else
			{
				auto opt_entry = cpu.machine().fds().entry_for_vfd(vfd);
				if (opt_entry.has_value() && (*opt_entry)->is_writable)
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

						ssize_t result = writev((*opt_entry)->real_fd,
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
			SYSPRINT("writev(%d) = %lld\n",
					 vfd, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_access, [](vCPU& cpu) { // ACCESS
			auto& regs = cpu.registers();
			regs.rax = -EPERM;
			SYSPRINT("access(0x%llX 0x%llX) = %lld\n",
					 regs.rdi, regs.rsi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_pipe2, [](vCPU& cpu) { // PIPE2
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("pipe2(0x%llX, 0x%X) = %lld\n",
					 regs.rdi, int(regs.rsi), regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_mremap, [](vCPU& cpu) { // MREMAP
			auto& regs = cpu.registers();
			auto &mm = cpu.machine().mmap();
			uint64_t old_addr = regs.rdi & ~(uint64_t)0xFFF;
			uint64_t old_len = (regs.rsi + 0xFFF) & ~(uint64_t)0xFFF;
			uint64_t new_len = (regs.rdx + 0xFFF) & ~(uint64_t)0xFFF;
			unsigned flags = regs.r10;

			if (old_addr + old_len == mm)
			{
				mm = old_addr + new_len;
				regs.rax = old_addr;
			}
			else if (flags & MREMAP_FIXED)
			{
				// We don't support MREMAP_FIXED
				regs.rax = ~0LL; /* MAP_FAILED */
			}
			else if (flags & MREMAP_MAYMOVE)
			{
				uint64_t new_addr = cpu.machine().mmap_allocate(new_len);
				regs.rax = new_addr;
				// Copy the old data to the new location
				cpu.machine().foreach_memory(old_addr, old_len,
											 [&cpu, &new_addr](std::string_view buffer)
											 {
												 cpu.machine().copy_to_guest(new_addr, buffer.data(), buffer.size());
												 new_addr += buffer.size();
											 });
				// Unmap the old range
				cpu.machine().mmap_unmap(old_addr, old_len);
			}
			else
			{
				// We don't support other flags
				regs.rax = ~0LL; /* MAP_FAILED */
			}
			PRINTMMAP("mremap(0x%llX, %llu, %llu, flags=0x%X) = 0x%llX\n",
					  regs.rdi, regs.rsi, regs.rdx, flags, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_mincore, [](vCPU& cpu) { // mincore
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			SYSPRINT("mincore(0x%llX, %llu, 0x%llX) = %lld\n",
					 regs.rdi, regs.rsi, regs.rdx, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_madvise, [](vCPU& cpu) { // MADVISE
			auto& regs = cpu.registers();
			regs.rax = 0;
			PRINTMMAP("madvise(0x%llX, %llu, 0x%llx) = %lld\n",
					  regs.rdi, regs.rsi, regs.rdx, regs.rax);
			if (regs.rdx == MADV_DONTNEED)
			{
				// MADV_DONTNEED
				/// XXX: TODO: Memdiscard the pages
				// cpu.machine().memzero(regs.rdi, regs.rsi);
			}
			cpu.set_registers(regs);
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
			SYSPRINT("dup(vfd=%lld fd=%d) = %lld\n",
					 regs.rdi, fd, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_nanosleep, [](vCPU& cpu) { // nanosleep
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("nanosleep(...) = %lld\n",
					 regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_getpid, [](vCPU& cpu) { // GETPID
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("getpid() = %lld\n", regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_socket, [](vCPU& cpu) { // SOCKET
			auto& regs = cpu.registers();
			// int socket(int domain, int type, int protocol);
			const int domain = regs.rdi;
			const int type = regs.rsi;
			const int protocol = regs.rdx;
			const int fd = socket(domain, type, protocol);
			if (fd < 0)
			{
				regs.rax = -errno;
			}
			else
			{
				regs.rax = cpu.machine().fds().manage(fd, true, true);
			}
			SYSPRINT("socket(%d, %d, %d) = %lld\n",
					 domain, type, protocol, regs.rax);
			cpu.set_registers(regs);
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
			if (optlen > optval.size())
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
			SYSPRINT("setsockopt(fd=%d, level=%d, optname=%d, optval=0x%lX, optlen=%zu) = %lld\n",
					 fd, level, optname, g_optval, optlen, regs.rax);
			cpu.set_registers(regs);
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
			if (getsockopt(fd, level, optname, optval.data(), &optlen_out) < 0) {
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
			SYSPRINT("getsockopt(fd=%d, level=%d, optname=%d, optval=0x%lX, optlen=0x%lX) = %lld\n",
					 fd, level, optname, g_optval, g_optlen, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_connect, [](vCPU& cpu) { // CONNECT
			auto& regs = cpu.registers();
			// int connect(int sockfd, const struct sockaddr *addr,
			//             socklen_t addrlen);
			const int fd = cpu.machine().fds().translate(regs.rdi);
			const uint64_t g_addr = regs.rsi;
			const size_t addrlen = regs.rdx;
			struct sockaddr addr {};
			if (addrlen > sizeof(addr))
			{
				regs.rax = -EINVAL;
			} else {
				cpu.machine().copy_from_guest(&addr, g_addr, addrlen);
				// Validate the address
				if (!cpu.machine().fds().validate_socket_address(fd, addr))
				{
					regs.rax = -EPERM;
				} else {
					if (connect(fd, &addr, addrlen) < 0) {
						regs.rax = -errno;
					}
					else {
						regs.rax = 0;
					}
				}
			}
			SYSPRINT("connect(fd=%d, addr=0x%lX, addrlen=%zu) = %lld\n",
					 fd, g_addr, addrlen, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_bind, [](vCPU& cpu) { // BIND
			auto& regs = cpu.registers();
			// int bind(int sockfd, const struct sockaddr *addr,
			//           socklen_t addrlen);
			const int fd = cpu.machine().fds().translate(regs.rdi);
			const uint64_t g_addr = regs.rsi;
			const size_t addrlen = regs.rdx;
			struct sockaddr addr {};
			if (addrlen > sizeof(addr))
			{
				regs.rax = -EINVAL;
				cpu.set_registers(regs);
				return;
			}
			cpu.machine().copy_from_guest(&addr, g_addr, addrlen);
			// Validate the address
			if (!cpu.machine().fds().validate_socket_address(fd, addr))
			{
				regs.rax = -EPERM;
			} else {
				if (bind(fd, &addr, addrlen) < 0) {
					regs.rax = -errno;
				}
				else {
					regs.rax = 0;
				}
			}
			SYSPRINT("bind(fd=%d, addr=0x%lX, addrlen=%zu) = %lld\n",
					 fd, g_addr, addrlen, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_getsockname, [](vCPU& cpu) { // GETSOCKNAME
			auto& regs = cpu.registers();
			// int getsockname(int sockfd, struct sockaddr *addr,
			//                  socklen_t *addrlen);
			const int fd = cpu.machine().fds().translate(regs.rdi);
			const uint64_t g_addr = regs.rsi;
			const size_t g_addrlen = regs.rdx;
			struct sockaddr addr {};
			socklen_t addrlen = sizeof(addr);
			if (getsockname(fd, &addr, &addrlen) < 0)
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
		});
	Machine::install_syscall_handler(
		SYS_socketpair, [](vCPU& cpu) { // SOCKETPAIR
			auto& regs = cpu.registers();
			// int socketpair(int domain, int type, int protocol, int sv[2]);
			const uint64_t g_sv = regs.r10;
			int sv[2] = { 0, 0 };
			const int res = socketpair(AF_UNIX, SOCK_STREAM, 0, sv);
			if (res < 0)
			{
				regs.rax = -errno;
			}
			else
			{
				sv[0] = cpu.machine().fds().manage(sv[0], true, true);
				sv[1] = cpu.machine().fds().manage(sv[1], true, true);
				cpu.machine().copy_to_guest(g_sv, sv, sizeof(sv));
				regs.rax = 0;
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
			try {
				const int fd = cpu.machine().fds().translate(regs.rdi);
				regs.rax = ::shutdown(fd, regs.rsi);
				if (int(regs.rax) < 0)
					regs.rax = -errno;
			} catch (...) {
				regs.rax = -EBADF;
			}
			SYSPRINT("SHUTDOWN(fd=%lld) = %lld\n",
				regs.rdi, regs.rax);
			cpu.set_registers(regs);
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
				if (bytes > 512UL << 20) // 512MB
				{
					// Ignore too large buffers
					regs.rax = -ENOMEM;
					cpu.set_registers(regs);
					return;
				}
				if (addrlen > sizeof(struct sockaddr))
				{
					regs.rax = -EINVAL;
					cpu.set_registers(regs);
					return;
				}
				fd = cpu.machine().fds().translate(vfd);
				// Gather memory buffers from the guest
				std::array<tinykvm::Machine::Buffer, 256> buffers;
				const auto bufcount =
					cpu.machine().gather_buffers_from_range(buffers.size(), buffers.data(), g_buf, bytes);

				if (addrlen > 0 && g_addr != 0x0) {
					struct sockaddr addr {};
					cpu.machine().copy_from_guest(&addr, g_addr, addrlen);
					// Can't use writev here, because we need to send the address too
					ssize_t total = 0;
					for (size_t i = 0; i < bufcount; i++)
					{
						// TODO: Use sendmsg() instead of sendto()
						ssize_t result = sendto(fd, buffers[i].ptr, buffers[i].len, flags, &addr, addrlen);
						if (result < 0)
						{
							total = -errno;
							break;
						}
						total += result;
					}
					regs.rax = total;
				}
				else {
					// Use writev
					ssize_t result = writev(fd, (const iovec *)&buffers[0], bufcount);
					if (result < 0) {
						regs.rax = -errno;
					}
					else {
						regs.rax = result;
					}
				}
			} catch (...) {
				regs.rax = -EBADF;
			}
			SYSPRINT("sendto(fd=%d (%d), buf=0x%lX, len=%lu, flags=0x%X, dest_addr=0x%lX, addrlen=%zu) = %lld\n",
					 vfd, fd, g_buf, bytes, flags, g_addr, addrlen, regs.rax);
			cpu.set_registers(regs);
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
				if (bytes > 64UL << 20) // 64MB
				{
					// Ignore too large buffers
					regs.rax = -ENOMEM;
					cpu.set_registers(regs);
					return;
				}
				fd = cpu.machine().fds().translate(vfd);
				std::vector<uint8_t> buf(bytes);
				struct sockaddr addr {};
				socklen_t addrlen = sizeof(addr);
				ssize_t result = recvfrom(fd, buf.data(), bytes, flags, &addr, &addrlen);
				if (result < 0)
				{
					regs.rax = -errno;
				}
				else
				{
					if (g_addrlen != 0x0) {
						cpu.machine().copy_to_guest(g_addrlen, &addrlen, sizeof(addrlen));
						cpu.machine().copy_to_guest(g_addr, &addr, addrlen);
					}
					// Copy the data to guest memory
					if (g_buf != 0x0 && result > 0)
					{
						cpu.machine().copy_to_guest(g_buf, buf.data(), result);
					}
					regs.rax = result;
				}
			} catch (...) {
				regs.rax = -EBADF;
			}
			SYSPRINT("recvfrom(fd=%d (%d), buf=0x%lX, len=%lu, flags=0x%X, src_addr=0x%lX, addrlen=0x%lX) = %lld\n",
					 vfd, fd, g_buf, bytes, flags, g_addr, g_addrlen, regs.rax);
			cpu.set_registers(regs);
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
					return;
				}
				// Copy the iovecs from guest memory
				const uint64_t g_iov = (uintptr_t)msg.msg_iov;
				cpu.machine().copy_from_guest(iovecs.data(), g_iov, msg.msg_iovlen * sizeof(GuestIOvec));
				// Calculate the total size of the buffers
				size_t total = 0;
				for (size_t i = 0; i < msg.msg_iovlen; i++)
				{
					if (total + iovecs[i].iov_len < total) {
						throw std::overflow_error("size_t overflow");
					}
					total += iovecs[i].iov_len;
				}
				if (total > 64UL << 20) // 64MB
				{
					// Ignore too large buffers
					regs.rax = -ENOMEM;
					cpu.set_registers(regs);
					return;
				}
				std::vector<uint8_t> buf(total);
				struct sockaddr addr {};
				socklen_t addrlen = sizeof(addr);
				ssize_t result = recvfrom(fd, buf.data(), total, flags, &addr, &addrlen);
				if (result < 0) {
					regs.rax = -errno;
				}
				else
				{
					// Copy the data to guest memory by going through the iovecs
					size_t offset = 0;
					for (size_t i = 0; i < msg.msg_iovlen; i++)
					{
						auto& iov = iovecs.at(i);
						size_t len_remaining = std::min(size_t(result - offset), size_t(iov.iov_len));
						if (offset + len_remaining > buf.size())
						{
							regs.rax = -EINVAL;
							cpu.set_registers(regs);
							return;
						}
						cpu.machine().copy_to_guest(iov.iov_base, buf.data() + offset, len_remaining);
						offset += iov.iov_len;
						if (offset >= size_t(result)) {
							break;
						}
					}
					// Copy the msg_name and msg_namelen back to guest memory
					const uint64_t g_name = (uintptr_t)msg.msg_name;
					if (g_name != 0x0)
					{
						cpu.machine().copy_to_guest(g_name, &addr, addrlen);
					}
					regs.rax = result;
				}
			} catch (const std::exception& e) {
				regs.rax = -EBADF;
			}
			SYSPRINT("recvmsg(fd=%d (%d), msg=0x%lX, flags=0x%X) = %lld\n",
					 vfd, fd, g_msg, flags, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_uname, [](vCPU& cpu) { // UTSNAME
			auto& regs = cpu.registers();
			if (cpu.machine().memory_safe_at(regs.rdi, sizeof(struct utsname)))
			{
				struct utsname uts{};
				strcpy(uts.sysname, "Linux");
				strcpy(uts.release, "3.2.0");
				cpu.machine().copy_to_guest(regs.rdi, &uts, sizeof(uts));
				regs.rax = 0;
			}
			else
			{
				SYSPRINT("SYSCALL utsname failed on 0x%llX\n", regs.rdi);
				regs.rax = -EFAULT;
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_fcntl, [](vCPU& cpu) { // FCNTL
			auto& regs = cpu.registers();
			const int vfd = regs.rdi;
			try {
				[[maybe_unused]] int fd = cpu.machine().fds().translate(vfd);
				const int cmd = regs.rsi;
				regs.rax = 0;
				if (cmd == F_GETFD)
				{
					//const int flags = fcntl(fd, cmd);
					regs.rax = 0x1;
				}
				else if (cmd == F_DUPFD_CLOEXEC)
				{
					const int new_fd = dup(fd);
					const int new_vfd = cpu.machine().fds().manage(new_fd, false, false);
					regs.rax = new_vfd;
				}
			} catch (...) {
				regs.rax = -EBADF;
			}
			SYSPRINT("fcntl(%d, ...) = %lld\n",
					 vfd, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_getcwd, [](vCPU& cpu) { // GETCWD
			auto& regs = cpu.registers();

			const char fakepath[] = "/";
			if (sizeof(fakepath) <= regs.rsi) {
				cpu.machine().copy_to_guest(regs.rdi, fakepath, sizeof(fakepath));
				regs.rax = regs.rdi;
			} else {
				regs.rax = 0;
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_mkdir, [](vCPU& cpu) { // MKDIR
			auto& regs = cpu.registers();
			regs.rax = -EPERM;
			SYSPRINT("mkdir(0x%llX, 0x%llX) = %lld\n",
					 regs.rdi, regs.rsi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_readlink, [](vCPU& cpu) { // READLINK
			auto& regs = cpu.registers();
			regs.rax = -ENOENT;
			SYSPRINT("readlink(0x%llX, bufd=0x%llX, size=%llu) = %lld\n",
					 regs.rdi, regs.rsi, regs.rdx, regs.rax);
			cpu.set_registers(regs);
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
			SYSPRINT("unlink(%s (0x%llX)) = %lld\n",
					 path.c_str(), regs.rdi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_gettimeofday, [](vCPU& cpu) { // gettimeofday
			auto& regs = cpu.registers();
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
			SYSPRINT("gettimeofday(buf=0x%llX) = %lld\n",
					 regs.rdi, regs.rax);
			cpu.set_registers(regs);
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
		});
	Machine::install_syscall_handler(
		SYS_getpgrp, [](vCPU& cpu) { // GETPGRP
			auto& regs = cpu.registers();
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_getgroups, [](vCPU& cpu) { // GETGROUPS
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			SYSPRINT("getgroups(...) = %lld\n", regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler( // sched_getparam
		SYS_sched_getparam, [](vCPU& cpu)
		{
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("sched_getparam(...) = %lld\n", regs.rax);
			cpu.set_registers(regs); });
	Machine::install_syscall_handler( // sched_getscheduler
		SYS_sched_getscheduler, [](vCPU& cpu)
		{
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("sched_getscheduler(...) = %lld\n", regs.rax);
			cpu.set_registers(regs); });
	Machine::install_syscall_handler(
		SYS_prctl, [](vCPU& cpu)
		{
			/* SYS prctl */
			auto& regs = cpu.registers();
			const int option = regs.rdi;
			(void)option;

			regs.rax = 0;
			SYSPRINT("prctl(opt=%d) = %lld\n", option, regs.rax);
			cpu.set_registers(regs); });
	Machine::install_syscall_handler(
		SYS_arch_prctl, [](vCPU& cpu)
		{
			/* SYS arch_prctl */
			auto& regs = cpu.registers();
			[[maybe_unused]] static constexpr long ARCH_SET_GS = 0x1001;
			[[maybe_unused]] static constexpr long ARCH_SET_FS = 0x1002;
			[[maybe_unused]] static constexpr long ARCH_GET_FS = 0x1003;
			[[maybe_unused]] static constexpr long ARCH_GET_GS = 0x1004;
			SYSPRINT("SYSCALL ARCH_PRCTL opt=0x%llX\n", regs.rdi);
			regs.rax = -22; // EINVAL
			cpu.set_registers(regs); });
	Machine::install_syscall_handler(
		SYS_tkill, [](auto &) { // tkill
			/* Normally, we would invoke signal w/altstack here */
			throw MachineException("TKILL system call received");
		});
	Machine::install_syscall_handler(
		SYS_time, [](vCPU& cpu) { // time
			auto& regs = cpu.registers();
			regs.rax = time(NULL);
			SYSPRINT("time(NULL) = %lld\n", regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_sched_getaffinity, [](vCPU& cpu) { // sched_getaffinity
			/* SYS sched_getaffinity */
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("sched_getaffinity() = %lld\n", regs.rax);
			cpu.set_registers(regs);
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
			SYSPRINT("GETDENTS64 to vfd=%lld, fd=%d, data=0x%llX = %lld\n",
				regs.rdi, fd, regs.rsi, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_clock_gettime, [](vCPU& cpu) { // clock_gettime
			auto& regs = cpu.registers();
			struct timespec ts;
			regs.rax = clock_gettime(CLOCK_MONOTONIC, &ts);
			if (int(regs.rax) < 0)
				regs.rax = -errno;
			else
				cpu.machine().copy_to_guest(regs.rsi, &ts, sizeof(ts));
			SYSPRINT("clock_gettime(clk=%lld, buf=0x%llX) = %lld\n",
					 regs.rdi, regs.rsi, regs.rax);
			cpu.set_registers(regs);
			//cpu.machine().threads().suspend_and_yield();
		});
	Machine::install_syscall_handler(
		SYS_clock_nanosleep, [](vCPU& cpu) { // clock_nanosleep
			auto& regs = cpu.registers();
			// We don't allow sleeping in the guest
			// but we can set the remaining time to the requested value
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
			SYSPRINT("clock_nanosleep(clk=%lld, flags=%lld, req=0x%llX, rem=%lld) = %lld\n",
					 regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.rax);
			cpu.set_registers(regs);
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
					int pfd = AT_FDCWD;
					if (vfd != AT_FDCWD) {
						pfd = cpu.machine().fds().translate(vfd);
					}
					real_path = path;
					if (!cpu.machine().fds().is_readable_path(real_path)) {
						throw std::runtime_error("Path not readable: " + real_path);
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
					int pfd = AT_FDCWD;
					if (vfd != AT_FDCWD) {
						pfd = cpu.machine().fds().translate(vfd);
					}

					real_path = path;
					if (!cpu.machine().fds().is_writable_path(real_path)) {
						SYSPRINT("OPENAT path was not writable: %s\n", real_path.c_str());
						throw std::runtime_error("Path not writable: " + real_path);
					}

					int fd = openat(pfd, real_path.c_str(), flags, S_IWUSR | S_IRUSR);
					SYSPRINT("OPENAT where=%lld path=%s (real_path=%s) flags=%X = fd %d\n",
						regs.rdi, path.c_str(), real_path.c_str(), flags, fd);

					if (fd > 0) {
						regs.rax = cpu.machine().fds().manage(fd, false);
					} else {
						regs.rax = -errno;
					}
				} catch (...) {
					regs.rax = -1;
				}
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_newfstatat, [] (vCPU& cpu) { // NEWFSTATAT
			auto& regs = cpu.registers();
			const auto vpath  = regs.rsi;
			const auto buffer = regs.rdx;
			int flags  = AT_SYMLINK_NOFOLLOW; // regs.r10;
			int fd = AT_FDCWD;
			std::string path;

			try {
				path = cpu.machine().memcstring(vpath, PATH_MAX);

				if (int(regs.rdi) >= 0) {
					// Use existing vfd
					fd = cpu.machine().fds().translate(int(regs.rdi));
				} else {
					// Use AT_FDCWD
					fd = AT_FDCWD;
				}

				if (!cpu.machine().fds().is_readable_path(path) && !path.empty()) {
					regs.rax = -EPERM;
				} else {
					// If path is empty, use AT_EMPTY_PATH to operate on the fd
					flags = (path.empty() && fd != AT_FDCWD) ? AT_EMPTY_PATH : 0;

					struct stat64 vstat;
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

			SYSPRINT("NEWFSTATAT to vfd=%lld, fd=%d, path=%s, data=0x%llX, flags=0x%X = %lld\n",
				regs.rdi, fd, path.c_str(), buffer, flags, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_set_robust_list, [](vCPU& cpu)
		{
			/* SYS set_robust_list */
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			SYSPRINT("set_robust_list(...) = %lld\n", regs.rax);
			cpu.set_registers(regs); });
	Machine::install_syscall_handler(
		SYS_eventfd2, [](vCPU& cpu)
		{
			/* SYS eventfd2 */
			auto& regs = cpu.registers();
			const int real_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
			const int vfd = cpu.machine().fds().manage(real_fd, false);
			if (vfd < 0) {
				regs.rax = -errno;
			}
			else {
				regs.rax = vfd;
			}
			SYSPRINT("eventfd2(...) = %d (%lld)\n",
				real_fd, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_epoll_create1, [](vCPU& cpu)
		{
			/* SYS epoll_create1 */
			auto& regs = cpu.registers();
			const int fd = epoll_create1(0);
			if (fd < 0)
			{
				regs.rax = -errno;
			}
			else
			{
				const int vfd = cpu.machine().fds().manage(fd, false);
				regs.rax = vfd;
			}
			SYSPRINT("epoll_create1() = %d (%lld)\n", fd, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_nanosleep, [](vCPU& cpu)
		{
			/* SYS nanosleep */
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("nanosleep(...) = %lld\n", regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler( // epoll_ctl
		SYS_epoll_ctl, [](vCPU& cpu)
		{
			auto& regs = cpu.registers();
			const int epollfd = cpu.machine().fds().translate_unless_forked(regs.rdi);
			const int op = regs.rsi;
			const int fd = cpu.machine().fds().translate(regs.rdx);
			const uint64_t g_event = regs.r10;
			if (epollfd > 0 && fd > 0)
			{
				struct epoll_event event {};
				if (g_event != 0x0) {
					cpu.machine().copy_from_guest(&event, g_event, sizeof(event));
				}
				if (epoll_ctl(epollfd, op, fd, &event) < 0) {
					regs.rax = -errno;
				}
				else {
					regs.rax = 0;
				}
			} else {
				regs.rax = -EBADF;
			}
			SYSPRINT("epoll_ctl(epollfd=%d (%lld), op=%d, fd=%d (%lld), g_event=0x%lX) = %lld\n",
				epollfd, regs.rdi, op, fd, regs.rdx, g_event, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler( // epoll_wait
		SYS_epoll_wait, [](vCPU& cpu)
		{
			auto& regs = cpu.registers();
			const int vfd = regs.rdi;
			[[maybe_unused]] const uint64_t g_events = regs.rsi;
			[[maybe_unused]] const int maxevents = regs.rdx;
			[[maybe_unused]] const int timeout = regs.r10;
			if (maxevents > 1024)
			{
				regs.rax = -EINVAL;
				SYSPRINT("epoll_wait(fd=%d maxevents=%d timeout=%d) = %lld\n",
					vfd, maxevents, timeout, regs.rax);
				cpu.set_registers(regs);
				return;
			}
			std::array<struct epoll_event, 1024> guest_events;
			// Only wait for 15us, as we are *not* pre-empting the guest
			const struct timespec ts {
				.tv_sec = 0,
				.tv_nsec = 250000,
			};
			const int epollfd = cpu.machine().fds().translate(vfd);
			const int result =
				epoll_pwait2(epollfd, guest_events.data(), maxevents, &ts, nullptr);
			// Copy events back to guest
			if (result > 0)
			{
				cpu.machine().copy_to_guest(g_events, guest_events.data(),
					result * sizeof(struct epoll_event));
				regs.rax = result;
			}
			else if (result < 0)
			{
				regs.rax = -errno;
			}
			else
			{
				regs.rax = 0;
				// XXX: This is a giga hack.
				cpu.machine().threads().suspend_and_yield();
			}
			SYSPRINT("epoll_wait(fd=%d (%lld), g_events=0x%lX, maxevents=%d, timeout=%d) = %lld\n",
				vfd, regs.rdi, g_events, maxevents, timeout, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_getrlimit, [](vCPU& cpu) { // getrlimit
			auto& regs = cpu.registers();
			[[maybe_unused]] const auto g_rlim = regs.rsi;
			regs.rax = -ENOSYS;
			SYSPRINT("getrlimit(0x%llX) = %lld\n", g_rlim, regs.rax);
			cpu.set_registers(regs);
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
					lim.rlim_cur = 4096;
					lim.rlim_max = 4096;
					SYSPRINT("prlimit64: current nofile limit 0x%lX max 0x%lX\n",
						lim.rlim_cur, lim.rlim_max);
					cpu.machine().copy_to_guest(oldptr, &lim, sizeof(lim));
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
		SYS_sendmmsg, [](vCPU& cpu) { // sendmmsg
			auto& regs = cpu.registers();
			const int fd = cpu.machine().fds().translate(regs.rdi);
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
			SYSPRINT("sendmmsg(fd=%d, buf=0x%lX, count=%d) = %lld\n",
					 fd, g_buf, vcnt, regs.rax);
			cpu.set_registers(regs);
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
			SYSPRINT("getrandom(buf=0x%lX bytes=%u flags=%X) = %lld\n",
					 g_buf, bytes, flags, regs.rax);
			cpu.set_registers(regs);
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
			int fd = AT_FDCWD;

			try {
				path = cpu.machine().memcstring(vpath, PATH_MAX);
				if (!path.empty()) {
					if (!cpu.machine().fds().is_readable_path(path)) {
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

			SYSPRINT("STATX to vfd=%lld, fd=%d, path=%s, data=0x%llX, flags=0x%llX, mask=0x%llX = %lld\n",
				regs.rdi, fd, path.c_str(), buffer, flags, mask, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_readlinkat, [](vCPU& cpu) { // READLINKAT
			auto& regs = cpu.registers();
			const int  vfd      = regs.rdi;
			const auto vpath    = regs.rsi;
			const auto g_buffer = regs.rdx;
			//const int  flags    = regs.r8;
			std::string path;
			try {
				path = cpu.machine().memcstring(vpath, PATH_MAX);
				if (!cpu.machine().fds().is_readable_path(path)) {
					regs.rax = -EPERM;
				} else {
					int fd = vfd;
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
			SYSPRINT("readlinkat(0x%llX, bufd=0x%llX, size=%llu) = %lld\n",
					 regs.rdi, regs.rsi, regs.rdx, regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_faccessat, [](vCPU& cpu) { // faccessat
			auto& regs = cpu.registers();
			regs.rax = -ENOSYS;
			SYSPRINT("faccessat(...) = %lld\n",
					 regs.rax);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		SYS_rseq, [](vCPU& cpu) { // rseq
			auto& regs = cpu.registers();
			regs.rax = 0;
			SYSPRINT("rseq(...) = %lld\n",
					 regs.rax);
			cpu.set_registers(regs);
		});

	// Threads: clone, futex, block/tkill etc.
	Machine::setup_multithreading();
}

} // tinykvm
