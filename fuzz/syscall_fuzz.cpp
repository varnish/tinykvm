/**
 * Coverage-guided fuzzer for the host-side Linux syscall emulation layer
 * (lib/tinykvm/linux/system_calls.cpp and friends).
 *
 * Threat model: the guest is untrusted. Its only channel into the host
 * process is the syscall trampoline, which lands in Machine::system_call()
 * with six fully guest-controlled 64-bit register arguments, several of
 * which are pointers into guest memory whose *contents* the guest also
 * controls. This harness reproduces exactly that: it drives
 * Machine::system_call() directly on a forked VM, so no VM entry is
 * needed and the interesting code -- the ~112 hand-written handlers --
 * runs under ASan/UBSan at native speed.
 *
 * Input grammar (little-endian, truncation-tolerant):
 *
 *   record := op:u8 payload
 *     (op & 3) == 0  -> POKE   sel:u8 off:i16 len:u8 bytes[len]
 *     otherwise      -> CALL   sysno:u16 arg[6]
 *     arg  := kind:u8 payload
 *       kind & 3 == 0 -> u8               (small ints: fds, flags, counts)
 *       kind & 3 == 1 -> u64              (fully arbitrary)
 *       kind & 3 == 2 -> sel:u8 off:i16   (guest pointer from the address table)
 *       kind & 3 == 3 -> sel:u8           (interesting constant)
 *
 * POKE writes fuzzer-chosen bytes into guest memory, which is what makes
 * the pointer arguments worth anything: most handlers read structs
 * (iovec, sockaddr, pollfd, timespec, path strings) out of the guest.
 * The address table is deliberately stocked with page boundaries,
 * end-of-mapping addresses and unmapped holes, because uniformly random
 * 64-bit pointers just bounce off copy_from_guest() and coverage stalls.
 *
 * Environment:
 *   TINYKVM_FUZZ_STRICT=1   treat any non-MachineException escaping a
 *                           handler as a finding (abort). Off by default so
 *                           a single easily-reached std::out_of_range does
 *                           not wall off the rest of the search space.
 *   TINYKVM_FUZZ_UNSAFE=1   install the "unsafe" syscall set.
 *   TINYKVM_FUZZ_VERBOSE=1  trace every call (debugging the harness only).
 */
#include <tinykvm/machine.hpp>

#include <csignal>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <set>
#include <string>
#include <sys/stat.h>
#include <typeinfo>
#include <unistd.h>
#include <vector>

#include "helpers.cpp"

using namespace tinykvm;

static constexpr uint64_t MAX_MEMORY  = 32ull << 20; /* 32MB */
static constexpr uint64_t MAX_COW_MEM = 8ull << 20;  /* 8MB per fork */
static constexpr size_t   MAX_RECORDS = 24;

/* NB: deliberately no __asan_on_error()/abort() hook here (unlike fuzz.cpp).
   Aborting from the callback runs *before* the sanitizer prints its report,
   which loses the stack trace. Use ASAN_OPTIONS=abort_on_error=1 if a
   coredump is wanted. */

static Machine* g_master = nullptr;
static Machine* g_fork   = nullptr;
static bool g_strict  = false;
static bool g_verbose = false;

static std::string g_sandbox_dir;
static std::string g_sandbox_ro;
static std::string g_sandbox_rw;

static std::vector<uint64_t> g_addrs;

/* ------------------------------------------------------------------ */
/* Syscalls we refuse to issue.                                       */
/*                                                                    */
/* Only two reasons qualify: the handler can block the host for a      */
/* guest-controlled duration (which shows up as a fuzzer timeout and   */
/* drowns out real findings), or it has a side effect outside the      */
/* sandbox. Everything else stays enabled -- including the whole       */
/* mmap/mprotect/thread/fd surface, which is the interesting part.     */
/* ------------------------------------------------------------------ */
static bool blocked_syscall(unsigned no)
{
	switch (no) {
	/* Blocking waits. None of these currently has a handler -- they fall
	   through to the unhandled path and return -ENOSYS -- so refusing them
	   costs no coverage today and guards against a future handler that would
	   block a worker. accept4 and clock_nanosleep *do* have handlers and are
	   deliberately NOT here: both are made safe by wrappers instead, so their
	   bodies still get covered (see install_nonblocking_wrappers). */
	case 23:  /* select */
	case 34:  /* pause */
	case 61:  /* wait4 */
	case 128: /* rt_sigtimedwait */
	case 247: /* waitid */
	case 270: /* pselect6 */
	case 43:  /* accept */
	/* Actually allocates disk blocks. */
	case 285: /* fallocate */
	/* Process-level side effects. Not installed today; refuse anyway so a
	   future handler cannot surprise a running campaign. */
	case 57:  /* fork */
	case 58:  /* vfork */
	case 59:  /* execve */
	case 101: /* ptrace */
	case 165: /* mount */
	case 166: /* umount2 */
	case 169: /* reboot */
	case 322: /* execveat */
		return true;
	default:
		return false;
	}
}

/* ------------------------------------------------------------------ */
/* Make guest-created fds non-blocking.                               */
/*                                                                    */
/* read()/recvfrom() on a guest-created pipe or datagram socket would  */
/* otherwise block forever. Rather than blocklisting the read family   */
/* (which is prime attack surface) we wrap the four handlers that mint */
/* fds and set O_NONBLOCK on the real fd afterwards. The original      */
/* handler still runs, so its coverage is unaffected.                  */
/* ------------------------------------------------------------------ */
static Machine::syscall_t g_orig_socket;
static Machine::syscall_t g_orig_pipe2;
static Machine::syscall_t g_orig_socketpair;
static Machine::syscall_t g_orig_eventfd2;

static void set_nonblocking_vfd(Machine& m, long vfd)
{
	if (vfd < FileDescriptors::VFD_START)
		return;
	try {
		const int fd = m.fds().translate(int(vfd));
		if (fd > 2)
			fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
	} catch (...) {
	}
}

/* Sweep the whole managed-vfd range rather than the socket-pair list: a
   handler can register both pipe ends and only afterwards fail to write the
   fds back to the guest, in which case the pair was never recorded but the
   real fds exist and would still block a later read(). */
static void nonblock_all_managed_fds(Machine& m)
{
	try {
		auto& fds = m.fds();
		const int last = FileDescriptors::VFD_START + int(fds.get_max_files()) + 8;
		for (int vfd = FileDescriptors::VFD_START; vfd < last; vfd++) {
			const auto entry = fds.entry_for_vfd(vfd);
			if (!entry.has_value() || (*entry) == nullptr)
				continue;
			const int fd = (*entry)->real_fd;
			if (fd > 2)
				fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
		}
	} catch (...) {
	}
}

/* clock_nanosleep passes the guest's timespec straight to the real
   clock_nanosleep, so a guest can pin the host thread for years -- a real
   issue in the library, not a harness one. Rather than
   refuse the syscall and lose all coverage of it, clamp the *values* in guest
   memory first and then run the original handler unmodified. The fuzzer still
   chooses the pointer, so the copy_from_guest/copy_to_guest edges -- the part
   worth fuzzing -- are all still reachable; only the duration is bounded. */
static Machine::syscall_t g_orig_clock_nanosleep;

static void install_clock_nanosleep_wrapper()
{
	g_orig_clock_nanosleep = Machine::get_syscall_handler(230);
	if (g_orig_clock_nanosleep == nullptr)
		return;

	Machine::install_syscall_handler(230, [](vCPU& cpu) {
		const uint64_t g_req = cpu.registers().sysarg(2);
		if (g_req != 0x0) {
			try {
				struct timespec ts {};
				cpu.machine().copy_from_guest(&ts, g_req, sizeof(ts));
				if (ts.tv_sec != 0 || ts.tv_nsec > 1000000L) {
					ts.tv_sec = 0;
					ts.tv_nsec = 1000L; /* 1us */
					cpu.machine().copy_to_guest(g_req, &ts, sizeof(ts));
				}
			} catch (const std::exception&) {
				/* Unreadable/unwritable pointer: leave it alone so the handler
				   under test gets to reject it itself. */
			}
		}
		g_orig_clock_nanosleep(cpu);
	});
}

static void install_nonblocking_wrappers()
{
	g_orig_socket     = Machine::get_syscall_handler(41);  /* socket */
	g_orig_pipe2      = Machine::get_syscall_handler(293); /* pipe2 */
	g_orig_socketpair = Machine::get_syscall_handler(53);  /* socketpair */
	g_orig_eventfd2   = Machine::get_syscall_handler(290); /* eventfd2 */

	install_clock_nanosleep_wrapper();

	/* NB: the post-step must run even when the original handler throws. A
	   handler can register both ends of a pipe and only then fail to write the
	   fds back to a bad guest address -- the fds exist, so a later read() on
	   one would block forever if it were left blocking. */
	if (g_orig_socket) {
		Machine::install_syscall_handler(41, [](vCPU& cpu) {
			try {
				g_orig_socket(cpu);
			} catch (...) {
				nonblock_all_managed_fds(cpu.machine());
				throw;
			}
			set_nonblocking_vfd(cpu.machine(), long(cpu.registers().sysret()));
		});
	}
	if (g_orig_eventfd2) {
		Machine::install_syscall_handler(290, [](vCPU& cpu) {
			try {
				g_orig_eventfd2(cpu);
			} catch (...) {
				nonblock_all_managed_fds(cpu.machine());
				throw;
			}
			set_nonblocking_vfd(cpu.machine(), long(cpu.registers().sysret()));
			nonblock_all_managed_fds(cpu.machine());
		});
	}
	if (g_orig_pipe2) {
		Machine::install_syscall_handler(293, [](vCPU& cpu) {
			try {
				g_orig_pipe2(cpu);
			} catch (...) {
				nonblock_all_managed_fds(cpu.machine());
				throw;
			}
			nonblock_all_managed_fds(cpu.machine());
		});
	}
	if (g_orig_socketpair) {
		Machine::install_syscall_handler(53, [](vCPU& cpu) {
			try {
				g_orig_socketpair(cpu);
			} catch (...) {
				nonblock_all_managed_fds(cpu.machine());
				throw;
			}
			nonblock_all_managed_fds(cpu.machine());
		});
	}
}

/* ------------------------------------------------------------------ */
/* Sandbox policy.                                                    */
/*                                                                    */
/* The path callbacks rewrite *every* requested path to one of two     */
/* files inside a private directory. That exercises the full open ->   */
/* manage -> translate -> read/write/stat/close path with no way to    */
/* reach anything else on the filesystem. Sockets are allowed to be    */
/* created (the fd bookkeeping is what we want to test) but never      */
/* connected or bound, so there is no egress.                         */
/* ------------------------------------------------------------------ */
static void install_sandbox_policy(Machine& m)
{
	auto& fds = m.fds();
	fds.set_open_readable_callback([](std::string& path) {
		path = g_sandbox_ro;
		return true;
	});
	fds.set_open_writable_callback([](std::string& path) {
		path = g_sandbox_rw;
		return true;
	});
	fds.set_resolve_symlink_callback([](std::string&) { return false; });
	fds.set_current_working_directory(g_sandbox_dir);

	/* No network egress. */
	fds.connect_socket_callback = [](int, struct sockaddr_storage&) { return false; };
	fds.bind_socket_callback    = [](int, struct sockaddr_storage&) { return false; };
	fds.listening_socket_callback = [](int, int) { return false; };
	fds.accept_callback = [](int, int, int) { return false; };

	/* poll()/ppoll() honour a guest-supplied timeout verbatim on a forked
	   VM, so let the guest reach the argument marshalling (the part that
	   parses the guest pollfd array) but never the blocking poll() itself. */
	fds.poll_callback = [](struct pollfd*, unsigned, int) { return false; };

	fds.set_max_files(64);
}

/* ------------------------------------------------------------------ */

static std::vector<uint8_t> load_file(const std::string& path)
{
	FILE* f = fopen(path.c_str(), "rb");
	if (f == nullptr) {
		fprintf(stderr, "syscall_fuzz: cannot open guest ELF '%s'\n", path.c_str());
		exit(1);
	}
	fseek(f, 0, SEEK_END);
	const long size = ftell(f);
	fseek(f, 0, SEEK_SET);
	std::vector<uint8_t> out;
	out.resize(size_t(size));
	if (fread(out.data(), 1, out.size(), f) != out.size()) {
		fclose(f);
		fprintf(stderr, "syscall_fuzz: short read on guest ELF\n");
		exit(1);
	}
	fclose(f);
	return out;
}

static void remove_sandbox()
{
	if (g_sandbox_dir.empty())
		return;
	unlink(g_sandbox_ro.c_str());
	unlink(g_sandbox_rw.c_str());
	rmdir(g_sandbox_dir.c_str());
}

/* atexit() is not enough: libFuzzer's fork-mode children are frequently killed
   rather than allowed to exit, and a long campaign spawns thousands of them.
   Sweep the sandbox directories whose owning pid is gone, so the set is
   self-healing rather than a slow /tmp leak. */
static void reap_stale_sandboxes(const std::string& base, const std::string& prefix)
{
	DIR* dir = opendir(base.c_str());
	if (dir == nullptr)
		return;
	while (const struct dirent* ent = readdir(dir)) {
		const std::string name = ent->d_name;
		if (name.compare(0, prefix.size(), prefix) != 0)
			continue;
		const std::string pid_part = name.substr(prefix.size());
		if (pid_part.empty() || pid_part.find_first_not_of("0123456789") != std::string::npos)
			continue;
		const pid_t pid = pid_t(strtol(pid_part.c_str(), nullptr, 10));
		if (pid <= 0 || pid == getpid())
			continue;
		if (kill(pid, 0) == 0 || errno != ESRCH)
			continue; /* still alive, or we cannot tell */
		const std::string path = base + "/" + name;
		unlink((path + "/readable").c_str());
		unlink((path + "/writable").c_str());
		rmdir(path.c_str());
	}
	closedir(dir);
}

static void make_sandbox()
{
	static const std::string PREFIX = "tinykvm-syscall-fuzz-";
	const char* env_base = getenv("TMPDIR");
	const std::string base = env_base ? env_base : "/tmp";

	reap_stale_sandboxes(base, PREFIX);

	g_sandbox_dir = base + "/" + PREFIX + std::to_string(getpid());
	mkdir(g_sandbox_dir.c_str(), 0700);

	g_sandbox_ro = g_sandbox_dir + "/readable";
	g_sandbox_rw = g_sandbox_dir + "/writable";

	/* Give the readable file some content so read()/mmap()/sendfile() paths
	   have something to move around. */
	if (FILE* f = fopen(g_sandbox_ro.c_str(), "wb")) {
		std::vector<uint8_t> data(64 * 1024);
		for (size_t i = 0; i < data.size(); i++)
			data[i] = uint8_t(i * 31 + 7);
		fwrite(data.data(), 1, data.size(), f);
		fclose(f);
	}
	if (FILE* f = fopen(g_sandbox_rw.c_str(), "wb")) {
		fputs("writable\n", f);
		fclose(f);
	}
}

/* Guest addresses worth pointing a syscall argument at. Ordinary valid
   pointers get us into the handler bodies; the boundary and hole entries
   are what actually stress the page-walking helpers. */
static void build_address_table(Machine& m, uint64_t scratch, uint64_t scratch_small)
{
	const uint64_t page = 4096;
	auto add = [](uint64_t a) { g_addrs.push_back(a); };

	add(0x0);
	add(0x1000);
	add(m.kernel_end_address());
	add(m.start_address());
	add(m.stack_address());
	add(m.stack_address() - page);
	add(m.heap_address());
	add(m.mmap_current());

	/* The bread-and-butter valid region. */
	add(scratch);
	add(scratch + 8);
	add(scratch + 64);
	/* Straddling a page boundary: the struct/buffer spans two guest pages
	   which, after CoW, are very often not physically contiguous. */
	add(((scratch + page - 1) & ~(page - 1)) - 4);
	add(((scratch + page - 1) & ~(page - 1)) - 1);
	add(((scratch + page - 1) & ~(page - 1)));
	add(scratch + page * 3 - 8);
	add(scratch + 0x1F000);   /* last page of the 128K region */
	add(scratch + 0x20000 - 8); /* last 8 bytes: reads past the end fall off */
	add(scratch + 0x20000);   /* one past the end */

	add(scratch_small);
	add(scratch_small + 0x2000 - 4);

	/* Out of bounds / unmapped / non-canonical. */
	add(m.max_address() - 8);
	add(m.max_address());
	add(m.max_address() + page);
	add(0x7FFFFFFFF000ull);
	add(0xFFFF800000000000ull);
	add(~uint64_t(0) - 0xFFF);
	add(~uint64_t(0));
}

static const uint64_t INTERESTING[] = {
	0, 1, 2, 3, 8, 0x10, 0x40, 0xFF, 0x100, 0x1000, 0x2000, 4095, 4096, 8192,
	0xFFFF, 0x10000, 0x100000, 0x1000000, 64ull << 20,
	uint64_t(-1), uint64_t(-2), uint64_t(-4095), uint64_t(int64_t(INT32_MIN)),
	0x7FFFFFFF, 0x80000000, 0xFFFFFFFF, 0x100000000ull, 0x7FFFFFFFFFFFFFFFull,
	0x8000000000000000ull,
	FileDescriptors::VFD_START, FileDescriptors::VFD_START + 1,
	FileDescriptors::VFD_START + 2, 0x100, 0x1001,
};
static constexpr size_t INTERESTING_COUNT = sizeof(INTERESTING) / sizeof(INTERESTING[0]);

/* ------------------------------------------------------------------ */

struct Reader {
	const uint8_t* p;
	const uint8_t* end;

	bool empty() const { return p >= end; }
	size_t left() const { return size_t(end - p); }

	uint8_t u8() { return p < end ? *p++ : 0; }
	uint16_t u16() { const uint16_t a = u8(); return uint16_t(a | (uint16_t(u8()) << 8)); }
	int16_t i16() { return int16_t(u16()); }
	uint64_t u64()
	{
		uint64_t v = 0;
		for (int i = 0; i < 8; i++)
			v |= uint64_t(u8()) << (i * 8);
		return v;
	}
};

static uint64_t table_address(Reader& r)
{
	const uint64_t base = g_addrs[r.u8() % g_addrs.size()];
	return base + uint64_t(int64_t(r.i16()));
}

static uint64_t decode_arg(Reader& r)
{
	const uint8_t kind = r.u8();
	switch (kind & 3) {
	case 0: return r.u8();
	case 1: return r.u64();
	case 2: return table_address(r);
	default: return INTERESTING[r.u8() % INTERESTING_COUNT];
	}
}

/* Report a non-MachineException exactly once per (type, message) pair so a
   non-strict campaign still tells us what it found without stopping. */
static void note_foreign_exception(const char* type, const char* what)
{
	static std::set<std::string> seen;
	std::string key = std::string(type) + ": " + what;
	if (seen.insert(key).second)
		fprintf(stderr, "syscall_fuzz: foreign exception escaped a handler: %s\n", key.c_str());
}

static void do_call(Reader& r)
{
	const unsigned sysno = r.u16() & 0x3FF;

	uint64_t args[6];
	for (unsigned i = 0; i < 6; i++)
		args[i] = decode_arg(r);

	if (blocked_syscall(sysno))
		return;

	/* Setting up the register frame is harness bookkeeping, not the code under
	   test; a failure here must not be reported as a finding. */
	tinykvm_regs regs;
	try {
		regs = g_fork->registers();
		for (unsigned i = 0; i < 6; i++)
			regs.sysarg(i) = args[i];
		regs.sysret() = 0;
		g_fork->set_registers(regs);
	} catch (const std::exception& e) {
		fprintf(stderr, "syscall_fuzz: harness could not set registers: %s\n", e.what());
		return;
	}

	if (g_verbose) {
		fprintf(stderr, "call %u(0x%llX, 0x%llX, 0x%llX, 0x%llX, 0x%llX, 0x%llX)\n",
			sysno, (unsigned long long)regs.sysarg(0), (unsigned long long)regs.sysarg(1),
			(unsigned long long)regs.sysarg(2), (unsigned long long)regs.sysarg(3),
			(unsigned long long)regs.sysarg(4), (unsigned long long)regs.sysarg(5));
	}

	try {
		g_fork->system_call(g_fork->cpu(), sysno);
	} catch (const MachineException&) {
		/* Expected and correct: this is how the emulation layer rejects a
		   bad pointer, a bad length or an unsupported request. */
	} catch (const std::exception& e) {
		/* Not expected: an embedder catching MachineException would let this
		   escape into its own request loop. */
		if (g_strict)
			throw;
		note_foreign_exception(typeid(e).name(), e.what());
	}
}

static void do_poke(Reader& r)
{
	const uint64_t addr = table_address(r);
	const size_t len = r.u8();
	uint8_t buf[256];
	const size_t n = len < r.left() ? len : r.left();
	for (size_t i = 0; i < n; i++)
		buf[i] = r.u8();
	if (n == 0)
		return;
	try {
		g_fork->copy_to_guest(addr, buf, n);
	} catch (const MachineException&) {
		/* Expected: the fuzzer is meant to aim at unmapped addresses too. */
	} catch (const std::exception& e) {
		/* Harness-side, not a syscall handler -- note it but never abort. */
		note_foreign_exception(typeid(e).name(), e.what());
	}
}

static void reset_fork()
{
	try {
		g_fork->reset_to(*g_master, {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = MAX_COW_MEM,
		});
		install_sandbox_policy(*g_fork);
		g_fork->set_printer([](const char*, size_t) {});
		return;
	} catch (const std::exception& e) {
		fprintf(stderr, "syscall_fuzz: reset_to failed (%s), rebuilding fork\n", e.what());
	}
	delete g_fork;
	g_fork = new Machine { *g_master, {
		.max_mem = MAX_MEMORY,
		.max_cow_mem = MAX_COW_MEM,
	} };
	install_sandbox_policy(*g_fork);
	g_fork->set_printer([](const char*, size_t) {});
}

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
	g_strict  = getenv("TINYKVM_FUZZ_STRICT") != nullptr;
	g_verbose = getenv("TINYKVM_FUZZ_VERBOSE") != nullptr;
	const bool unsafe = getenv("TINYKVM_FUZZ_UNSAFE") != nullptr;

	/* The guest can get the host killed by SIGPIPE: create a pipe or
	   socketpair, close one end, write() to the other. The emulation layer
	   passes MSG_NOSIGNAL on the sendmsg/sendto paths but plain
	   write()/writev()/pwritev64() have no equivalent, so the default
	   disposition terminates the process. That is a real finding about the
	   library, not about this harness -- ignore it here so one
	   trivially-reachable signal does not end every campaign. */
	signal(SIGPIPE, SIG_IGN);

	/* read(0, ...) must not be able to block on the fuzzer's own stdin. */
	if (const int devnull = open("/dev/null", O_RDONLY); devnull >= 0) {
		dup2(devnull, STDIN_FILENO);
		if (devnull != STDIN_FILENO)
			close(devnull);
	}

	make_sandbox();
	atexit(remove_sandbox);

	Machine::init();
	Machine::setup_linux_system_calls(unsafe);
	Machine::setup_multithreading();
	Machine::install_unhandled_syscall_handler([](vCPU&, unsigned) {});
	install_nonblocking_wrappers();

	const char* guest_path = getenv("TINYKVM_FUZZ_GUEST");
#ifdef FUZZ_GUEST_PATH
	if (guest_path == nullptr)
		guest_path = FUZZ_GUEST_PATH;
#endif
	if (guest_path == nullptr) {
		fprintf(stderr, "syscall_fuzz: set TINYKVM_FUZZ_GUEST to a static guest ELF\n");
		exit(1);
	}
	static const std::vector<uint8_t> binary = load_file(guest_path);

	/* Everything below must succeed or be reported loudly. libFuzzer has not
	   installed its crash handlers yet at this point, so an exception escaping
	   here dies silently via std::terminate -- in fork mode that shows up as an
	   artifact-less "crash" in the parent's tally and looks like a finding.
	   Booting the master can genuinely fail transiently under load (the run
	   timeout is wall-clock), so retry a few times before giving up. */
	uint64_t scratch = 0, scratch_small = 0;
	std::string last_error;
	for (int attempt = 0; attempt < 4; attempt++) {
		try {
			delete g_master;
			g_master = nullptr;

			g_master = new Machine { binary, { .max_mem = MAX_MEMORY } };
			install_sandbox_policy(*g_master);
			g_master->set_printer([](const char*, size_t) {});
			g_master->setup_linux({ "syscall_fuzz" }, { "LC_ALL=C", "USER=root" });
			/* Generous: this is a trivial guest, but 8 sanitized workers can
			   starve each other badly enough to trip a tight timeout. */
			g_master->run(60.0f);

			scratch = g_master->address_of("scratch");
			scratch_small = g_master->address_of("scratch_small");
			if (scratch == 0x0 || scratch_small == 0x0)
				throw std::runtime_error("guest ELF is missing the scratch symbols");

			g_master->prepare_copy_on_write(MAX_COW_MEM);

			g_fork = new Machine { *g_master, {
				.max_mem = MAX_MEMORY,
				.max_cow_mem = MAX_COW_MEM,
			} };
			install_sandbox_policy(*g_fork);
			g_fork->set_printer([](const char*, size_t) {});
			last_error.clear();
			break;
		} catch (const std::exception& e) {
			last_error = e.what();
			fprintf(stderr, "syscall_fuzz: master setup attempt %d failed: %s\n",
				attempt + 1, last_error.c_str());
		}
	}
	if (!last_error.empty()) {
		fprintf(stderr, "syscall_fuzz: giving up on master setup: %s\n", last_error.c_str());
		exit(2);
	}

	build_address_table(*g_master, scratch, scratch_small);

	fprintf(stderr, "syscall_fuzz: ready. scratch=0x%lX addresses=%zu strict=%d unsafe=%d\n",
		scratch, g_addrs.size(), int(g_strict), int(unsafe));
	return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len)
{
	Reader r { data, data + len };

	for (size_t i = 0; i < MAX_RECORDS && !r.empty(); i++) {
		const uint8_t op = r.u8();
		if ((op & 3) == 0)
			do_poke(r);
		else
			do_call(r);
	}

	reset_fork();
	return 0;
}
