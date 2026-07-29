#include <catch2/catch_test_macros.hpp>

#include <tinykvm/machine.hpp>
#include <chrono>
#include <cstdio>
#include <string>
#include <unistd.h>

/* Regression tests for host-side syscall emulation bugs found by
   fuzz/syscall_fuzz.cpp. Each of these is reachable from an ordinary,
   unprivileged guest using a completely legal syscall. */

extern std::vector<uint8_t> build_and_load(const std::string& code);
extern std::pair<std::string, std::vector<uint8_t>>
	build_and_load(const std::string& code, const std::string& args);
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};

namespace {
	/* A real file on the host that the guest's open() calls are redirected to,
	   mirroring how an embedder's path policy rewrites guest paths. */
	struct ScratchFile {
		std::string path;

		ScratchFile()
		{
			char tmpl[] = "/tmp/tinykvm-syscall-test-XXXXXX";
			const int fd = mkstemp(tmpl);
			REQUIRE(fd >= 0);
			/* Some content, so reads have something to return. */
			const std::string data(4096, 'A');
			REQUIRE(write(fd, data.data(), data.size()) == ssize_t(data.size()));
			close(fd);
			path = tmpl;
		}
		~ScratchFile() { unlink(path.c_str()); }
	};

	void allow_scratch_file(tinykvm::Machine& machine, const ScratchFile& file)
	{
		machine.fds().set_open_readable_callback([&file](std::string& path) {
			path = file.path;
			return true;
		});
		machine.fds().set_open_writable_callback([&file](std::string& path) {
			path = file.path;
			return true;
		});
		/* The openat handler resolves against the cwd fd; without one, opens
		   for writing fail before the handler under test is reached. */
		machine.fds().set_current_working_directory("/tmp");
	}
}

TEST_CASE("Initialize KVM", "[Initialize]")
{
	tinykvm::Machine::init();
}

TEST_CASE("Opening an existing file for writing succeeds", "[Syscalls]")
{
	/* The openat handler built an open_how with a non-zero .mode for every
	   write-open. openat2 only accepts a mode when the open can create a file,
	   so O_RDWR/O_WRONLY on a path that already exists failed with EINVAL --
	   guests could never open an existing file for writing. */
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
	int fd = open("/scratch", O_RDWR);
	if (fd < 0) return 100 + (errno & 0x7F);
	close(fd);

	fd = open("/scratch", O_WRONLY);
	if (fd < 0) return 200 + (errno & 0x7F);
	close(fd);
	return 0;
})M");

	ScratchFile file;
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	allow_scratch_file(machine, file);
	machine.setup_linux({"open-existing-writable"}, env);
	machine.run(4.0f);

	REQUIRE(machine.return_value() == 0);
}

TEST_CASE("Zero-length I/O does not dereference an empty buffer list", "[Syscalls]")
{
	/* read/write/pread64/pwrite64 gather the guest range into a vector of
	   host buffers. A zero-length request gathers nothing, and the handlers
	   then indexed buffers[0] on the empty vector. For write() that was a
	   load from a null pointer -- i.e. any guest could kill the VMM process
	   with write(fd, p, 0), a legal no-op call. */
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <errno.h>

int main() {
	int fd = open("/scratch", O_RDWR);
	if (fd < 0) return 1;

	char b[1] = {'x'};
	if (write(fd, b, 0) != 0)   return 2;
	if (read(fd, b, 0) != 0)    return 3;
	if (pwrite(fd, b, 0, 0) != 0) return 4;
	if (pread(fd, b, 0, 0) != 0)  return 5;

	/* Zero-length writev/readv too, for good measure. */
	struct iovec iov = { b, 0 };
	if (writev(fd, &iov, 1) != 0) return 6;

	return 0;
})M");

	ScratchFile file;
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	allow_scratch_file(machine, file);
	machine.setup_linux({"zero-length-io"}, env);
	machine.run(4.0f);

	REQUIRE(machine.return_value() == 0);
}

TEST_CASE("getdents64 on a non-directory does not leak host memory", "[Syscalls]")
{
	/* The handler stored the host getdents64() return value in sysret(),
	   which is __u64, and then tested it with `> 0`. On failure (-1) that
	   became ~2^64 and was passed to copy_to_guest() as a length, streaming
	   the host stack into guest memory until the copy walked off the end of
	   the guest address space. getdents64 on a regular fd -- which returns
	   ENOTDIR -- is enough to trigger it. */
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

/* In .bss, far away from anything the guest cares about. */
char dirbuf[8192];

int main() {
	int fd = open("/scratch", O_RDONLY);
	if (fd < 0) return 1;

	memset(dirbuf, 0xAA, sizeof(dirbuf));

	long rc = syscall(SYS_getdents64, fd, dirbuf, sizeof(dirbuf));
	/* A regular file is not a directory: this must fail, not succeed. */
	if (rc >= 0) return 2;

	/* Nothing may have been written into the guest buffer. */
	for (unsigned i = 0; i < sizeof(dirbuf); i++) {
		if ((unsigned char)dirbuf[i] != 0xAA)
			return 3;
	}
	return 0;
})M");

	ScratchFile file;
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	allow_scratch_file(machine, file);
	machine.setup_linux({"getdents64-enotdir"}, env);
	machine.run(4.0f);

	REQUIRE(machine.return_value() == 0);
}

TEST_CASE("Socket and pipe I/O still round-trips", "[Syscalls]")
{
	/* Positive counterpart to the bounds checks and empty-buffer-list fixes
	   below: those added new -EINVAL paths and changed how the gathered buffer
	   list is handed to the host, so verify the ordinary cases still work.
	   Covers write/read, writev/readv, sendmsg/recvmsg and sendto/recvfrom over
	   a socketpair and a pipe, including a multi-entry iovec. */
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>

int main() {
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return 1;

	/* write() / read() */
	if (write(sv[0], "hello", 5) != 5) return 2;
	char buf[32] = {0};
	if (read(sv[1], buf, sizeof(buf)) != 5) return 3;
	if (memcmp(buf, "hello", 5) != 0) return 4;

	/* writev() with two entries. NB: readv() has no handler in the emulation
	   layer at all (it returns -ENOSYS), so read it back with read(). */
	struct iovec wv[2] = { { "ab", 2 }, { "cde", 3 } };
	if (writev(sv[0], wv, 2) != 5) return 5;
	memset(buf, 0, sizeof(buf));
	if (read(sv[1], buf, sizeof(buf)) != 5) return 6;
	if (memcmp(buf, "abcde", 5) != 0) return 7;

	/* sendmsg() / recvmsg() with msg_name unused (namelen 0) */
	struct iovec siov = { "msghdr", 6 };
	struct msghdr smsg;
	memset(&smsg, 0, sizeof(smsg));
	smsg.msg_iov = &siov;
	smsg.msg_iovlen = 1;
	if (sendmsg(sv[0], &smsg, 0) != 6) return 8;

	memset(buf, 0, sizeof(buf));
	struct iovec riov = { buf, sizeof(buf) };
	struct msghdr rmsg;
	memset(&rmsg, 0, sizeof(rmsg));
	rmsg.msg_iov = &riov;
	rmsg.msg_iovlen = 1;
	if (recvmsg(sv[1], &rmsg, 0) != 6) return 9;
	if (memcmp(buf, "msghdr", 6) != 0) return 10;

	/* sendto() / recvfrom() on a connected socket: no address */
	if (sendto(sv[0], "sendto", 6, 0, NULL, 0) != 6) return 11;
	memset(buf, 0, sizeof(buf));
	if (recvfrom(sv[1], buf, sizeof(buf), 0, NULL, NULL) != 6) return 12;
	if (memcmp(buf, "sendto", 6) != 0) return 13;

	close(sv[0]);
	close(sv[1]);

	/* And the same for a pipe. */
	int pfd[2];
	if (pipe(pfd) < 0) return 14;
	if (write(pfd[1], "pipe", 4) != 4) return 15;
	memset(buf, 0, sizeof(buf));
	if (read(pfd[0], buf, sizeof(buf)) != 4) return 16;
	if (memcmp(buf, "pipe", 4) != 0) return 17;

	return 0;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"socket-roundtrip"}, env);
	machine.run(4.0f);

	REQUIRE(machine.return_value() == 0);
}

TEST_CASE("sendmsg rejects an oversized msg_namelen", "[Syscalls]")
{
	/* The handler copied msg_namelen bytes out of the guest into a 128-byte
	   sockaddr_storage on its own stack, with the length taken straight from
	   the guest's msghdr and never bounded. Both the length and the bytes are
	   guest-controlled, so this was a straightforward stack smash of the VMM. */
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>

static char payload[8192];

int main() {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return 1;

	memset(payload, 0x41, sizeof(payload));

	char body[8] = {0};
	struct iovec iov = { body, sizeof(body) };

	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = payload;
	msg.msg_namelen = sizeof(payload);  /* >> sizeof(sockaddr_storage) */
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* Must be refused, not copied. Any error is acceptable. */
	if (sendmsg(fd, &msg, 0) >= 0) return 2;
	return 0;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"sendmsg-namelen"}, env);
	machine.run(4.0f);

	REQUIRE(machine.return_value() == 0);
}

TEST_CASE("sendmmsg rejects an oversized message count", "[Syscalls]")
{
	/* vlen was only checked for being positive before being multiplied by
	   sizeof(mmsghdr) and used as the length of a copy into a 1024-entry
	   (64KB) stack array. A large vlen overflowed the VMM's stack with
	   guest-supplied bytes. */
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>

static char payload[262144];

int main() {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return 1;

	memset(payload, 0x42, sizeof(payload));

	/* 4096 mmsghdrs is 4x the handler's fixed capacity. */
	long rc = syscall(SYS_sendmmsg, fd, payload, 4096, 0);
	if (rc >= 0) return 2;
	return 0;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"sendmmsg-vlen"}, env);
	machine.run(4.0f);

	REQUIRE(machine.return_value() == 0);
}

TEST_CASE("prctl(PR_GET_NAME) does not read past its name literal", "[Syscalls]")
{
	/* The handler copied buflen bytes (up to 16) directly out of the 8-byte
	   string literal "tinykvm", handing the guest whatever .rodata happened to
	   follow it. */
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <string.h>
#include <sys/prctl.h>

int main() {
	char name[16];
	memset(name, 0xCC, sizeof(name));

	if (prctl(PR_GET_NAME, name, sizeof(name), 0, 0) != 0) return 1;
	if (strncmp(name, "tinykvm", 7) != 0) return 2;

	/* Everything after the name must be NUL padding, not host .rodata. */
	for (unsigned i = 7; i < sizeof(name); i++) {
		if (name[i] != 0) return 3;
	}
	return 0;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"prctl-get-name"}, env);
	machine.run(4.0f);

	REQUIRE(machine.return_value() == 0);
}

TEST_CASE("timerfd_create with a bad clockid returns an error", "[Syscalls]")
{
	/* clockid is guest-controlled and reaches timerfd_create() directly. On
	   failure the handler passed the -1 to FileDescriptors::manage(), which
	   throws std::runtime_error -- so the following `if (vfd < 0)` was dead
	   code and the exception escaped the handler entirely. An embedder that
	   catches MachineException (the documented contract) would not catch it. */
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <errno.h>
#include <sys/timerfd.h>

int main() {
	/* Not a valid clockid. */
	int fd = timerfd_create(0x7FFFFFFF, 0);
	if (fd >= 0) return 1;
	if (errno <= 0) return 2;
	return 0;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"timerfd-bad-clockid"}, env);
	machine.run(4.0f);

	REQUIRE(machine.return_value() == 0);
}

TEST_CASE("madvise(MADV_DONTNEED) still zeroes in-range memory", "[Syscalls]")
{
	/* Positive counterpart to the clamp added to Machine::memzero(): the range
	   is now bounded to the addresses this VM's page tables can cover, so verify
	   an ordinary in-range MADV_DONTNEED is still honoured and not clipped away.
	   Uses several pages, and checks the page straddling the end of the range is
	   handled too. */
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <string.h>
#include <sys/mman.h>

#define LEN (16 * 4096)

int main() {
	unsigned char *p = mmap(NULL, LEN, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) return 1;

	memset(p, 0xA5, LEN);
	/* Confirm the write landed, so a zero result below means something. */
	for (unsigned i = 0; i < LEN; i += 4096) {
		if (p[i] != 0xA5) return 2;
	}
	if (p[LEN - 1] != 0xA5) return 3;

	if (madvise(p, LEN, MADV_DONTNEED) != 0) return 4;

	/* Every byte must now read back as zero. */
	for (unsigned i = 0; i < LEN; i++) {
		if (p[i] != 0x00) return 5;
	}

	/* Partial range: dirty it again, discard only the middle two pages. */
	memset(p, 0x5A, LEN);
	if (madvise(p + 4096, 2 * 4096, MADV_DONTNEED) != 0) return 6;
	for (unsigned i = 0; i < 4096; i++) {
		if (p[i] != 0x5A) return 7;               /* before: untouched */
	}
	for (unsigned i = 4096; i < 3 * 4096; i++) {
		if (p[i] != 0x00) return 8;               /* discarded */
	}
	for (unsigned i = 3 * 4096; i < LEN; i++) {
		if (p[i] != 0x5A) return 9;               /* after: untouched */
	}
	return 0;
})M");

	/* Dirtying 64KB of fresh anonymous memory in a non-forked master needs more
	   headroom than the 8MB the other cases use. */
	tinykvm::Machine machine { binary, { .max_mem = 64ul << 20 } };
	machine.setup_linux({"madvise-dontneed"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 0);
}

TEST_CASE("madvise still zeroes when a remote VM is connected", "[Syscalls]")
{
	/* The clamp added to Machine::memzero() widens its bound to include a
	   connected remote's range, so that address-space merging keeps working.
	   That branch is only taken when has_remote() is true, which no other test
	   reaches -- so exercise it and confirm zeroing of the VM's *own* memory is
	   unaffected by the presence of a remote. */
	const auto storage_binary = build_and_load(R"M(
int main() { return 1234; }
)M", "-Wl,-Ttext-segment=0x40400000");

	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <stddef.h>
#include <string.h>
#include <sys/mman.h>

#define LEN (8 * 4096)

int main() {
	unsigned char *p = mmap(NULL, LEN, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) return 1;

	memset(p, 0x3C, LEN);
	if (p[0] != 0x3C || p[LEN - 1] != 0x3C) return 2;

	if (madvise(p, LEN, MADV_DONTNEED) != 0) return 3;
	for (unsigned i = 0; i < LEN; i++) {
		if (p[i] != 0x00) return 4;
	}
	return 0;
})M");

	tinykvm::Machine storage { storage_binary.second, {
		.max_mem = 16ULL << 20,
		.vmem_base_address = 1ULL << 30, /* 1GB, above the main VM */
	} };
	storage.setup_linux({"storage"}, env);
	storage.run(4.0f);
	REQUIRE(storage.return_value() == 1234);

	tinykvm::Machine machine { binary, { .max_mem = 64ul << 20 } };
	machine.setup_linux({"madvise-remote"}, env);
	machine.remote_connect(storage);
	machine.set_remote_allow_page_faults(true);
	REQUIRE(machine.has_remote());

	machine.run(8.0f);
	REQUIRE(machine.return_value() == 0);
}

TEST_CASE("madvise with an out-of-range length returns promptly", "[Syscalls]")
{
	/* madvise(MADV_DONTNEED) passes the guest's length straight to
	   Machine::memzero(), which walks the range one page-table lookup per 4K
	   and deliberately ignores pages that are not present -- so an
	   out-of-range length is not an error, it is an unbounded walk. At ~10M
	   pages/second a 16TB length is minutes and a 2^64 length is years, and
	   because this runs inside the syscall handler the execution timeout does
	   not apply: the host thread is simply gone.

	   16TB is chosen so the pre-fix behaviour is slow enough to fail this
	   assertion by a wide margin without hanging CI outright. */
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <sys/mman.h>

int main() {
	/* Return value is unimportant -- what matters is that we get here. */
	madvise((void *)0x1000000, 1UL << 44, MADV_DONTNEED);
	return 0;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"madvise-huge"}, env);

	const auto t0 = std::chrono::steady_clock::now();
	machine.run(30.0f);
	const auto elapsed = std::chrono::duration<double>(
		std::chrono::steady_clock::now() - t0).count();

	REQUIRE(machine.return_value() == 0);
	REQUIRE(elapsed < 5.0);
}
