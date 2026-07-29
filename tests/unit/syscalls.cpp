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
