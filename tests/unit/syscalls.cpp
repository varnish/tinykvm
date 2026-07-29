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
