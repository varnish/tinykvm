#include "machine.hpp"

#include <cstring>
#include <stdexcept>
#include <unistd.h>
#include "rsp_client.hpp"
extern char** environ;

namespace tinykvm {
void Machine::print_remote_gdb_backtrace(
	const std::string& filename,
	const RemoteGDBOptions& opts)
{
	const uint16_t port = 2159;

	if (0 == fork())
	{
		char scrname[64];
		strncpy(scrname, "/tmp/dbgscript-XXXXXX", sizeof(scrname));
		const int fd = mkstemp(scrname);
		if (fd < 0)
		{
			throw std::runtime_error("Unable to create script for debugging");
		}

		std::string debugscript =
			// Delete the script file (after GDB closes it)
			"shell unlink " + std::string(scrname)
			+ "\n"
			+ "set debuginfod enabled on\n"
			  // Load the original file used by the script
			  "file " + filename + "\n"
			  // Connect remotely to the given port @port
			  "target remote localhost:"
			+ std::to_string(port)
			+ "\n"
			+ opts.command + "\n";
		if (opts.quit)
			debugscript += "quit\n";

		ssize_t len = write(fd, debugscript.c_str(), debugscript.size());
		if (len < (ssize_t)debugscript.size())
		{
			throw std::runtime_error(
				"Unable to write script file for debugging");
		}
		close(fd);

		const char* argv[]
			= {opts.gdb_path.c_str(), "-x", scrname, nullptr};
		// XXX: This is not kosher, but GDB is open-source, safe and let's not
		// pretend that anyone downloads gdb-multiarch from a website anyway.
		// There is a finite list of things we should pass to GDB to make it
		// behave well, but I haven't been able to find the right combination.
		if (-1 == execve(argv[0], (char* const*)argv, environ))
		{
			throw std::runtime_error(
				"Unable to start gdb-multiarch for debugging");
		}
	}

	RSP server {filename, *this, port};
	if (opts.verbose) {
		printf("Waiting for GDB to connect on port %u...\n", port);
	}
	auto client = server.accept();
	if (client != nullptr)
	{
		if (opts.verbose) {
			printf("GDB connected\n");
		}
		// client->set_verbose(true);
		while (client->process_one())
			;
	}
}

} // namespace tinykvm
