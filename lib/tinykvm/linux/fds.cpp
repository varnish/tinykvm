#include "fds.hpp"

#include "../machine.hpp"
#include "threads.hpp"
#include <fcntl.h>
#include <cstring>
#include <sys/stat.h>
#include <stdexcept>
#include <unistd.h>

namespace tinykvm
{
	FileDescriptors& Machine::fds()
	{
		if (!m_fds) {
			m_fds = std::make_unique<FileDescriptors>(*this);
		}
		return *m_fds;
	}
	const FileDescriptors& Machine::fds() const
	{
		return const_cast<Machine&>(*this).fds();
	}

	FileDescriptors::FileDescriptors(Machine& machine)
		: m_machine(machine)
	{
		m_allowed_readable_paths =
			std::make_shared<std::unordered_set<std::string>>();
		m_allowed_readable_paths_starts_with =
			std::make_shared<std::vector<std::string>>();
		// Add all common standard libraries to the list of allowed readable paths
		this->add_readonly_file("/lib64/ld-linux-x86-64.so.2");
		this->add_readonly_file("/lib/x86_64-linux-gnu/libgcc_s.so.1");
		this->add_readonly_file("/lib/x86_64-linux-gnu/libc.so.6");
		this->add_readonly_file("/lib/x86_64-linux-gnu/libm.so.6");
		this->add_readonly_file("/lib/x86_64-linux-gnu/libpthread.so.0");
		this->add_readonly_file("/lib/x86_64-linux-gnu/libdl.so.2");
		this->add_readonly_file("/lib/x86_64-linux-gnu/libstdc++.so.6");
		this->add_readonly_file("/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v2/libstdc++.so.6");
		this->add_readonly_file("/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libstdc++.so.6");
		this->add_readonly_file("/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v4/libstdc++.so.6");

		// XXX: TODO: Create proper redirects for stdout/stderr by
		// for example providing a pipe to stdout/stderr.
	}

	FileDescriptors::~FileDescriptors()
	{
		for (auto& [fd, entry] : m_fds) {
			if (entry.real_fd >= 0) {
				close(entry.real_fd);
			}
		}
	}

	void FileDescriptors::reset_to(const FileDescriptors& other)
	{
		// Close all current file descriptors
		// We don't have a sandbox-safe way to share
		// file descriptors between VMs, so just close.
		for (auto& [fd, entry] : m_fds) {
			if (entry.real_fd >= 0) {
				close(entry.real_fd);
			}
		}
		// Clear the current file descriptors
		m_fds.clear();
		m_next_file_fd = other.m_next_file_fd;
		m_next_socket_fd = other.m_next_socket_fd;
		m_allowed_readable_paths = other.m_allowed_readable_paths;
	}

	int FileDescriptors::manage(int fd, bool is_socket, bool is_writable)
	{
		if (fd < 0) {
			throw std::runtime_error("Invalid file descriptor in FileDescriptors::add()");
		}
		if (is_socket) {
			m_fds[m_next_socket_fd] = {fd, is_writable, false};
			return m_next_socket_fd++;
		} else {
			m_fds[m_next_file_fd] = {fd, is_writable, false};
			return m_next_file_fd++;
		}
	}

	std::optional<const FileDescriptors::Entry*> FileDescriptors::entry_for_vfd(int vfd) const
	{
		auto it = m_fds.find(vfd);
		if (it != m_fds.end()) {
			return &it->second;
		}
		return std::nullopt;
	}

	int FileDescriptors::translate(int vfd)
	{
		if (vfd >= 0 && vfd < 3) {
			return this->m_stdout_redirects.at(vfd);
		}
		auto it = m_fds.find(vfd);
		if (it != m_fds.end()) {
			return it->second.real_fd;
		}

		if (this->m_find_ro_master_vm_fd) {
			auto opt_entry = this->m_find_ro_master_vm_fd(vfd);
			if (opt_entry) {
				auto& entry = *opt_entry;
				const int new_fd = dup(entry->real_fd);
				if (new_fd < 0) {
					throw std::runtime_error("Failed to duplicate file descriptor");
				}
				if (this->m_verbose) {
					fprintf(stderr, "TinyKVM: %d -> %d\n", entry->real_fd, new_fd);
				}
				// We need to manage the *same* virtual file descriptor as the main
				// VM, so we need to set the real_fd of the new entry to the new fd.
				m_fds[vfd] = {new_fd, entry->is_writable, true};
				return new_fd;
			}
		}
		throw std::runtime_error("Invalid virtual file descriptor: " + std::to_string(vfd));
	}

	int FileDescriptors::translate_unless_forked(int vfd)
	{
		if (vfd >= 0 && vfd < 3) {
			return this->m_stdout_redirects.at(vfd);
		}
		auto it = m_fds.find(vfd);
		if (it != m_fds.end()) {
			if (it->second.is_forked) {
				return -1;
			}
			return it->second.real_fd;
		}
		throw std::runtime_error("Invalid virtual file descriptor: " + std::to_string(vfd));
	}

	void FileDescriptors::free(int vfd)
	{
		auto it = m_fds.find(vfd);
		if (it != m_fds.end()) {
			close(it->second.real_fd);
			m_fds.erase(it);
		}
	}

	void FileDescriptors::add_readonly_file(const std::string& path)
	{
		if (path.empty())
			throw std::runtime_error("Empty path in FileDescriptors::add_readonly_file");
		if (path.find("..") != std::string::npos)
			throw std::runtime_error("Path contains parent directory in FileDescriptors::add_readonly_file");
		// We allow paths that start with $ to be treated as
		// a prefix for the allowed paths. This is useful for
		// allowing directories and other prefixes.
		if (path.front() == '$')
			this->m_allowed_readable_paths_starts_with->push_back(path.substr(1));
		else
			this->m_allowed_readable_paths->insert(path);
	}

	bool FileDescriptors::is_readable_path(std::string& modifiable_path) const noexcept
	{
		if (modifiable_path.empty())
			return false;

		if (m_open_readable)
		{
			if (m_open_readable(modifiable_path)) {
				if (this->m_verbose) {
					fprintf(stderr, "TinyKVM: %s is allowed (read, callback)\n", modifiable_path.c_str());
				}
				return true;
			}
		}
		auto it = m_allowed_readable_paths->find(modifiable_path);
		if (it != m_allowed_readable_paths->end())
		{
			if (this->m_verbose) {
				fprintf(stderr, "TinyKVM: %s is allowed (read)\n", modifiable_path.c_str());
			}
			return true;
		}
		// Iterate over the allowed paths and check if a path
		// starts with modifiable_path, however path cannot contain
		// any parent-directory components (..)
		if (modifiable_path.find("..") != std::string::npos)
		{
			return false;
		}
		for (const auto& path : *m_allowed_readable_paths_starts_with)
		{
			if (modifiable_path.find(path) == 0)
			{
				if (this->m_verbose) {
					fprintf(stderr, "TinyKVM: %s is allowed (read, prefixed)\n", modifiable_path.c_str());
				}
				return true;
			}
		}
		if (this->m_verbose) {
			fprintf(stderr, "TinyKVM: %s is not a readable path\n", modifiable_path.c_str());
		}
		return false;
	}

	bool FileDescriptors::is_writable_path(std::string& modifiable_path) const noexcept
	{
		if (m_open_writable) {
			bool success = m_open_writable(modifiable_path);
			if (this->m_verbose && success) {
				fprintf(stderr, "TinyKVM: %s is allowed (write, callback)\n", modifiable_path.c_str());
			}
			return success;
		}
		if (this->m_verbose) {
			fprintf(stderr, "TinyKVM: %s is not a writable path\n", modifiable_path.c_str());
		}
		return false;
	}

} // tinykvm
