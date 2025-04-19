#include "fds.hpp"

#include "../machine.hpp"
#include "threads.hpp"
#include <fcntl.h>
#include <cstring>
#include <sys/stat.h>
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

	FileDescriptors::FileDescriptors(Machine& machine)
		: m_machine(machine)
	{
		// Add all common standard libraries to the list of allowed readable paths
		m_allowed_readable_paths.insert("/lib64/ld-linux-x86-64.so.2");
		m_allowed_readable_paths.insert("/lib/x86_64-linux-gnu/libgcc_s.so.1");
		m_allowed_readable_paths.insert("/lib/x86_64-linux-gnu/libc.so.6");
		m_allowed_readable_paths.insert("/lib/x86_64-linux-gnu/libm.so.6");
		m_allowed_readable_paths.insert("/lib/x86_64-linux-gnu/libpthread.so.0");
		m_allowed_readable_paths.insert("/lib/x86_64-linux-gnu/libdl.so.2");
		m_allowed_readable_paths.insert("/lib/x86_64-linux-gnu/libstdc++.so.6");
		m_allowed_readable_paths.insert("/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v2/libstdc++.so.6");
		m_allowed_readable_paths.insert("/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libstdc++.so.6");
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
			m_fds[m_next_socket_fd] = {fd, is_writable};
			return m_next_socket_fd++;
		} else {
			m_fds[m_next_file_fd] = {fd, is_writable};
			return m_next_file_fd++;
		}
	}

	std::optional<FileDescriptors::Entry*> FileDescriptors::entry_for_vfd(int vfd)
	{
		auto it = m_fds.find(vfd);
		if (it != m_fds.end()) {
			return &it->second;
		}
		return std::nullopt;
	}

	int FileDescriptors::translate(int vfd) const
	{
		auto it = m_fds.find(vfd);
		if (it != m_fds.end()) {
			return it->second.real_fd;
		}
		throw std::runtime_error("Invalid virtual file descriptor");
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
		this->m_allowed_readable_paths.insert(path);
	}

	bool FileDescriptors::is_readable_path(std::string& modifiable_path) const noexcept
	{
		if (m_open_readable)
		{
			if (m_open_readable(modifiable_path))
				return true;
		}
		auto it = m_allowed_readable_paths.find(modifiable_path);
		return (it != m_allowed_readable_paths.end());
	}

	bool FileDescriptors::is_writable_path(std::string& modifiable_path) const noexcept
	{
		if (m_open_writable) {
			return m_open_writable(modifiable_path);
		}
		return false;
	}

} // tinykvm
