#include "fds.hpp"

#include "../machine.hpp"
#include "threads.hpp"
#include <algorithm>
#include <cstring>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
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
		: m_machine(machine),
		  m_current_working_directory_fd(AT_FDCWD)
	{
		m_allowed_readable_paths =
			std::make_shared<std::unordered_set<std::string>>();
		m_allowed_readable_paths_starts_with =
			std::make_shared<std::vector<std::string>>();
		// Add all common standard libraries to the list of allowed readable paths
		this->add_readonly_file("/lib64/ld-linux-x86-64.so.2");
		this->add_readonly_file("/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
		this->add_readonly_file("/lib/x86_64-linux-gnu/libgcc_s.so.1");
		this->add_readonly_file("/lib/x86_64-linux-gnu/libc.so.6");
		this->add_readonly_file("/lib/x86_64-linux-gnu/libm.so.6");
		this->add_readonly_file("/lib/x86_64-linux-gnu/libpthread.so.0");
		this->add_readonly_file("/lib/x86_64-linux-gnu/libdl.so.2");
		this->add_readonly_file("/lib/x86_64-linux-gnu/libstdc++.so.6");
		this->add_readonly_file("/lib/x86_64-linux-gnu/librt.so.1");
		this->add_readonly_file("/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v2/libstdc++.so.6");
		this->add_readonly_file("/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v3/libstdc++.so.6");
		this->add_readonly_file("/lib/x86_64-linux-gnu/glibc-hwcaps/x86-64-v4/libstdc++.so.6");

		// XXX: TODO: Create proper redirects for stdout/stderr by
		// for example providing a pipe to stdout/stderr.
	}

	FileDescriptors::~FileDescriptors()
	{
		for (auto& [fd, entry] : m_fds) {
			if (entry.real_fd >= 0 && !entry.is_forked) {
				close(entry.real_fd);
			}
		}
	}

	void FileDescriptors::reset_to(const FileDescriptors& other)
	{
		// Close all current file descriptors, except if forked
		for (auto& [fd, entry] : m_fds) {
			if (entry.real_fd > 2 && !entry.is_forked) {
				close(entry.real_fd);
			}
		}
		// Clear the current file descriptors
		m_fds.clear();
		m_next_file_fd = other.m_next_file_fd;
		m_next_socket_fd = other.m_next_socket_fd;
		m_allowed_readable_paths = other.m_allowed_readable_paths;
		this->m_max_files = other.m_max_files;
		this->m_total_fds_opened = other.m_total_fds_opened;
		this->m_max_total_fds_opened = other.m_max_total_fds_opened;
		// Deep copy the master epoll FDs
		this->m_epoll_fds.clear();
		for (auto [vfd, entry] : other.m_epoll_fds) {
			// Check if it's a shared epoll fd
			if (!entry->shared_epoll_fds.empty())
			{
				// Check if one of the shared epoll fds is already in the list
				for (auto shared_vfd : entry->shared_epoll_fds) {
					auto it = this->m_epoll_fds.find(shared_vfd);
					if (it != this->m_epoll_fds.end()) {
						// Found a shared epoll fd, so we can *share* the entry
						this->m_epoll_fds.insert_or_assign(vfd, it->second);
						if (UNLIKELY(this->m_verbose)) {
							fprintf(stderr, "TinyKVM: Sharing epoll fd %d with %d\n", vfd, shared_vfd);
						}
						// Continue to the next entry
						continue;
					}
				}
			}
			auto cloned_entry = std::make_shared<EpollEntry>();
			*cloned_entry = *entry;
			this->m_epoll_fds.insert_or_assign(vfd, std::move(cloned_entry));
		}
		// For each socketpair and pipe2 pair, we need to create a new pair
		// and add them to the list of managed file descriptors.
		for (auto sp : other.m_sockets) {
			// Create a new socketpair or pipe2 pair
			int pair[2] = {-1, -1};
			switch (sp.type) {
				case SocketType::PIPE2:
					if (pipe2(pair, 0) < 0) {
						fprintf(stderr, "TinyKVM: Failed to create pipe2\n");
						throw std::runtime_error("TinyKVM: Failed to create pipe2");
					}
					// Manage the new pair using *the same* vfd as the original pair
					this->manage_as(sp.vfd1, pair[0], false, true);
					this->manage_as(sp.vfd2, pair[1], false, true);
					if (UNLIKELY(this->m_verbose)) {
						fprintf(stderr, "TinyKVM: Created new pipe2 pair %d %d\n", sp.vfd1, sp.vfd2);
					}
					break;
				case SocketType::SOCKETPAIR:
					if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0, pair) < 0) {
						fprintf(stderr, "TinyKVM: Failed to create socketpair\n");
						throw std::runtime_error("TinyKVM: Failed to create socketpair");
					}
					this->manage_as(sp.vfd1, pair[0], true, true);
					this->manage_as(sp.vfd2, pair[1], true, true);
					if (UNLIKELY(this->m_verbose)) {
						fprintf(stderr, "TinyKVM: Created new socketpair %d %d\n", sp.vfd1, sp.vfd2);
					}
					break;
				case SocketType::EVENTFD: {
					const int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
					if (fd < 0) {
						fprintf(stderr, "TinyKVM: Failed to create eventfd2\n");
						throw std::runtime_error("TinyKVM: Failed to create eventfd2");
					}
					this->manage_as(sp.vfd1, fd, false, true);
					if (UNLIKELY(this->m_verbose)) {
						fprintf(stderr, "TinyKVM: Created new eventfd2 %d (%d)\n", sp.vfd1, fd);
					}
					break;
				}
				case SocketType::DUPFD: {
					// This is a duplicated fd, so we need to create a new one
					// and manage it as a duplicate of the original fd.
					const int ret = dup(sp.vfd1);
					if (ret < 0) {
						fprintf(stderr, "TinyKVM: Failed to duplicate a DUPFD during reset\n");
						throw std::runtime_error("TinyKVM: Failed to duplicate a DUPFD during reset");
					}
					this->manage_as(sp.vfd2, ret, false, true);
					if (UNLIKELY(this->m_verbose)) {
						fprintf(stderr, "TinyKVM: Created new dupfd %d (%d)\n", sp.vfd2, ret);
					}
					break;
				}
				default:
					fprintf(stderr, "TinyKVM: Unknown socket type %d\n", sp.type);
					throw std::runtime_error("TinyKVM: Unknown socket type");
			}
		}
	}

	int FileDescriptors::manage(int fd, bool is_socket, bool is_writable)
	{
		if (fd < 0) {
			throw std::runtime_error("TinyKVM: Invalid file descriptor in FileDescriptors::add()");
		}
		if (this->m_total_fds_opened >= this->m_max_total_fds_opened) {
			// We have a limit on the total number of file descriptors,
			// so since we aren't going to manage this fd, we need to close it.
			close(fd);
			throw std::runtime_error("TinyKVM: Too many opened fds in total, max_total_fds_opened = " +
				std::to_string(this->m_max_total_fds_opened));
		}
		if (this->m_fds.size() >= this->m_max_files) {
			close(fd);
			throw std::runtime_error("TinyKVM: Too many open files, max_files = " +
				std::to_string(this->m_max_files));
		}
		this->m_total_fds_opened ++;

		if (is_socket) {
			m_fds[m_next_socket_fd] = {fd, is_writable, false};
			return m_next_socket_fd++;
		} else {
			m_fds[m_next_file_fd] = {fd, is_writable, false};
			return m_next_file_fd++;
		}
	}
	int FileDescriptors::manage_duplicate(int original_vfd, int fd, bool is_socket, bool is_writable)
	{
		const int ret = this->manage(fd, is_socket, is_writable);
		if (ret < 0) {
			return ret;
		}
		// Check if the fd is (for example) an epoll fd, or another tracked type
		auto eit = m_epoll_fds.find(original_vfd);
		if (eit != m_epoll_fds.end()) {
			// Create a shared entry for the new fd
			eit->second->shared_epoll_fds.insert(original_vfd);
			eit->second->shared_epoll_fds.insert(ret);
			this->m_epoll_fds[ret] = eit->second;
			if (UNLIKELY(this->m_verbose)) {
				fprintf(stderr, "TinyKVM: Managing shared epoll fd %d (%d)\n", ret, fd);
			}
		} else {
			this->add_socket_pair({fd, ret, FileDescriptors::SocketType::DUPFD});
			if (UNLIKELY(this->m_verbose)) {
				fprintf(stderr, "TinyKVM: Managing new duplicated fd %d (%d)\n", ret, fd);
			}
		}
		return ret;
	}
	void FileDescriptors::manage_as(int vfd, int fd, bool is_socket, bool is_writable)
	{
		(void)is_socket; // Unused
		if (fd < 0) {
			throw std::runtime_error("TinyKVM: Invalid fd in FileDescriptors::manage_as()");
		}
		this->m_total_fds_opened++;
		if (this->m_total_fds_opened >= this->m_max_total_fds_opened) {
			// We have a limit on the total number of file descriptors,
			// so since we aren't going to manage this fd, we need to close it.
			close(fd);
			throw std::runtime_error("TinyKVM: Too many opened fds in total, max_total_fds_opened = " +
				std::to_string(this->m_max_total_fds_opened));
		}
		if (this->m_fds.size() >= this->m_max_files) {
			close(fd);
			throw std::runtime_error("TinyKVM: Too many open files, max_files = " +
				std::to_string(this->m_max_files));
		}

		Entry entry{fd, is_writable, false};
		m_fds.insert_or_assign(vfd, entry);
		// Make sure we are not overwriting the vfd
		this->m_next_file_fd = std::max(this->m_next_file_fd, vfd + 1);
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
				if (UNLIKELY(this->m_verbose)) {
					fprintf(stderr, "TinyKVM: Creating fork entry for %d (%d)\n", entry->real_fd, vfd);
				}
				auto eit = m_epoll_fds.find(vfd);
				if (eit != m_epoll_fds.end()) {
					// This is an epoll fd which cannot be shared with forks
					// however, we have all the vfds that are in the epoll
					// so we can create a new one, duplicate all the vfds
					// and return the new fd.
					auto& epoll_entry = eit->second;
					// Check if this is a shared epoll fd
					if (!epoll_entry->shared_epoll_fds.empty()) {
						// Check if we are already managing any of the vfds in
						// the shared epoll entries
						for (auto shared_vfd : epoll_entry->shared_epoll_fds) {
							// This is the one we are investigating, so skip it
							if (shared_vfd == vfd)
								continue;

							auto it = m_fds.find(shared_vfd);
							if (it != m_fds.end()) {
								// We are already managing this fd, so we can
								// just return the fd.
								const int real_fd = it->second.real_fd;
								if (UNLIKELY(this->m_verbose)) {
									fprintf(stderr, "TinyKVM: Found shared epoll fd %d (%d)\n", vfd, real_fd);
								}
								m_fds[vfd] = {real_fd, it->second.is_writable, true};
								return real_fd;
							}
						}
					}

					int new_fd = epoll_create1(0);
					if (new_fd < 0) {
						throw std::runtime_error("TinyKVM: Failed to create epoll fd");
					}
					// Since we are creating a new epoll fd, it's not forked
					// Register immediately in case of exception
					m_fds[vfd] = {new_fd, true, false};
					if (UNLIKELY(this->m_verbose)) {
						fprintf(stderr, "TinyKVM: Created new epoll fd %d (%d)\n", vfd, new_fd);
					}
					// Add all the fds to the new epoll fd
					for (auto it : epoll_entry->epoll_fds) {
						const int entry_vfd = it.first;
						epoll_event& entry_event = it.second;
						int real_fd = this->translate(entry_vfd);
						if (real_fd < 0) {
							throw std::runtime_error("TinyKVM: Failed to translate fd");
						}
						if (epoll_ctl(new_fd, EPOLL_CTL_ADD, real_fd, &entry_event) < 0) {
							if (errno != EEXIST) {
								throw std::runtime_error("TinyKVM: Failed to add fd to epoll");
							}
						}
						if (UNLIKELY(this->m_verbose)) {
							std::string event_str;
							if (entry_event.events & EPOLLIN) {
								event_str += "EPOLLIN ";
							}
							if (entry_event.events & EPOLLOUT) {
								event_str += "EPOLLOUT ";
							}
							if (entry_event.events & EPOLLERR) {
								event_str += "EPOLLERR ";
							}
							if (entry_event.events & EPOLLHUP) {
								event_str += "EPOLLHUP ";
							}
							if (entry_event.events & EPOLLRDHUP) {
								event_str += "EPOLLRDHUP ";
							}
							if (entry_event.events & EPOLLET) {
								event_str += "EPOLLET ";
							}
							if (entry_event.events & EPOLLONESHOT) {
								event_str += "EPOLLONESHOT ";
							}
							fprintf(stderr, "TinyKVM: -> Added fd %d (%d) with event [%s] data i32=%d u32=0x%X u64=0x%lX\n",
								real_fd, entry_vfd, event_str.c_str(),
								entry_event.data.fd, entry_event.data.u32, entry_event.data.u64);
						}
					}
					return new_fd;
				}
				// We need to manage the *same* virtual file descriptor as the main
				// VM, so we need to set the real_fd of the new entry to the new fd.
				m_fds[vfd] = {entry->real_fd, entry->is_writable, true};
				return entry->real_fd;
			}
		}
		return -1;
	}

	int FileDescriptors::translate_writable_vfd(int vfd)
	{
		if (vfd >= 0 && vfd < 3) {
			return this->m_stdout_redirects.at(vfd);
		}
		auto it = m_fds.find(vfd);
		if (it != m_fds.end()) {
			if (!it->second.is_writable) {
				throw std::runtime_error("TinyKVM: File descriptor is not writable");
			}
			return it->second.real_fd;
		}
		if (this->m_find_ro_master_vm_fd) {
			auto opt_entry = this->m_find_ro_master_vm_fd(vfd);
			if (opt_entry) {
				const auto& entry = *opt_entry;
				if (!entry->is_writable) {
					throw std::runtime_error("TinyKVM: File descriptor is not writable");
				}
				if (UNLIKELY(this->m_verbose)) {
					fprintf(stderr, "TinyKVM: Creating fork entry for %d (%d)\n", entry->real_fd, vfd);
				}
				// We need to manage the *same* virtual file descriptor as the main
				// VM, so we need to set the real_fd of the new entry to the new fd.
				m_fds[vfd] = {entry->real_fd, entry->is_writable, true};
				return entry->real_fd;
			}
		}
		return -1;
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
		return -1;
	}
	int FileDescriptors::translate_unless_forked_then(int vfd, std::function<int(const Entry&)> func, bool must_be_writable)
	{
		if (vfd >= 0 && vfd < 3) {
			return this->m_stdout_redirects.at(vfd);
		}
		auto it = m_fds.find(vfd);
		if (it != m_fds.end()) {
			if (!it->second.is_writable && must_be_writable) {
				throw std::runtime_error("TinyKVM: File descriptor is not writable");
			}
			if (it->second.is_forked) {
				fprintf(stderr, "TinyKVM: Forked file descriptor %d (%d) is not allowed\n", it->second.real_fd, vfd);
				return func(it->second);
			}
			return it->second.real_fd;
		}
		if (this->m_find_ro_master_vm_fd) {
			auto opt_entry = this->m_find_ro_master_vm_fd(vfd);
			if (opt_entry) {
				const auto* entry = *opt_entry;
				if (UNLIKELY(this->m_verbose)) {
					fprintf(stderr, "TinyKVM: Creating fork duplicate for %d (%d)\n", entry->real_fd, vfd);
				}
				if (!entry->is_writable && must_be_writable) {
					throw std::runtime_error("TinyKVM: File descriptor is not writable");
				}
				// We need to manage the *same* virtual file descriptor as the main
				// VM, so we need to set the real_fd of the new entry to the new fd.
				const int new_fd = func(*entry);
				const bool is_forked = false; // We just duplicated it, so we own it
				m_fds[vfd] = {new_fd, entry->is_writable, is_forked};
				return new_fd;
			}
		}
		// If the fd is not found, return -1
		return -1;
	}

	void FileDescriptors::free(int vfd)
	{
		auto it = m_fds.find(vfd);
		if (it != m_fds.end()) {
			if (UNLIKELY(it->second.is_forked))
				throw std::runtime_error("Cannot free a forked file descriptor");
			close(it->second.real_fd);
			m_fds.erase(it);
		}
		// Potentially remove the fd from the epoll fds
		auto res = m_epoll_fds.erase(vfd);
		if (res > 0) {
			if (UNLIKELY(this->m_verbose)) {
				printf("TinyKVM: Removed epoll fd %d\n", vfd);
			}
		}
		// Potentially remove the fd from the socket pairs
		// NOTE: If one of the sockets are closed, we remove the whole entry
		auto it2 = std::remove_if(m_sockets.begin(), m_sockets.end(),
			[vfd](const SocketPair& sp) {
				return sp.vfd1 == vfd || sp.vfd2 == vfd;
			});
		if (it2 != m_sockets.end()) {
			if (UNLIKELY(this->m_verbose)) {
				printf("TinyKVM: Removing socket pair %d %d\n", it2->vfd1, it2->vfd2);
			}
			m_sockets.erase(it2, m_sockets.end());
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

	void FileDescriptors::add_readonly_prefix(const std::string& path)
	{
		if (path.empty())
			throw std::runtime_error("Empty path in FileDescriptors::add_readonly_prefix");
		if (path.find("..") != std::string::npos)
			throw std::runtime_error("Path contains parent directory in FileDescriptors::add_readonly_prefix");
		this->m_allowed_readable_paths_starts_with->push_back(path);
	}

	void FileDescriptors::add_writable_prefix(const std::string& path) {
		if (path.empty())
			throw std::runtime_error("Empty path in FileDescriptors::add_writable_prefix");
		if (path.find("..") != std::string::npos)
			throw std::runtime_error("Path contains parent directory in FileDescriptors::add_writable_prefix");
		this->m_allowed_writable_paths_starts_with.push_back(path);
	}

	bool FileDescriptors::is_readable_path(std::string& modifiable_path) const noexcept
	{
		if (modifiable_path.empty())
			return false;

		if (m_open_readable)
		{
			if (m_open_readable(modifiable_path)) {
				if (UNLIKELY(this->m_verbose)) {
					fprintf(stderr, "TinyKVM: %s is allowed (read, callback)\n", modifiable_path.c_str());
				}
				return true;
			}
		}
		auto it = m_allowed_readable_paths->find(modifiable_path);
		if (it != m_allowed_readable_paths->end())
		{
			if (UNLIKELY(this->m_verbose)) {
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
				if (UNLIKELY(this->m_verbose)) {
					fprintf(stderr, "TinyKVM: %s is allowed (read, prefixed)\n", modifiable_path.c_str());
				}
				return true;
			}
		}
		if (UNLIKELY(this->m_verbose)) {
			fprintf(stderr, "TinyKVM: %s is not a readable path\n", modifiable_path.c_str());
		}
		return false;
	}

	bool FileDescriptors::is_writable_path(std::string& modifiable_path) const noexcept
	{
		// Check if the path contains any parent-directory components (..)
		if (modifiable_path.find("..") != std::string::npos) {
			return false;
		}
		// Check if the path is in the allowed writable prefix paths
		for (const auto& path : m_allowed_writable_paths_starts_with) {
			if (modifiable_path.find(path) == 0) {
				if (UNLIKELY(this->m_verbose)) {
					fprintf(stderr, "TinyKVM: %s is allowed (write, prefixed)\n", modifiable_path.c_str());
				}
				return true;
			}
		}
		// Fallback to the writable path callback if it is set
		if (m_open_writable) {
			bool success = m_open_writable(modifiable_path);
			if (this->m_verbose && success) {
				fprintf(stderr, "TinyKVM: %s is allowed (write, callback)\n", modifiable_path.c_str());
			}
			return success;
		}
		if (UNLIKELY(this->m_verbose)) {
			fprintf(stderr, "TinyKVM: %s is not a writable path\n", modifiable_path.c_str());
		}
		return false;
	}

	bool FileDescriptors::validate_socket_address(const int socket_fd, struct sockaddr_storage& socket_address) const noexcept
	{
		if (m_connect_socket) {
			return m_connect_socket(socket_fd, socket_address);
		}
		// If no callback is set, we disallow all connect() calls.
		return false;
	}

	/// Current working directory ///

	void FileDescriptors::set_current_working_directory(const std::string& path) noexcept
	{
		m_current_working_directory = path;
		// Set the current working directory fd by opening the path
		int fd = open(path.c_str(), O_RDONLY | O_DIRECTORY);
		m_current_working_directory_fd = fd;
		if (fd < 0) {
			if (UNLIKELY(this->m_verbose)) {
				fprintf(stderr, "TinyKVM: Failed to set current working directory to %s\n", path.c_str());
			}
		} else if (UNLIKELY(this->m_verbose)) {
			fprintf(stderr, "TinyKVM: Set current working directory to %s with fd %d\n",
				path.c_str(), fd);
		}
	}

	int FileDescriptors::transform_relative_fd(int fd) const noexcept
	{
		if (fd == AT_FDCWD) {
			return m_current_working_directory_fd;
		}
		return fd;
	}

	/// Symlink related ///

	bool FileDescriptors::resolve_symlink(std::string& modifiable_path) const noexcept
	{
		if (m_resolve_symlink)
		{
			if (m_resolve_symlink(modifiable_path)) {
				if (UNLIKELY(this->m_verbose)) {
					fprintf(stderr, "TinyKVM: A symlink lead to %s\n", modifiable_path.c_str());
				}
				return true;
			}
		}
		if (UNLIKELY(this->m_verbose)) {
			fprintf(stderr, "TinyKVM: %s is not a symlink\n", modifiable_path.c_str());
		}
		return false;
	}

	/// epoll related ///

	FileDescriptors::EpollEntry& FileDescriptors::get_epoll_entry_for_vfd(int vfd)
	{
		auto it = m_epoll_fds.find(vfd);
		if (it != m_epoll_fds.end()) {
			return *it->second;
		}
		auto res = m_epoll_fds.try_emplace(vfd, std::make_shared<EpollEntry>());
		if (!res.second) {
			throw std::runtime_error("TinyKVM: Failed to insert epoll entry");
		}
		return *res.first->second;
	}

	void FileDescriptors::add_socket_pair(const SocketPair& pair)
	{
		if (m_machine.is_forked()) {
			// We don't manage any extra state in the forks
			return;
		}

		if (this->m_sockets.size() >= 64) {
			throw std::runtime_error("TinyKVM: Too many recorded sockets: " +
				std::to_string(this->m_sockets.size()));
		}

		this->m_sockets.push_back(pair);
		if (UNLIKELY(this->m_verbose)) {
			std::string type;
			switch (pair.type) {
				case SocketType::PIPE2:
					type = "pipe2";
					break;
				case SocketType::SOCKETPAIR:
					type = "socketpair";
					break;
				case SocketType::EVENTFD:
					type = "eventfd";
					break;
				case SocketType::DUPFD:
					type = "dupfd";
					break;
				default:
					type = "unknown";
					break;
			}
			fprintf(stderr, "TinyKVM: Recorded socket pair %d %d (%s)\n",
				pair.vfd1, pair.vfd2, type.c_str());
		}
	}

	std::string FileDescriptors::sockaddr_to_string(const struct sockaddr_storage& addr) const
	{
		std::string addr_family_str;
		std::string addr_str;
		switch (addr.ss_family)
		{
		case AF_INET:
			addr_family_str = "AF_INET";
			break;
		case AF_INET6:
			addr_family_str = "AF_INET6";
			break;
		case AF_UNIX:
			addr_family_str = "AF_UNIX";
			break;
		default:
			addr_family_str = "AF_UNKNOWN";
			break;
		}
		if (addr.ss_family == AF_INET)
		{
			struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
			addr_str = inet_ntoa(addr_in->sin_addr);
			addr_str += ":" + std::to_string(ntohs(addr_in->sin_port));
		}
		else if (addr.ss_family == AF_INET6)
		{
			struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&addr;
			addr_str.resize(INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &addr_in6->sin6_addr, 
						addr_str.data(), INET6_ADDRSTRLEN);
			addr_str = "[" + addr_str + "]";
			addr_str += ":" + std::to_string(ntohs(addr_in6->sin6_port));
		}
		else if (addr.ss_family == AF_UNIX)
		{
			struct sockaddr_un *addr_un = (struct sockaddr_un *)&addr;
			addr_str = addr_un->sun_path;
		}
		else
		{
			addr_str = "UNKNOWN(" + std::to_string(addr.ss_family) + ")";
		}

		return addr_family_str + " " + addr_str;
	}
} // tinykvm
