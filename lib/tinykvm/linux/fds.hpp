#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <sys/epoll.h>
struct sockaddr_storage;

namespace tinykvm
{
	struct Machine;

	struct FileDescriptors
	{
		static constexpr unsigned DEFAULT_MAX_FILES = 256;
		static constexpr unsigned DEFAULT_TOTAL_FILES = 4096;
		static constexpr int SOCKET_BIT = 0x40000000;
		struct Entry
		{
			int real_fd = -1;
			bool is_writable = false;
			bool is_forked = false;
		};
		using open_readable_t = std::function<bool(std::string&)>;
		using open_writable_t = std::function<bool(std::string&)>;
		using connect_socket_t = std::function<bool(int, struct sockaddr_storage&)>;
		using resolve_symlink_t = std::function<bool(std::string&)>;
		using find_readonly_master_vm_fd_t = std::function<std::optional<const Entry*>(int)>;

		FileDescriptors(Machine& machine);
		~FileDescriptors();
		void reset_to(const FileDescriptors& other);

		/// @brief Add a file descriptor to the list of managed FDs.
		/// @param fd The real file descriptor.
		/// @param is_socket True if the file descriptor is a socket.
		/// @return The virtual file descriptor.
		int manage(int fd, bool is_socket, bool is_writable = false);
		void manage_as(int vfd, int fd, bool is_socket, bool is_writable);

		/// @brief Remove a virtual file descriptor from the list of managed FDs.
		/// @param vfd The virtual file descriptor to remove.
		void free(int vfd);

		std::optional<const Entry*> entry_for_vfd(int vfd) const;

		/// @brief Translate a virtual file descriptor to a real file descriptor,
		/// or throw an exception, failing execution.
		/// @param vfd The virtual file descriptor to translate.
		/// @return The real file descriptor.
		int translate(int vfd);

		/// @brief Translate a virtual file descriptor to a real file descriptor,
		/// or throw an exception, failing execution. This is used for writable
		/// file descriptors, and will throw an exception if the file descriptor
		/// is not marked as writable.
		int translate_writable_vfd(int vfd);

		/// @brief Check if a file descriptor is a socket or a file. If this fd was
		/// created by duplicating an fd from the main VM, this function instead
		/// returns -1, preventing a disallowed operation on the fd. Eg. it's allowed
		/// to close a duplicated fd, but not use epoll_ctl() on it.
		/// @param vfd The virtual file descriptor to check.
		/// @return The real file descriptor, or -1 if the fd was created by
		/// duplicating an fd from the main VM.
		int translate_unless_forked(int vfd);
		int translate_unless_forked_then(int vfd, std::function<int(const Entry&)> func, bool must_be_writable = false);

		bool is_socket_vfd(int vfd) const noexcept {
			return (vfd & SOCKET_BIT) != 0;
		}
		bool is_file_vfd(int vfd) const noexcept {
			return (vfd & SOCKET_BIT) == 0;
		}

		/// @brief Set the callback for checking if a path is allowed to be opened
		/// for reading. This is used to check if a path is allowed to be opened
		/// for reading. The callback should return true if the path is allowed,
		/// and false otherwise. The path may be modified by the callback,
		/// indicating which real path to open.
		/// @param callback The callback to set.
		void set_open_readable_callback(open_readable_t callback) noexcept {
			m_open_readable = callback;
		}

		/// @brief Set the callback for checking if a path is allowed to be opened
		/// for writing. This is used to check if a path is allowed to be opened
		/// for writing. The callback should return true if the path is allowed,
		/// and false otherwise. The path may be modified by the callback,
		/// indicating which real path to open.
		/// @param callback The callback to set.
		void set_open_writable_callback(open_writable_t callback) noexcept {
			m_open_writable = callback;
		}

		/// @brief Add a read-only file
		/// @note If the path starts with a $ character, it is treated as a prefix
		/// for the allowed paths. This is useful for allowing directories and
		/// other prefixes. The path must not contain any parent-directory
		/// components (..).
		/// @param path The path to add.
		void add_readonly_file(const std::string& path);

		/// @brief Add a read-only file that starts with a prefix. This is used
		/// to allow directories and other prefixes. The path must not contain
		/// any parent-directory components (..).
		/// @param path The prefix path to add.
		void add_readonly_prefix(const std::string& path);

		/// @brief Add a writable prefix path
		/// @note The path must not contain any parent-directory components (..).
		/// @note This is not passed to forks, so it is not accessible in forked
		/// VMs. Can only be used in the main VM (during startup).
		/// @param path The prefix path to add.
		void add_writable_prefix(const std::string& path);

		/// @brief Check if a path is allowed to be opened for reading.
		/// @param modifiable_path The path to check. This may be modified by
		/// the callback to indicate which real path to open.
		/// @return True if the path is allowed to be opened for reading, false
		/// otherwise. The path may be modified by the callback, indicating
		/// which real path to open.
		bool is_readable_path(std::string& modifiable_path) const noexcept;

		/// @brief Check if a path is writable. Paths are usually not writable,
		/// but this can be overridden by setting the open_writable callback.
		/// @param modifiable_path 
		/// @return True if the path is writable, false otherwise. The path
		/// may be modified by the callback, indicating which real path to open.
		bool is_writable_path(std::string& modifiable_path) const noexcept;

		/// @brief Check if a path can be treated as a symlink, and resolve it.
		/// @param modifiable_path The path to check. This *will* be modified by
		/// the callback to indicate where the symlink points to.
		/// @return True if the path is a symlink, false otherwise. The path
		/// *will* be modified by the callback, indicating where the symlink
		/// points to.
		bool resolve_symlink(std::string& modifiable_path) const noexcept;

		/// @brief Set the callback for resolving symlinks. This is used to check
		/// if a path is a symlink. The callback should return true if the path
		/// is a symlink, and false otherwise. The path *will* be modified by the
		/// callback, indicating where the symlink points to.
		/// @param callback The callback to set.
		void set_resolve_symlink_callback(resolve_symlink_t callback) noexcept {
			m_resolve_symlink = callback;
		}

		/// @brief Set the maximum number of file descriptors that can be opened.
		/// @param max_files The maximum number of file descriptors that can be
		/// opened.
		void set_max_files(uint16_t max_files) noexcept {
			m_max_files = max_files;
		}

		/// @brief Get the maximum number of file descriptors that can be opened.
		/// @return The maximum number of file descriptors that can be opened.
		uint16_t get_max_files() const noexcept {
			return m_max_files;
		}

		/// @brief Set the maximum number of sockets that can be opened.
		/// @param max_sockets The maximum number of sockets that can be opened.
		void set_max_sockets(uint16_t max_sockets) noexcept {
			m_max_sockets = max_sockets;
		}

		/// @brief Get the maximum number of sockets that can be opened.
		/// @return The maximum number of sockets that can be opened.
		uint16_t get_max_sockets() const noexcept {
			return m_max_sockets;
		}

		/// @brief Set the maximum number of file descriptors that can be opened
		/// in total. This is the sum of the maximum number of files and sockets
		/// that can be opened.
		/// @param max_total_fds_opened The maximum number of file descriptors
		/// that can be opened in total.
		void set_max_total_fds_opened(uint16_t max_total_fds_opened) noexcept {
			m_max_total_fds_opened = max_total_fds_opened;
		}

		/// @brief Get the maximum number of file descriptors that can be opened
		/// in total. This is the sum of the maximum number of files and sockets
		/// that can be opened.
		/// @return The maximum number of file descriptors that can be opened
		/// in total.
		uint16_t get_max_total_fds_opened() const noexcept {
			return m_max_total_fds_opened;
		}

		/// @brief Get the number of file descriptors that have been opened
		/// since the last reset. This is the number of file descriptors that
		/// are currently open, plus the number of file descriptors that have
		/// been closed. Includes files and sockets.
		/// @return The number of file descriptors that have been opened since
		/// the last reset. Includes files and sockets.
		uint16_t get_total_fds_opened() const noexcept {
			return m_total_fds_opened;
		}

		/// @brief Get the number of file descriptors that are currently open.
		/// Does not include sockets.
		/// @return The number of file descriptors that are currently open.
		uint16_t get_current_fds_opened() const noexcept {
			return m_fds.size();
		}

		/// @brief Get the number of sockets that are currently open.
		/// @return The number of sockets that are currently open.
		uint16_t get_current_sockets_opened() const noexcept {
			return m_fds.size() - m_stdout_redirects.size();
		}

		/// @brief Set a callback for connecting a socket. This is used to check if a
		/// socket is allowed to be connected. The callback should return true if the
		/// socket is allowed, and false otherwise. The socket may be modified by the
		/// callback, indicating which real socket to connect to. The argument is
		/// a vector of bytes that contains the socket address, eg. a struct sockaddr.
		/// @param callback The callback to set.
		void set_connect_socket_callback(connect_socket_t callback) noexcept {
			m_connect_socket = callback;
		}

		/// @brief Validate and modify the socket address. This is used to check if a
		/// socket is allowed to be connected. The callback should return true if the
		/// socket is allowed, and false otherwise. The socket may be modified by the
		/// callback, indicating which real socket to connect to. The argument is
		/// a vector of bytes that contains the socket address, eg. a sockaddr_storage.
		/// @param socket_address The socket address to validate and modify.
		/// @return True if the socket address is allowed, false otherwise.
		bool validate_socket_address(const int socket_fd, struct sockaddr_storage& socket_address) const noexcept;

		/// @brief Set the current working directory. This is used in a few system
		/// calls, such as getcwd() and chdir().
		/// @param path The path to set as the current working directory.
		void set_current_working_directory(const std::string& path) noexcept;

		/// @brief Get the current working directory. This is used in a few system
		/// calls, such as getcwd() and chdir().
		/// @return The current working directory.
		const std::string& current_working_directory() const noexcept {
			return m_current_working_directory;
		}

		/// @brief Transform a file descriptor to a file descriptor that is
		/// relative to the current working directory. This is used in a few
		/// at-related system calls, such as openat() and fstatat(). Only
		/// AT_FDCWD is transformed, all other file descriptors are returned as-is.
		/// @param fd The file descriptor to transform.
		/// @return The file descriptor that is relative to the current working
		/// directory.
		int transform_relative_fd(int fd) const noexcept;

		/// @brief Get the fd for the current working directory. This is used in a few
		/// at-related system calls, such as openat() and fstatat(). Only
		/// AT_FDCWD is transformed, all other file descriptors are returned as-is.
		/// @return The file descriptor that is relative to the current working
		/// directory.
		int current_working_directory_fd() const noexcept {
			return m_current_working_directory_fd;
		}

		/// @brief Set verbose mode. This will print out information about
		/// file descriptor management.
		/// @param verbose True to enable verbose mode, false to disable it.
		void set_verbose(bool verbose) noexcept {
			m_verbose = verbose;
		}

		/// @brief Set the callback for finding the read-only master VM file descriptor.
		/// This is used to find the real file descriptor for a virtual file
		/// descriptor that is a read-only master VM file descriptor.
		/// @param callback The callback to set.
		void set_find_readonly_master_vm_fd_callback(find_readonly_master_vm_fd_t callback) noexcept {
			m_find_ro_master_vm_fd = callback;
		}

		struct EpollEntry
		{
			int real_fd = -1;
			std::unordered_map<int, struct epoll_event> epoll_fds;
		};
		EpollEntry& get_epoll_entry_for_vfd(int vfd);
		enum SocketType : int {
			INVALID,
			PIPE2,
			SOCKETPAIR,
			EVENTFD,
		};
		struct SocketPair
		{
			int vfd1 = -1;
			int vfd2 = -1;
			SocketType type = INVALID;
		};
		void add_socket_pair(const SocketPair&);

		std::string sockaddr_to_string(const struct sockaddr_storage& addr) const;
	private:
		Machine& m_machine;
		std::map<int, Entry> m_fds;
		std::shared_ptr<std::unordered_set<std::string>> m_allowed_readable_paths;
		std::shared_ptr<std::vector<std::string>> m_allowed_readable_paths_starts_with;
		std::vector<std::string> m_allowed_writable_paths_starts_with; // Not passed to forks
		int m_next_file_fd = 0x1000;
		int m_next_socket_fd = 0x1000 | SOCKET_BIT;
		std::array<int, 3> m_stdout_redirects { 0, 1, 2 };
		std::string m_current_working_directory;
		int m_current_working_directory_fd = -1;
		bool m_verbose = false;
		open_readable_t m_open_readable;
		open_writable_t m_open_writable;
		resolve_symlink_t m_resolve_symlink;
		connect_socket_t m_connect_socket;
		find_readonly_master_vm_fd_t m_find_ro_master_vm_fd;
		uint16_t m_max_files = DEFAULT_MAX_FILES;
		uint16_t m_max_sockets = DEFAULT_MAX_FILES;
		uint16_t m_total_fds_opened = 0;
		uint16_t m_max_total_fds_opened = DEFAULT_TOTAL_FILES;

		std::map<int, EpollEntry> m_epoll_fds;
		std::vector<SocketPair> m_sockets;
	};
}
