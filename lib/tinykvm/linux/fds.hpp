#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_set>

namespace tinykvm
{
	struct Machine;

	struct FileDescriptors
	{
		static constexpr unsigned DEFAULT_MAX_FILES = 64;
		static constexpr int SOCKET_BIT = 0x40000000;
		struct Entry
		{
			int real_fd = -1;
			bool is_writable = false;
			bool is_forked = false;
		};
		using open_readable_t = std::function<bool(std::string&)>;
		using open_writable_t = std::function<bool(std::string&)>;
		using find_readonly_master_vm_fd_t = std::function<std::optional<const Entry*>(int)>;

		FileDescriptors(Machine& machine);
		~FileDescriptors();
		void reset_to(const FileDescriptors& other);

		/// @brief Add a file descriptor to the list of managed FDs.
		/// @param fd The real file descriptor.
		/// @param is_socket True if the file descriptor is a socket.
		/// @return The virtual file descriptor.
		int manage(int fd, bool is_socket, bool is_writable = false);

		/// @brief Remove a virtual file descriptor from the list of managed FDs.
		/// @param vfd The virtual file descriptor to remove.
		void free(int vfd);

		std::optional<const Entry*> entry_for_vfd(int vfd) const;

		/// @brief Translate a virtual file descriptor to a real file descriptor,
		/// or throw an exception, failing execution.
		/// @param vfd The virtual file descriptor to translate.
		/// @return The real file descriptor.
		int translate(int vfd);

		/// @brief Check if a file descriptor is a socket or a file. If this fd was
		/// created by duplicating an fd from the main VM, this function instead
		/// returns -1, preventing a disallowed operation on the fd. Eg. it's allowed
		/// to close a duplicated fd, but not use epoll_ctl() on it.
		/// @param vfd The virtual file descriptor to check.
		/// @return The real file descriptor, or -1 if the fd was created by
		/// duplicating an fd from the main VM.
		int translate_unless_forked(int vfd);

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
		void add_readonly_file(const std::string& path);

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

	private:
		Machine& m_machine;
		std::map<int, Entry> m_fds;
		std::shared_ptr<std::unordered_set<std::string>> m_allowed_readable_paths;
		std::shared_ptr<std::vector<std::string>> m_allowed_readable_paths_starts_with;
		int m_next_file_fd = 0x1000;
		int m_next_socket_fd = 0x1000 | SOCKET_BIT;
		std::array<int, 3> m_stdout_redirects { 0, 1, 2 };
		bool m_verbose = false;
		open_readable_t m_open_readable;
		open_writable_t m_open_writable;
		find_readonly_master_vm_fd_t m_find_ro_master_vm_fd;
		uint16_t m_max_files = DEFAULT_MAX_FILES;
		uint16_t m_max_sockets = DEFAULT_MAX_FILES;
		uint16_t m_total_fds_opened = 0;
		uint16_t m_max_total_fds_opened = DEFAULT_MAX_FILES;
	};
}
