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
		static constexpr int SOCKET_BIT = 0x40000000;
		struct Entry
		{
			int real_fd = -1;
			bool is_writable = false;
		};
		using open_readable_t = std::function<bool(std::string&)>;
		using open_writable_t = std::function<bool(std::string&)>;

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

		std::optional<Entry*> entry_for_vfd(int vfd);

		/// @brief Translate a virtual file descriptor to a real file descriptor,
		/// or throw an exception, failing execution.
		/// @param vfd The virtual file descriptor to translate.
		/// @return The real file descriptor.
		int translate(int vfd) const;

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

	private:
		Machine& m_machine;
		std::map<int, Entry> m_fds;
		std::shared_ptr<std::unordered_set<std::string>> m_allowed_readable_paths;
		std::shared_ptr<std::vector<std::string>> m_allowed_readable_paths_starts_with;
		int m_next_file_fd = 0x1000;
		int m_next_socket_fd = 0x1000 | SOCKET_BIT;
		bool m_verbose = true;
		open_readable_t m_open_readable;
		open_writable_t m_open_writable;
	};
}
