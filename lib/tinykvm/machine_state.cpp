#include "machine.hpp"

#include <fcntl.h>
#include <linux/kvm.h>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef TINYKVM_ARCH_AMD64
#include "amd64/amd64.hpp"
#endif
#include "linux/fds.hpp"
#include "linux/threads.hpp"

namespace tinykvm {

struct ColdStartThreadState {
	int tid;
	tinykvm_x86regs    regs;
	uint64_t 		   fsbase;
	uint64_t 		   clear_tid;
};
struct ColdStartThreads {
	size_t count;
	int current_tid;
};

struct ColdStartFds {
	// Note: We don't store *any* file descriptors, just the metadata
	// to reconstruct epoll event loops and socket pairs
	size_t epoll_entries;
	size_t socket_pairs;
	int next_vfd;
};
struct ColdStartEpollEntry {
	size_t epoll_fds;
	size_t shared_epoll_fds;
	int vfd;
};
struct ColdStartEpollFd {
	int vfd;
	struct epoll_event event;
};
struct ColdStartSharedEpollFd {
	int vfd;
};

struct ColdStartSocketPair {
	int vfd1;
	int vfd2;
	int type;
};

struct SnapshotState {
	static constexpr uint32_t MAGIC = 0x564D4353; // 'VMCS'
	uint32_t magic;
	uint32_t size;
	tinykvm_x86regs    regs;
	kvm_sregs          sregs;
	tinykvm_x86fpuregs fpu;
	bool m_prepped;
	bool m_forked;
	bool m_just_reset;
	bool m_relocate_fixed_mmap;

	Machine::address_t m_image_base;
	Machine::address_t m_stack_address;
	Machine::address_t m_heap_address;
	Machine::address_t m_brk_address;
	Machine::address_t m_brk_end_address;
	Machine::address_t m_start_address;
	Machine::address_t m_kernel_end;
	//MMapCache m_mmap_cache;
	Machine::address_t mmap_current;

	bool main_memory_writes;
	Machine::address_t m_page_tables;

	static constexpr size_t Size() noexcept { return 4096ul; }

	template <typename T>
	T* next(void*& current) {
		T* ret = reinterpret_cast<T*>(current);
		current = reinterpret_cast<char*>(current) + sizeof(T);
		// Bounds-check against end-of-structure
		if (reinterpret_cast<char*>(current) > reinterpret_cast<char*>(this) + Size()) {
			throw std::runtime_error("Out of bounds access on SnapshotState");
		}
		return ret;
	}
};
bool Machine::load_snapshot_state()
{
	if (!memory.has_loadable_snapshot_state()) {
		return false;
	}
	if (!this->memory.has_snapshot_area) {
		throw std::runtime_error("No snapshot state area allocated");
	}
	if (this->is_forked()) {
		throw std::runtime_error("Cannot load snapshot state into a forked VM");
	}
	void* map = this->memory.get_snapshot_state_area();
	SnapshotState& state = *reinterpret_cast<SnapshotState*>(map);
	if (state.magic != SnapshotState::MAGIC) {
		throw std::runtime_error("No valid snapshot state found");
	}
	if (state.size < sizeof(SnapshotState) || state.size > SnapshotState::Size()) {
		throw std::runtime_error("Invalid snapshot state size");
	}

	// Load the state into the VM
	try {
		this->set_registers(state.regs);
		this->set_special_registers(state.sregs);
		this->set_fpu_registers(state.fpu);
		this->m_prepped = state.m_prepped;
		this->m_forked = state.m_forked;
		this->m_just_reset = state.m_just_reset;
		this->m_relocate_fixed_mmap = state.m_relocate_fixed_mmap;
		this->m_image_base = state.m_image_base;
		this->m_stack_address = state.m_stack_address;
		this->m_heap_address = state.m_heap_address;
		this->m_brk_address = state.m_brk_address;
		this->m_brk_end_address = state.m_brk_end_address;
		this->m_start_address = state.m_start_address;
		this->m_kernel_end = state.m_kernel_end;
		this->m_mmap_cache.current() = state.mmap_current;
		this->memory.main_memory_writes = state.main_memory_writes;
		this->memory.page_tables = state.m_page_tables;

		void* current = reinterpret_cast<char*>(&state) + sizeof(SnapshotState);
		// Load the thread states
		ColdStartThreads* threads = state.next<ColdStartThreads>(current);
		if (threads->count > 0) {
			auto& mt = this->threads();
			for (size_t i = 0; i < threads->count; i++) {
				ColdStartThreadState* tstate = state.next<ColdStartThreadState>(current);
				Thread& thread = mt.create(tstate->tid);
				thread.stored_regs = tstate->regs;
				thread.fsbase = tstate->fsbase;
				thread.clear_tid = tstate->clear_tid;
			}
			mt.set_to_and_suspend_others(threads->current_tid);
		}
		// Load the file descriptor states
		ColdStartFds* fds = state.next<ColdStartFds>(current);
		auto& fdm = this->fds();
		fdm.set_vfd_start(fds->next_vfd);
		for (size_t i = 0; i < fds->epoll_entries; i++) {
			ColdStartEpollEntry* centry = state.next<ColdStartEpollEntry>(current);
			auto& entry = fdm.get_epoll_entry_for_vfd(centry->vfd);
			for (size_t j = 0; j < centry->epoll_fds; j++) {
				ColdStartEpollFd* cefd = state.next<ColdStartEpollFd>(current);
				entry.epoll_fds[cefd->vfd] = cefd->event;
			}
			for (size_t j = 0; j < centry->shared_epoll_fds; j++) {
				ColdStartSharedEpollFd* csefd = state.next<ColdStartSharedEpollFd>(current);
				entry.shared_epoll_fds.insert(csefd->vfd);
			}
		}
		for (size_t i = 0; i < fds->socket_pairs; i++) {
			ColdStartSocketPair* csp = state.next<ColdStartSocketPair>(current);
			FileDescriptors::SocketPair sp;
			sp.vfd1 = csp->vfd1;
			sp.vfd2 = csp->vfd2;
			sp.type = FileDescriptors::SocketType(csp->type);
			fdm.add_socket_pair(sp);
		}

	} catch (const MachineException& me) {
		fprintf(stderr, "Failed to set cold start state: %s Data: 0x%#lX\n",
			me.what(), me.data());
		return false;
	}
	return true;
}
void Machine::save_snapshot_state_now() const
{
	if (this->is_forked()) {
		throw std::runtime_error("Cannot save snapshot state of a forked VM");
	}
	void* map = this->memory.get_snapshot_state_area();
	SnapshotState& state = *reinterpret_cast<SnapshotState*>(map);
	try {
		state.magic = SnapshotState::MAGIC;
		state.size  = 0; // Invalid (for now)
		state.regs  = this->registers();
		state.sregs = this->get_special_registers();
		state.fpu   = this->fpu_registers();
		state.m_prepped = this->m_prepped;
		state.m_forked = this->m_forked;
		state.m_just_reset = this->m_just_reset;
		state.m_relocate_fixed_mmap = this->m_relocate_fixed_mmap;
		state.m_image_base = this->m_image_base;
		state.m_stack_address = this->m_stack_address;
		state.m_heap_address = this->m_heap_address;
		state.m_brk_address = this->m_brk_address;
		state.m_brk_end_address = this->m_brk_end_address;
		state.m_start_address = this->m_start_address;
		state.m_kernel_end = this->m_kernel_end;
		state.mmap_current = this->m_mmap_cache.current();
		state.main_memory_writes = this->memory.main_memory_writes;
		state.m_page_tables = this->memory.page_tables;

		void* current = reinterpret_cast<char*>(&state) + sizeof(SnapshotState);
		// Save the multi-threading state
		ColdStartThreads* threads = state.next<ColdStartThreads>(current);
		if (this->has_threads()) {
			threads->count = this->m_mt->size();
			threads->current_tid = this->m_mt->gettid();
			// Save each thread's state
			for (const auto& [tid, thread] : this->m_mt->threads()) {
				ColdStartThreadState* tstate = state.next<ColdStartThreadState>(current);
				tstate->tid = tid;
				tstate->regs = thread.stored_regs;
				tstate->fsbase = thread.fsbase;
				tstate->clear_tid = thread.clear_tid;
			}
		} else {
			threads->count = 0;
		}

		// Save the file descriptor states
		ColdStartFds* fds = state.next<ColdStartFds>(current);
		const auto& fdm = this->fds();
		fds->next_vfd = fdm.vfd_start();
		const auto& epoll_entries = fdm.get_epoll_entries();
		fds->epoll_entries = epoll_entries.size();
		fds->socket_pairs = fdm.get_socket_pairs().size();
		// Epoll reconstruction entries
		for (const auto& [vfd, entry] : epoll_entries) {
			ColdStartEpollEntry* centry = state.next<ColdStartEpollEntry>(current);
			centry->vfd = vfd;
			centry->epoll_fds = entry->epoll_fds.size();
			centry->shared_epoll_fds = entry->shared_epoll_fds.size();
			for (const auto& [evfd, event] : entry->epoll_fds) {
				ColdStartEpollFd* cefd = state.next<ColdStartEpollFd>(current);
				cefd->vfd = evfd;
				cefd->event = event;
			}
			for (const auto& sevfd : entry->shared_epoll_fds) {
				ColdStartSharedEpollFd* csefd = state.next<ColdStartSharedEpollFd>(current);
				csefd->vfd = sevfd;
			}
		}
		// Socket pair reconstruction entries
		for (const auto& sp : fdm.get_socket_pairs()) {
			ColdStartSocketPair* csp = state.next<ColdStartSocketPair>(current);
			if (sp.type == FileDescriptors::INVALID || sp.type == FileDescriptors::DUPFD) {
				// Silently ignore invalid or dupfd socket pairs that cannot be reconstructed
				// when re-loading the state anyway
				csp->vfd1 = -1;
				csp->vfd2 = -1;
				csp->type = int(FileDescriptors::INVALID);
				continue;
			}
			csp->vfd1 = sp.vfd1;
			csp->vfd2 = sp.vfd2;
			csp->type = int(sp.type);
		}

		// Finally, set the size
		state.size = static_cast<uint32_t>(
			reinterpret_cast<char*>(current) - reinterpret_cast<char*>(&state));
		if (state.size < sizeof(SnapshotState) || state.size > SnapshotState::Size()) {
			throw std::runtime_error("Snapshot state size was invalid");
		}

	} catch (const MachineException& me) {
		throw std::runtime_error(std::string("Failed to get snapshot state: ") + me.what());
	}
}

void* vMemory::get_snapshot_state_area() const
{
	if (!this->has_snapshot_area) {
		throw std::runtime_error("No snapshot state area allocated");
	}
	// The snapshot state area is after the end of the memory
	return (void*)(this->ptr + this->size);
}
bool vMemory::has_loadable_snapshot_state() const noexcept
{
	if (this->has_snapshot_area) {
		void* area = this->get_snapshot_state_area();
		uint32_t* magic = reinterpret_cast<uint32_t*>(area);
		return *magic == SnapshotState::MAGIC;
	}
	return false;
}
void* Machine::get_snapshot_state_user_area() const
{
	if (!this->memory.has_snapshot_area) {
		return nullptr;
	}
	void* map = this->memory.get_snapshot_state_area();
	SnapshotState& state = *reinterpret_cast<SnapshotState*>(map);
	if (state.magic != SnapshotState::MAGIC) {
		return nullptr;
	}
	if (state.size < sizeof(SnapshotState) || state.size > SnapshotState::Size()) {
		return nullptr;
	}
	// The user area is after the SnapshotState base + size
	return reinterpret_cast<char*>(map) + state.size;
}

} // namespace tinykvm
