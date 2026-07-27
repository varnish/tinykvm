#pragma once
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <sys/types.h>
#include <utility>
#include <vector>

namespace tinykvm {
struct Machine;
struct MachineOptions;

/* Host KVM limits, queried once from Machine::init(). The count of vCPUs a
   single struct kvm can hold (KVM_CAP_MAX_VCPUS) is what bounds a group: ids
   may be sparse up to KVM_CAP_MAX_VCPU_ID, but the count is a hard wall, and
   closing a vCPU fd does not give the capacity back. */
struct KvmLimits {
	unsigned max_vcpus   = 0;
	unsigned max_vcpu_id = 0;
	unsigned nr_memslots = 0;
	unsigned vcpu_mmap_size = 0;

	static const KvmLimits& get() noexcept;
	static void query(int kvm_fd) noexcept;
};

/* One seat in a group: everything permanently tied to a group-unique
   kvm_vcpu_id, which therefore cannot be released while the group lives.
   A member Machine borrows a seat for its lifetime and hands it back on
   destruction without closing anything. */
struct VmGroupSeat {
	int      kvm_vcpu_id = -1;
	int      vcpu_fd     = -1;      /* never closed before group teardown */
	void*    kvm_run     = nullptr; /* nullptr while never run (lever C) */
	void*    timer_id    = nullptr;
	/* The thread the timer above is bound to (SIGEV_THREAD_ID/sigev_tid). A
	   seat outlives its tenants and is not thread-bound, so a tenant that
	   adopts the seat from another thread must rebind the timer: see
	   vCPU::init_from_seat(). 0 while there is no timer. */
	pid_t    owner_tid   = 0;
	bool     vcpu_initialized = false; /* KVM_SET_CPUID2 already issued */
	uint64_t arena_gpa   = 0;       /* start of this seat's arena partition */
	uint64_t arena_size  = 0;       /* usable bytes (stride minus guard band) */
	char*    arena_hva   = nullptr;
	uint32_t memslot     = 0;       /* the single slot covering the partition */
	bool     live        = false;   /* held by a member right now */
};

/* A shared struct kvm holding up to capacity() forked members of one master.
   The master's main memory (and its mmap ranges) are installed once, here;
   each seat adds exactly one memslot covering its whole arena partition, so
   a live group performs no memslot operations in steady state. */
struct VmGroup {
	/* Arena partitions are strided by the ceiling of the working-memory
	   budget rounded up to a whole bank, plus one unmapped bank of guard
	   band. The guard band restores a hardware backstop for a linear
	   overrun past the end of a partition. */
	static constexpr uint64_t BANK_ALIGNMENT = 8ULL << 20;
	static constexpr uint64_t GUARD_BAND     = 8ULL << 20;
	static constexpr unsigned DEFAULT_SIZE   = 1024;
	/* All the guest-physical room an arena has, and therefore a hard ceiling
	   on B x stride. MemoryBanks picks the arena base from one of two
	   addresses 32 GiB apart (MemoryBanks::ARENA_BASE_ADDRESS = 0x7000000000,
	   or that plus 0x800000000 for a VM with a relocated vmem base), so a
	   span longer than the gap would reach the other one; and nothing above
	   the upper base is part of the layout at all. At the default 8 MiB
	   working-memory budget - a 16 MiB stride - this caps B at 2048. */
	static constexpr uint64_t ARENA_SPAN_LIMIT = 0x800000000ULL;
	/* vCPU ids left unused, so a host that also creates VMs outside of any
	   group does not fail at the KVM_CAP_MAX_VCPUS wall. */
	static constexpr unsigned VCPU_HEADROOM  = 64;

	VmGroup(const Machine& master, const MachineOptions&, unsigned target_size);
	~VmGroup();
	VmGroup(const VmGroup&) = delete;
	VmGroup& operator=(const VmGroup&) = delete;

	/* Take a seat, materializing a new one if the group is not full yet.
	   Returns nullptr when the group is full. */
	VmGroupSeat* acquire_seat();
	/* Hand a seat back. Recycles @dirty_bytes of the arena partition with
	   madvise; performs no memslot operations and closes nothing. */
	void release_seat(VmGroupSeat*, uint64_t dirty_bytes) noexcept;

	int      vm_fd() const noexcept { return m_fd; }
	uint32_t id() const noexcept { return m_id; }
	unsigned capacity() const noexcept { return m_capacity; }
	unsigned live_members() const noexcept;
	unsigned high_water() const noexcept;    /* seats ever materialized */
	uint64_t arena_base() const noexcept { return m_arena_base; }
	uint64_t arena_stride() const noexcept { return m_arena_stride; }
	uint32_t max_cow_mem() const noexcept { return m_max_cow_mem; }
	/* Master mmap ranges installed at group creation. A member whose master
	   has grown more of them cannot join this group. */
	size_t mmap_range_count() const noexcept { return m_mmap_ranges; }

	/* Hazard-4 accounting, read by the host-side placement policy: the
	   shared EPT/mmu_lock knee sits at ~4 concurrently faulting members. */
	unsigned in_guest_now() const noexcept { return m_in_guest.load(std::memory_order_relaxed); }
	void enter_guest() noexcept { m_in_guest.fetch_add(1, std::memory_order_relaxed); }
	void exit_guest() noexcept { m_in_guest.fetch_sub(1, std::memory_order_relaxed); }

private:
	VmGroupSeat* materialize_seat();
	void install_slot(uint32_t idx, uint64_t gpa, char* hva, uint64_t size);

	int      m_fd = -1;
	uint32_t m_id;
	unsigned m_capacity;
	uint64_t m_arena_base;
	uint64_t m_arena_stride;
	uint32_t m_max_cow_mem;   /* frozen ceiling; resets may not exceed it */
	uint32_t m_next_slot;
	size_t   m_mmap_ranges = 0;
	unsigned m_live = 0;
	mutable std::mutex m_mtx;
	std::vector<std::unique_ptr<VmGroupSeat>> m_seats;
	std::vector<VmGroupSeat*> m_free;
	std::atomic<unsigned> m_in_guest {0};
};

/* Per-master registry of groups. Groups are per-master: the shared slot 0 is
   the master's (physbase, host pointer, size) triple, so members of different
   masters can never share a struct kvm. */
struct VmGroupSet {
	explicit VmGroupSet(const Machine& master) : m_master{master} {}

	/* Acquire a seat, opening a new group when every live group is full.
	   Members are built into the emptiest live group (compaction); handing
	   work out round-robin across groups (striping) is the host's job. */
	std::pair<std::shared_ptr<VmGroup>, VmGroupSeat*> acquire(const MachineOptions&);

	std::vector<std::shared_ptr<VmGroup>> groups() const;
	size_t group_count() const noexcept;

private:
	const Machine& m_master;
	mutable std::mutex m_mtx;
	std::vector<std::shared_ptr<VmGroup>> m_groups;
};

} // tinykvm
