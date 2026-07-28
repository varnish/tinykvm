#pragma once
/* For VmGroupHostGuard, which is part of MachineOptions and therefore of the
   public API. The dependency is one-way on purpose: common.hpp knows nothing
   about VmGroup. */
#include "common.hpp"
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
struct VmGroupSet;

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
	/* Created once, when the seat is materialized, and never closed before
	   group teardown. A seat that reaches a member always has this open: a
	   seat whose materialization failed is kept only so the group destructor
	   can release what it did get, and is never handed out. */
	int      vcpu_fd     = -1;
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
	/* A slice of the group's single arena mapping, at index * stride; not
	   owned by the seat and never unmapped by it. The whole group window is
	   released once, in ~VmGroup. */
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
	   budget rounded up to a whole bank, plus one bank of guard band, which
	   restores a hardware backstop for a linear overrun past the end of a
	   partition.

	   The guard band has two sides, and they cost differently.
	   Guest-physical: always on, and free. A seat's memslot covers only its
	   first arena_size bytes, so the band has no backing in the group's VM at
	   all - a guest touching it faults exactly as it would on any GPA the VM
	   has no memslot for. Nothing has to be done to get this.
	   Host address space: m_host_guard, and not free - see VmGroupHostGuard.
	   It only matters because seat windows are adjacent slices of one mapping:
	   without it a host-side linear overrun off the end of a partition - a
	   page_duplicate() or memcpy() walking past the last bank - lands in a
	   sibling's guest memory, where an unpooled VM's standalone bank mmap
	   would have SIGSEGV'd. */
	static constexpr uint64_t BANK_ALIGNMENT = 8ULL << 20;
	static constexpr uint64_t GUARD_BAND     = 8ULL << 20;
	static constexpr unsigned DEFAULT_SIZE   = 1024;
	/* How much of the guard band the Madvise mode actually guards. The threat
	   model is a *linear* overrun, so the first guarded page catches it; the
	   rest of the band is reserved address space and needs nothing done to it.
	   Guarding the whole 8 MiB would cost a page-table page per 2 MiB per seat
	   (guard PTEs are per-page markers, so the band can no longer stay an
	   empty PMD) for no added coverage. */
	static constexpr uint64_t HOST_GUARD_BYTES = 64ULL << 10;
	/* All the guest-physical room an arena has, and therefore a hard ceiling
	   on B x stride. MemoryBanks picks the arena base from one of two
	   addresses 32 GiB apart (MemoryBanks::ARENA_BASE_ADDRESS = 0x7000000000,
	   or that plus 0x800000000 for a VM with a relocated vmem base), so a
	   span longer than the gap would reach the other one; and nothing above
	   the upper base is part of the layout at all. At the default 8 MiB
	   working-memory budget - a 16 MiB stride - this caps B at 2048. */
	static constexpr uint64_t ARENA_SPAN_LIMIT = 0x800000000ULL;
	/* vCPU ids left unused inside this struct kvm. KVM_CAP_MAX_VCPUS is a
	   per-struct-kvm count, not a host-global one, so this is not headroom
	   for other VMs on the box - it is headroom for vCPUs this group's own
	   VM may need beyond its seats (and slack against a host whose real cap
	   is lower than the reported capability). */
	static constexpr unsigned VCPU_HEADROOM  = 64;
	/* Memslots a group consumes besides its seats: slot 0 is the master's
	   main memory, slot 1 is reserved for remote memory (never installed by
	   a group, but MemoryBanks::FIRST_BANK_IDX skips it), and one slot per
	   master mmap range. Each seat then adds exactly one. */
	static constexpr unsigned BASE_MEMSLOTS  = 2;

	VmGroup(const Machine& master, const MachineOptions&, unsigned target_size,
		std::weak_ptr<VmGroupSet> owner = {});
	~VmGroup();
	VmGroup(const VmGroup&) = delete;
	VmGroup& operator=(const VmGroup&) = delete;

	/* Take a seat, materializing a new one if the group is not full yet.
	   Returns nullptr when the group is full. Throws if a new seat cannot be
	   materialized (no vCPU capacity, no address space); the half-built seat
	   is retained for teardown and never handed out, so a failure costs one
	   seat of capacity and cannot poison the free list. */
	VmGroupSeat* acquire_seat();
	/* Hand a seat back. Recycles @dirty_bytes of the arena partition with
	   madvise; performs no memslot operations and closes nothing. When this
	   empties the group it asks the owning set to reconsider retirement - so
	   the caller must hold a shared_ptr to this group across the call (Machine
	   does: m_group is cleared only afterwards). */
	void release_seat(VmGroupSeat*, uint64_t dirty_bytes) noexcept;

	int      vm_fd() const noexcept { return m_fd; }
	uint32_t id() const noexcept { return m_id; }
	unsigned capacity() const noexcept { return m_capacity; }
	unsigned live_members() const noexcept;
	unsigned high_water() const noexcept;    /* seats ever materialized */
	uint64_t arena_base() const noexcept { return m_arena_base; }
	uint64_t arena_stride() const noexcept { return m_arena_stride; }
	/* The group's single host reservation. I1: arena_span() is byte-for-byte
	   capacity() * arena_stride(), the same length as the GPA span at
	   arena_base(). I2: therefore arena_gpa - arena_hva is one constant for
	   every seat of the group. */
	char*    arena_hva() const noexcept { return m_arena_hva; }
	uint64_t arena_span() const noexcept { return m_arena_span; }
	/* The resolved mode, never Auto: Auto is decided in the constructor.
	   Read by VmGroupSet::is_eligible(), which will not put a member that asked
	   for an explicit mode into a group that resolved to a different one - the
	   window's protection was chosen from this and cannot be retrofitted. Can
	   be downgraded to Off once, if MADV_GUARD_INSTALL is refused for a seat's
	   range after the kernel probe said it was available. */
	VmGroupHostGuard host_guard() const noexcept {
		return m_host_guard.load(std::memory_order_relaxed);
	}
	/* Whether this kernel implements MADV_GUARD_INSTALL (>= 6.13). Probed
	   once, on first call. */
	static bool madv_guard_supported() noexcept;
	uint32_t max_cow_mem() const noexcept { return m_max_cow_mem; }
	/* Master mmap ranges installed at group creation. A member whose master
	   has grown more of them cannot join this group. */
	size_t mmap_range_count() const noexcept { return m_mmap_ranges; }

	/* Hazard-4 accounting, read by the host-side placement policy: the
	   shared EPT/mmu_lock knee sits at ~4 concurrently faulting members.
	   PHASE 3 API: nothing in tinykvm calls enter_guest()/exit_guest() - the
	   counter is incremented by the host around the run of a member it hands
	   work to (fast-agent's striped reserve), because tinykvm cannot see the
	   difference between a member that is about to fault a lot and one that
	   is idling in a vmcall. Reads as 0 until then. */
	unsigned in_guest_now() const noexcept { return m_in_guest.load(std::memory_order_relaxed); }
	void enter_guest() noexcept { m_in_guest.fetch_add(1, std::memory_order_relaxed); }
	void exit_guest() noexcept { m_in_guest.fetch_sub(1, std::memory_order_relaxed); }

private:
	friend struct VmGroupSet;
	VmGroupSeat* materialize_seat();
	void install_slot(uint32_t idx, uint64_t gpa, char* hva, uint64_t size);

	/* Weak, not raw: a group can outlive the set that made it (a member is
	   still holding it while the master goes away), and release_seat() must be
	   able to find out *and* keep the set alive for the duration of the
	   notification. A raw pointer read under the group lock does not do that -
	   the set can be freed between the read and the call. */
	std::weak_ptr<VmGroupSet> m_owner;
	int      m_fd = -1;
	uint32_t m_id;
	unsigned m_capacity;
	uint64_t m_arena_base;
	uint64_t m_arena_stride;
	/* One MAP_NORESERVE reservation for the whole group, made once in the
	   constructor and released once in the destructor. Seats take slices of
	   it; none of them owns anything. nullptr only on the constructor's own
	   failure paths. */
	char*    m_arena_hva = nullptr;
	uint64_t m_arena_span = 0;
	/* Resolved from MachineOptions::vm_group_host_guard at construction and
	   frozen thereafter: seats of one group all use the same mode, and
	   VmGroupSet::is_eligible() treats it as a group property a member has to
	   match. The one exception is the Madvise -> Off downgrade in
	   materialize_seat(), which only ever removes a backstop, never changes how
	   the window is mapped.

	   Atomic only because of that downgrade. It is written under m_mtx and every
	   in-tree read happens to be serialized against it by the *set* lock
	   (materialize_seat() is reached only through VmGroupSet::acquire(), which
	   holds it, and is_eligible() is only called under it), but host_guard() is
	   public and unlocked, so a host reading it during a downgrade would
	   otherwise be a data race on a plain byte. Relaxed throughout: nothing is
	   ordered against it. */
	std::atomic<VmGroupHostGuard> m_host_guard { VmGroupHostGuard::Auto };
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
struct VmGroupSet : public std::enable_shared_from_this<VmGroupSet> {
	explicit VmGroupSet(const Machine& master) : m_master{master} {}

	/* Acquire a seat, opening a new group when every live group is full.
	   Members are built into the emptiest live group (compaction); handing
	   work out round-robin across groups (striping) is the host's job. */
	std::pair<std::shared_ptr<VmGroup>, VmGroupSeat*> acquire(const MachineOptions&);

	/* Called by VmGroup::release_seat() when a group's last member leaves.
	   Retiring a group drops the set's reference so it destructs - closing its
	   VM fd (and with it its PM-notifier registration), its seats' vCPU fds,
	   kvm_run mappings and POSIX timers, and unmapping its one arena window.
	   The releasing member still holds a reference, so a retired group's
	   destructor runs on the releasing thread after release_seat() returns.

	   POLICY, in the order applied to every currently empty group:

	   (a) An empty *ineligible* group is retired at once. Ineligible means it
	       can never serve anyone again: its frozen working-memory ceiling is
	       below what this master's forks are asking for, or its installed mmap
	       range count no longer matches the master's. Keeping such a group
	       resident is pure waste - and, worse, the "keep one group" rule
	       applied blindly keeps whichever group emptied *first*, which can be
	       exactly this useless one while the group that is actually being used
	       gets created and destroyed on every fork.

	       (b) One empty *eligible* group is kept as a warm spare - hysteresis
	       of one whole group. Without it, occupancy straddling a group boundary
	       (B live members, then the B+1st forked and destroyed over and over)
	       pays a KVM_CREATE_VM plus a full teardown per fork, synchronously on
	       a request thread in ~Machine. Measured at B=4 by the
	       "[straddle-probe]" case in tests/unit/vm_group.cpp: 525 us/iteration
	       with the spare, 11,604 us/iteration retiring every empty group -
	       which is the unpooled cost (10,825 us/iteration) exactly, i.e. the
	       entire pooling win, inverted. Preference goes to the group that just
	       emptied: it is the one about to be refilled, and its seats' vCPUs,
	       kvm_run mappings and timers are already warm.

	   (c) Empty eligible groups beyond that one spare are retired.

	   Eligibility is judged against what the master's forks currently ask for
	   (the most recent acquire()'s budget) and the master's mmap range count as
	   of that acquire - cached, never read from the master here, because a
	   group may outlive its master and this path must not touch it. */
	void note_seat_released(VmGroup&) noexcept;

	std::vector<std::shared_ptr<VmGroup>> groups() const;
	size_t group_count() const noexcept;

private:
	/* Both callers compare in whole pages, exactly as
	   MemoryBanks::init_from_partition() does, so that group eligibility and
	   the ceiling check there can never disagree. */
	bool is_eligible(const VmGroup&) const noexcept;

	const Machine& m_master;
	mutable std::mutex m_mtx;
	std::vector<std::shared_ptr<VmGroup>> m_groups;
	/* Snapshot of what the master's forks currently want, taken at every
	   acquire(). Read by note_seat_released(), which must not dereference
	   m_master: a group (and hence this notification) can outlive the master. */
	uint32_t m_wanted_cow_pages = 0;
	size_t   m_master_ranges = 0;
	/* Unresolved, as the member asked for it: Auto matches any group, an
	   explicit mode only a group that resolved to exactly it. */
	VmGroupHostGuard m_wanted_host_guard = VmGroupHostGuard::Auto;
};

} // tinykvm
