#include "vm_group.hpp"

#include "machine.hpp"
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <linux/kvm.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#if defined(TINYKVM_ARCH_AMD64)
#include "amd64/amd64.hpp"
#include "paging.hpp"
#include <functional>
#endif
extern "C" int close(int);

/* Kernel >= 6.13. Defined here so a build against older headers still compiles
   the Madvise mode in; the runtime probe below is what decides whether it is
   ever used, and pre-6.13 kernels answer an unknown advice value with EINVAL. */
#ifndef MADV_GUARD_INSTALL
#define MADV_GUARD_INSTALL 102
#define MADV_GUARD_REMOVE  103
#endif

namespace tinykvm {
static constexpr bool VERBOSE_VM_GROUP = false;
/* The group installs main memory at slot 0 and the master's mmap ranges from
   FIRST_BANK_IDX onwards, skipping the remote slot: the memslot accounting in
   the constructor has to agree with that. */
static_assert(VmGroup::BASE_MEMSLOTS == MemoryBanks::FIRST_BANK_IDX,
	"VM group base memslot count must match the first free bank index");
static KvmLimits g_kvm_limits;
static std::atomic<uint32_t> g_group_counter {0};

const KvmLimits& KvmLimits::get() noexcept
{
	return g_kvm_limits;
}
TINYKVM_COLD()
void KvmLimits::query(int kvm_fd) noexcept
{
	const auto cap = [kvm_fd] (int extension, unsigned fallback) -> unsigned {
		const int value = ioctl(kvm_fd, KVM_CHECK_EXTENSION, extension);
		return (value > 0) ? unsigned(value) : fallback;
	};
	/* The fallbacks are the values KVM documents for hosts that do not
	   report the capability at all. */
	g_kvm_limits.max_vcpus = cap(KVM_CAP_MAX_VCPUS, 4u);
	g_kvm_limits.max_vcpu_id = cap(KVM_CAP_MAX_VCPU_ID, g_kvm_limits.max_vcpus);
	g_kvm_limits.nr_memslots = cap(KVM_CAP_NR_MEMSLOTS, 32u);

	const int mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	g_kvm_limits.vcpu_mmap_size = (mmap_size > 0) ? unsigned(mmap_size) : 0u;
}

static uint64_t align_up(uint64_t value, uint64_t alignment) noexcept
{
	return (value + (alignment - 1)) & ~(alignment - 1);
}

TINYKVM_COLD()
bool VmGroup::madv_guard_supported() noexcept
{
	/* Probed once per process: one page, one madvise, one munmap. There is no
	   capability to query, so the only way to know is to try it. An older
	   kernel rejects the unknown advice value with EINVAL and does nothing
	   else, so this is safe to run anywhere. */
	static const bool supported = [] () -> bool {
		const uint64_t page = vMemory::PageSize();
		char* probe = (char *) mmap(NULL, page, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (UNLIKELY(probe == MAP_FAILED)) {
			return false;
		}
		const bool ok = (madvise(probe, page, MADV_GUARD_INSTALL) == 0);
		munmap(probe, page);
		return ok;
	}();
	return supported;
}

static const char* host_guard_name(VmGroupHostGuard mode) noexcept
{
	switch (mode) {
	case VmGroupHostGuard::Off:      return "off";
	case VmGroupHostGuard::Madvise:  return "madvise";
	case VmGroupHostGuard::Mprotect: return "mprotect";
	case VmGroupHostGuard::Auto:     break;
	}
	return "auto";
}

TINYKVM_COLD()
static VmGroupHostGuard resolve_host_guard(VmGroupHostGuard wanted)
{
	switch (wanted) {
	case VmGroupHostGuard::Off:
		return VmGroupHostGuard::Off;
	case VmGroupHostGuard::Mprotect:
		return VmGroupHostGuard::Mprotect;
	case VmGroupHostGuard::Madvise:
		/* An explicit request that cannot be honoured is refused, not
		   downgraded: silently running without the host-side guard is exactly
		   the situation the caller asked to be protected from, and it would
		   only be discovered as a sibling's memory being corrupted. */
		if (UNLIKELY(!VmGroup::madv_guard_supported())) {
			throw MachineException(
				"VM group host guard mode 'madvise' needs MADV_GUARD_INSTALL "
				"(Linux 6.13 or later)", MADV_GUARD_INSTALL);
		}
		return VmGroupHostGuard::Madvise;
	case VmGroupHostGuard::Auto:
		break;
	}
	/* Auto: the strongest guard that is free, then the strongest that is
	   affordable.
	   Madvise costs nothing per seat that matters (guard PTE markers, no VMA
	   split), so it is taken whenever the kernel has it.
	   Otherwise the choice is between paying 2 VMAs per seat and having no
	   host-side guard at all, and it is decided by build mode rather than by
	   preference: Mprotect is what turns a linear overrun into a SIGSEGV at the
	   scene, which is worth its cost while code is being developed and tested;
	   in a release build the same cost is precisely the per-seat mmap_lock and
	   mm_take_all_locks overhead pooling exists to remove, and the remaining
	   walls (the allocator wall in MemoryBanks::allocate_new_bank(), the
	   GPA-side guard) are the ones that actually stop the bug rather than
	   report it. */
	if (VmGroup::madv_guard_supported()) {
		return VmGroupHostGuard::Madvise;
	}
#if !defined(NDEBUG)
	return VmGroupHostGuard::Mprotect;
#else
	return VmGroupHostGuard::Off;
#endif
}

TINYKVM_COLD()
VmGroup::VmGroup(const Machine& master, const MachineOptions& options,
	unsigned target_size, std::weak_ptr<VmGroupSet> owner)
	: m_owner { std::move(owner) },
	  m_id { g_group_counter.fetch_add(1, std::memory_order_relaxed) }
{
	const auto& limits = KvmLimits::get();

	/* The working-memory ceiling is frozen here: every member of this group
	   is bound by it, and a reset may not raise it. */
	this->m_max_cow_mem = options.max_cow_mem;
	const uint64_t usable =
		align_up(std::max(uint64_t(options.max_cow_mem), BANK_ALIGNMENT), BANK_ALIGNMENT);
	this->m_arena_stride = usable + GUARD_BAND;

	/* Partitions are relative to the master's arena base: it is not a
	   constant (see MemoryBanks::MemoryBanks). */
	const auto& mem = master.main_memory();
	this->m_arena_base = mem.banks.arena_begin();

	/* B is the smallest of four walls.
	   1. What was asked for.
	   2. KVM_CAP_MAX_VCPUS, a count wall - and closing a vCPU fd does not
	      reclaim capacity, so it bounds the seats a group may ever hand out,
	      not just the ones it holds at once.
	   3. KVM_CAP_NR_MEMSLOTS. One slot per seat covers its whole partition
	      (that is the point of the partition), plus the group's shared base
	      slots: main memory, the reserved remote slot, and the master's mmap
	      ranges. Enormous on current hosts (32764), but it is a real wall and
	      MemoryBank::idx is a uint16_t, so query it rather than assume.
	   4. The guest-physical room the arena has (below). Pooling multiplies
	      the arena by B, so a working-memory budget that is unremarkable for
	      a single VM can walk the span into a neighbouring region. */
	const unsigned wanted = (target_size != 0) ? target_size : DEFAULT_SIZE;
	unsigned wall = 1u;
	if (limits.max_vcpus > VCPU_HEADROOM) {
		wall = limits.max_vcpus - VCPU_HEADROOM;
	}
	const unsigned base_slots =
		BASE_MEMSLOTS + unsigned(master.main_memory().mmap_ranges.size());
	unsigned slot_wall = 0u;
	if (limits.nr_memslots > base_slots) {
		slot_wall = limits.nr_memslots - base_slots;
	}
	if (UNLIKELY(slot_wall == 0)) {
		Machine::machine_exception("VM group has no memslots left for seats",
			limits.nr_memslots);
	}
	/* A uint16_t slot index is what MemoryBank::idx and the memslot install
	   path carry, so the last seat's slot must still fit in one. */
	slot_wall = std::min(slot_wall, unsigned(UINT16_MAX) - base_slots);
	const uint64_t span_wall = ARENA_SPAN_LIMIT / m_arena_stride;
	if (UNLIKELY(span_wall == 0)) {
		Machine::machine_exception("VM group working memory exceeds the whole arena range",
			m_arena_stride);
	}
	this->m_capacity = std::min(std::min(wanted, slot_wall),
		std::min(wall, std::min(limits.max_vcpu_id, unsigned(span_wall))));
	if (UNLIKELY(this->m_capacity == 0)) {
		Machine::machine_exception("VM group has no vCPU capacity on this host");
	}
	/* B == 1 is legal (a host reporting KVM_CAP_MAX_VCPUS just above
	   VCPU_HEADROOM, or a working-memory budget so large that the arena span
	   allows a single partition) and degenerate: every concurrent member needs
	   its own group, so pooling buys nothing and the fork path pays a
	   KVM_CREATE_VM per member exactly as before. What it must not also do is
	   pay a *teardown* per member - which is what the retirement spare in
	   VmGroupSet::note_seat_released() prevents: the group a departing member
	   empties is kept and refilled rather than destroyed and re-created. So B==1
	   degrades to the unpooled cost, not below it. */

	const uint64_t span = uint64_t(m_capacity) * m_arena_stride;
	uint64_t arena_end = 0;
	if (UNLIKELY(__builtin_add_overflow(m_arena_base, span, &arena_end))) {
		Machine::machine_exception("VM group arena span wraps guest-physical space",
			m_arena_stride);
	}

	/* The span_wall above guarantees the span fits in ARENA_SPAN_LIMIT, but
	   that only bounds its length: check it against the master's actual GPA
	   layout too, since arena_begin() is not a constant and the regions below
	   it grow at run time.

	   Main memory is slot 0, shared by every member of the group. */
	if (UNLIKELY(arena_end > mem.physbase && m_arena_base < mem.physbase + mem.size)) {
		Machine::machine_exception("VM group arena span overlaps the main memory region",
			span);
	}
	/* The mmap-physical region (file mappings, foreign banks) grows upward
	   from mmap_physical_begin towards the arena. It is below the arena in
	   every layout MemoryBanks builds, so this is a backstop rather than an
	   expected refusal - but it is checked against the values the master has
	   right now, not against MMAP_PHYS_BASE. */
	if (UNLIKELY(arena_end > mem.mmap_physical_begin
		&& m_arena_base < mem.mmap_physical))
	{
		Machine::machine_exception("VM group arena span overlaps the mmap-physical region",
			span);
	}

	const VmGroupHostGuard guard = resolve_host_guard(options.vm_group_host_guard);
	this->m_host_guard.store(guard, std::memory_order_relaxed);

	/* ONE host reservation for the whole group, made here, instead of one per
	   seat in materialize_seat(). That per-seat mmap+mprotect pair was the
	   residual O(N) in a pooled populate: two VMAs and two mmap_lock write
	   acquisitions per seat, and every VMA is walked and locked again by every
	   later KVM_CREATE_VM (mm_take_all_locks).

	   I1: the reservation is byte-for-byte the group's guest-physical span,
	   m_capacity * m_arena_stride - the same length that was just checked
	   against the master's GPA layout, and bounded at ARENA_SPAN_LIMIT
	   (32 GiB) by span_wall above. MAP_NORESERVE, so nothing is committed
	   until a bank is touched.
	   I2: consequently seat i lives at m_arena_hva + i*stride while its GPA is
	   m_arena_base + i*stride, i.e. (arena_gpa - arena_hva) is one constant
	   for every seat of the group.

	   Capacity halving on failure rather than a hard refusal: a failed
	   *per-seat* mmap used to cost exactly one seat, but a failed group window
	   fails the whole group and with it the create_fork() that asked for it.
	   Degrading B keeps the failure mode at "smaller groups" instead of "no
	   forks". The span and overlap checks above need no re-run: every one of
	   them only gets looser as capacity shrinks - a shorter span starting at
	   the same base cannot begin to overlap a region it already cleared. */
	const int arena_prot = (guard == VmGroupHostGuard::Mprotect)
		? PROT_NONE : (PROT_READ | PROT_WRITE);
	while (true) {
		this->m_arena_span = uint64_t(m_capacity) * m_arena_stride;
		void* window = mmap(NULL, m_arena_span, arena_prot,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
		if (LIKELY(window != MAP_FAILED)) {
			this->m_arena_hva = (char *) window;
			break;
		}
		if (UNLIKELY(m_capacity == 1)) {
			throw MemoryException("Failed to reserve the VM group arena",
				m_arena_base, m_arena_span);
		}
		const int reason = errno;
		this->m_capacity /= 2;
		/* Once per process: a host that cannot fit the window will not fit it
		   for the next group either, and this is a warning, not an event. */
		static std::atomic<bool> warned {false};
		if (!warned.exchange(true, std::memory_order_relaxed)) {
			fprintf(stderr, "tinykvm: VM group arena reservation of %lu MiB failed"
				" (errno %d); degrading B to %u\n",
				m_arena_span >> 20, reason, m_capacity);
		}
	}

	/* Opt the window out of transparent hugepages unless the caller explicitly
	   asked for them. One syscall per group, advisory, and it does not split
	   the mapping (MADV_NOHUGEPAGE is a flag on the VMA).

	   Why it is needed here and was not needed before: a mapping this long is
	   near-certain to be PMD-aligned - the kernel's THP-aware unmapped-area
	   search hands out 2 MiB-aligned addresses for large anonymous requests -
	   so with system THP at `always` every 8 MiB bank that gets touched at all
	   could be backed by 2 MiB pages. Banks are sparsely used by design (a
	   fork writes a handful of pages into one), so that is RSS inflation of up
	   to 512x per touched page, multiplied by B seats. The old per-seat
	   windows were 56 MiB and could get the same treatment in principle, but
	   rarely did; a single 32 GiB region reliably does.

	   Mirroring the unpooled path, deliberately and with one difference. The
	   unpooled bank allocator (MemoryBanks::try_alloc) applies no advice at
	   all, so bank memory inherits the system THP policy; only *main* memory
	   opts in, via options.transparent_hugepages in
	   vMemory::allocate_mapped_memory(). Honouring that same field is what
	   keeps an explicit opt-in working; defaulting to NOHUGEPAGE rather than
	   to "inherit" is the difference, and it is what keeps a group's RSS
	   comparable to the unpooled forks it replaces instead of being decided by
	   a host-wide sysfs setting nothing in tinykvm can see. The hugetlb
	   options (options.hugepages, hugepages_arena_size, using_hugepages())
	   need no handling: a pooled fork is refused outright if it sets any of
	   them (Machine::Machine's group path, and
	   MemoryBanks::init_from_partition), so this constructor never sees one. */
	if (!options.transparent_hugepages) {
		madvise(this->m_arena_hva, this->m_arena_span, MADV_NOHUGEPAGE);
	}

	this->m_fd = Machine::create_kvm_vm();
	try {
		/* A fork copies the master's physbase *and* host pointer, so one
		   group-level slot 0 serves every member. */
		const auto vmem = master.main_memory().vmem();
		this->install_slot(0, vmem.physbase, vmem.ptr, vmem.size);

		/* The master's mmap ranges are identical (GPA, HVA, size) triples
		   for every member: install them once, here. Members copy the
		   range vector without installing anything. */
		this->m_next_slot = MemoryBanks::FIRST_BANK_IDX;
		for (const auto& range : master.main_memory().mmap_ranges) {
			this->install_slot(m_next_slot++, range.physbase, range.ptr, range.size);
		}
		this->m_mmap_ranges = master.main_memory().mmap_ranges.size();
	} catch (...) {
		/* ~VmGroup does not run for a constructor that throws, so everything
		   acquired above this point has to be released by hand - including the
		   group window, which is now this object's only arena mapping. */
		close(this->m_fd);
		this->m_fd = -1;
		munmap(this->m_arena_hva, this->m_arena_span);
		this->m_arena_hva = nullptr;
		this->m_arena_span = 0;
		throw;
	}

	if (options.verbose_loader || VERBOSE_VM_GROUP) {
		printf("VM group %u: B=%u, arena 0x%lX + %u x %lu MiB (%lu MiB span, "
			"%lu MiB guard), host 0x%lX + %lu MiB, guard mode %s\n",
			m_id, m_capacity, m_arena_base, m_capacity, m_arena_stride >> 20,
			m_arena_span >> 20, GUARD_BAND >> 20,
			(uintptr_t)m_arena_hva, m_arena_span >> 20,
			host_guard_name(guard));
	}
}

TINYKVM_COLD()
VmGroup::~VmGroup()
{
	/* Whole-group teardown is the only place a seat's vCPU may be closed and
	   its kvm_run unmapped. A seat's arena_hva is a slice of the group window
	   and is not unmapped here (or anywhere else): I5, exactly one munmap of
	   arena memory in the tree, at the bottom of this function.

	   THE ORDER MATTERS, and it is the reason the single big munmap is cheap.
	   While the VM fd is open, this group's struct kvm has an mmu_notifier
	   registered on this mm, so every munmap of memory that a memslot points
	   at drives kvm_mmu_notifier_invalidate_range_start for it - zapping EPT
	   and taking the group's mmu_lock. Closing the vCPU fds first (they hold
	   references to the struct kvm, so the VM is not torn down while they are
	   open) and then the VM fd means the notifier is already unregistered by
	   the time the arena mapping goes away: the 32 GiB munmap then does
	   nothing but drop one VMA and its (MAP_NORESERVE, mostly untouched) page
	   tables. Unmapping first, as this used to, would make it the expensive
	   half of retirement instead. */
	for (auto& seat : m_seats) {
		if (seat->timer_id != nullptr) {
			timer_delete((timer_t)seat->timer_id);
		}
		if (seat->kvm_run != nullptr) {
			munmap(seat->kvm_run, KvmLimits::get().vcpu_mmap_size);
		}
		if (seat->vcpu_fd >= 0) {
			close(seat->vcpu_fd);
		}
	}
	if (this->m_fd >= 0) {
		close(this->m_fd);
	}
	/* nullptr when the constructor threw before or during the reservation. */
	if (this->m_arena_hva != nullptr) {
		munmap(this->m_arena_hva, this->m_arena_span);
	}
}

void VmGroup::install_slot(uint32_t idx, uint64_t gpa, char* hva, uint64_t size)
{
	const struct kvm_userspace_memory_region memreg {
		.slot = idx,
		.flags = 0u,
		.guest_phys_addr = gpa,
		.memory_size = size,
		.userspace_addr = (uintptr_t) hva,
	};
	if (UNLIKELY(ioctl(this->m_fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0)) {
		throw MemoryException("Failed to install VM group memory region", gpa, size);
	}
}

VmGroupSeat* VmGroup::materialize_seat()
{
	/* The seat is registered with the group *before* anything is acquired for
	   it, and stays registered even if this throws. Two reasons:
	   1. ~VmGroup is then the single place that releases whatever the seat did
	      manage to get - in particular a vCPU fd, whose capacity a struct kvm
	      never gives back, so dropping the seat on the floor would leak the
	      capacity for the lifetime of the group.
	   2. arena_gpa is derived from the seat index, so an index may never be
	      reused by a later seat: the failed seat's partition stays retired.
	   The seat is only pushed onto the free list by acquire_seat() after this
	   returns successfully, so a half-built seat is never handed to a member -
	   which is what keeps a vcpu_fd == -1 seat from sitting at the head of the
	   LIFO free list and failing every subsequent acquire forever. */
	const unsigned index = m_seats.size();
	m_seats.push_back(std::make_unique<VmGroupSeat>());
	VmGroupSeat* seat = m_seats.back().get();
	seat->kvm_vcpu_id = int(index);
	seat->arena_gpa = m_arena_base + uint64_t(index) * m_arena_stride;
	seat->arena_size = m_arena_stride - GUARD_BAND;

	/* The seat's vCPU, created once and adopted by every tenant after that.
	   First, because it is the one resource whose capacity is consumed
	   permanently: if it cannot be had, nothing else should be spent. */
	seat->vcpu_fd = ioctl(this->m_fd, KVM_CREATE_VCPU, seat->kvm_vcpu_id);
	if (UNLIKELY(seat->vcpu_fd < 0)) {
		Machine::machine_exception("Failed to KVM_CREATE_VCPU in a VM group", errno);
	}

	/* The seat's slice of the group's single MAP_NORESERVE window, reserved
	   once in the constructor. Nothing is mapped here: a seat is an offset.
	   I2 - the slice sits at the same index * stride offset in host memory as
	   the seat's partition does in guest-physical memory, so
	   (arena_gpa - arena_hva) is one constant for the whole group.
	   MemoryBanks carves its banks out of this at fixed offsets, with no mmap
	   and no memslot install per bank; the group's one memslot per seat (I3,
	   below) covers the whole partition.

	   The guard band exists on both sides of the partition boundary.
	   Guest-physical: free and unconditional, because the memslot stops at
	   arena_size while the stride reaches GUARD_BAND further.
	   Host: m_host_guard, frozen at construction (except for the one downgrade
	   below). Mprotect pays 2 VMAs per seat because it has to - PROT_NONE is a
	   VMA attribute, so opening the usable part of a partition splits the
	   window. Madvise pays none: guard markers are PTE-level. Off pays
	   nothing and does nothing. */
	seat->arena_hva = m_arena_hva + uint64_t(index) * m_arena_stride;
	/* I2, stated as code: the delta is the group's, not the seat's. And, by I1,
	   the slice is wholly inside the reservation. */
	assert(seat->arena_gpa - uintptr_t(seat->arena_hva)
		== m_arena_base - uintptr_t(m_arena_hva));
	assert(uint64_t(index) * m_arena_stride + m_arena_stride <= m_arena_span);
	switch (m_host_guard.load(std::memory_order_relaxed)) {
	case VmGroupHostGuard::Mprotect:
		/* The window was reserved PROT_NONE, so this both grants access to the
		   partition and leaves the band behind it inaccessible. */
		if (UNLIKELY(mprotect(seat->arena_hva, seat->arena_size,
			PROT_READ | PROT_WRITE) < 0))
		{
			throw MemoryException("Failed to open the VM group arena partition window",
				seat->arena_gpa, seat->arena_size);
		}
		break;
	case VmGroupHostGuard::Madvise: {
		/* The window is already RW for its whole length in this mode, so the
		   guard is installed rather than carved: MADV_GUARD_INSTALL puts guard
		   markers in the PTEs of the range, leaving one VMA. A touch anywhere
		   in the range takes SIGSEGV exactly as PROT_NONE would.

		   Only the first HOST_GUARD_BYTES of the band, not all of it: see
		   HOST_GUARD_BYTES. The markers survive the MADV_DONTNEED that
		   release_seat() does on recycling, and that madvise is clamped to
		   arena_size anyway, so a seat is guarded once, here, for the life of
		   the group. */
		const uint64_t glen =
			std::min(HOST_GUARD_BYTES, m_arena_stride - seat->arena_size);
		if (UNLIKELY(madvise(seat->arena_hva + seat->arena_size, glen,
			MADV_GUARD_INSTALL) < 0))
		{
			/* The kernel was probed for MADV_GUARD_INSTALL at construction, so
			   this is not "unsupported" but a refusal for this range (pinned
			   pages, a policy the mapping does not allow). The guard is
			   hardening, not correctness: the partition wall in
			   MemoryBanks::allocate_new_bank() is what stops an out-of-bounds
			   bank, and the memslot geometry is what stops the guest. Failing
			   the seat - and with it the create_fork() that asked for it - would
			   trade a real outage for a lost backstop, so warn and carry on.

			   Off is the only mode this can degrade to: the window is mapped RW
			   for its whole length in Madvise mode, so Mprotect's invariant
			   (reserved PROT_NONE, opened per seat) does not hold for it and
			   switching to it would leave later seats' bands accessible while
			   pretending otherwise. */
			const int reason = errno;
			this->m_host_guard.store(VmGroupHostGuard::Off,
				std::memory_order_relaxed);
			static std::atomic<bool> warned {false};
			if (!warned.exchange(true, std::memory_order_relaxed)) {
				fprintf(stderr, "tinykvm: VM group %u seat %d: MADV_GUARD_INSTALL"
					" failed (errno %d); continuing with no host-side arena"
					" guard for this group\n",
					m_id, seat->kvm_vcpu_id, reason);
			}
		}
		break;
	}
	case VmGroupHostGuard::Off:
	case VmGroupHostGuard::Auto:
		/* Off: the window is already RW for its whole length, and nothing is
		   done per seat at all. Auto is unreachable: it was resolved in the
		   constructor. */
		break;
	}

	/* I3: memslot geometry is untouched by any of the above - one slot per
	   seat, at the seat's own GPA, covering exactly arena_size bytes. Only
	   where the HVA comes from has changed, and a live group still performs
	   zero memslot operations. */
	seat->memslot = m_next_slot;
	this->install_slot(seat->memslot, seat->arena_gpa, seat->arena_hva,
		seat->arena_size);
	m_next_slot += 1;

	return seat;
}

VmGroupSeat* VmGroup::acquire_seat()
{
	std::scoped_lock lock(m_mtx);
	VmGroupSeat* seat = nullptr;
	if (!m_free.empty()) {
		seat = m_free.back();
		m_free.pop_back();
		/* Two members on one seat would share a vCPU fd, a kvm_run mapping and
		   an arena partition - the whole isolation story. It cannot happen
		   through the free list alone, so a live seat here means the seat was
		   released twice (and is now on the list more than once) or a member
		   handed its seat pointer to something else. Refuse loudly instead of
		   handing out the double.
		   NB: this deliberately strands the seat - it has already been popped
		   off the free list and is not put back. The alternative (push it back)
		   would leave the corrupt duplicate in place to be handed out by the
		   next acquire, and a stranded seat costs one seat of the group's
		   capacity while a shared one costs isolation. The seat stays in
		   m_seats, so ~VmGroup still releases everything behind it. */
		if (UNLIKELY(seat->live)) {
			Machine::machine_exception("VM group seat acquired while still live",
				seat->kvm_vcpu_id);
		}
	} else if (m_seats.size() < m_capacity) {
		seat = this->materialize_seat();
	} else {
		return nullptr;
	}
	seat->live = true;
	m_live += 1;
	return seat;
}

void VmGroup::release_seat(VmGroupSeat* seat, uint64_t dirty_bytes) noexcept
{
	/* Give the dirty part of the partition back to the kernel. Recycling is
	   madvise-only: deleting a live group's memslot would zap the whole
	   group's EPT and refault every resident page of every sibling. */
	if (dirty_bytes > 0 && seat->arena_hva != nullptr) {
		madvise(seat->arena_hva, std::min(dirty_bytes, seat->arena_size),
			MADV_DONTNEED);
	}
	bool empty = false;
	{
		std::scoped_lock lock(m_mtx);
		if (UNLIKELY(!seat->live)) {
			/* Double release: the seat is already on the free list, and
			   pushing it again would hand it to two members at once. */
			fprintf(stderr, "tinykvm: VM group %u seat %d released twice\n",
				m_id, seat->kvm_vcpu_id);
			return;
		}
		seat->live = false;
		m_free.push_back(seat);
		m_live -= 1;
		empty = (m_live == 0);
	}
	if (!empty) {
		return;
	}
	/* Promote the weak owner to a strong reference and hold it across the
	   notification: this member may be the last thing keeping the group alive,
	   and the master (which owns the set) can be going away concurrently.
	   Expired means the set is already gone and there is nobody to notify. */
	const std::shared_ptr<VmGroupSet> owner = m_owner.lock();
	/* Called outside the group lock, always: VmGroupSet::acquire() holds the
	   set lock across VmGroup::acquire_seat(), so set-then-group is the only
	   order any thread may take the two locks in. note_seat_released()
	   re-checks emptiness under the set lock, which is what makes the gap here
	   safe: a member acquired in the meantime is visible there. */
	if (owner != nullptr) {
		owner->note_seat_released(*this);
	}
}

unsigned VmGroup::live_members() const noexcept
{
	std::scoped_lock lock(m_mtx);
	return m_live;
}
unsigned VmGroup::high_water() const noexcept
{
	std::scoped_lock lock(m_mtx);
	return m_seats.size();
}

std::pair<std::shared_ptr<VmGroup>, VmGroupSeat*>
	VmGroupSet::acquire(const MachineOptions& options)
{
	std::scoped_lock lock(m_mtx);

	/* Build into the emptiest *eligible* live group: whole-group retirement
	   needs members concentrated, while striping hot members across groups is
	   a separate decision made by the host when it hands out work.

	   Eligibility, not just free capacity. Everything a group froze at
	   creation is a property a candidate member has to match, and a mismatch
	   has to mean "open a new group" rather than "this fork cannot be built":
	   the group set is the only thing that can ever satisfy such a member, so
	   refusing here would be a permanent create_fork() outage for this
	   master, one that no amount of retrying or draining would clear. */
	/* Snapshot what this master's forks are asking for. note_seat_released()
	   judges eligibility against this rather than against m_master, which it
	   may not touch: a group can outlive its master. */
	this->m_master_ranges = m_master.main_memory().mmap_ranges.size();
	this->m_wanted_cow_pages = options.max_cow_mem / vMemory::PageSize();
	/* The *requested* mode, unresolved: a group stores what it resolved to, and
	   is_eligible() compares the two. Auto means "whatever a group already
	   has", so snapshotting it unresolved is what lets an Auto member join any
	   group instead of only the ones this call's kernel/build happened to
	   resolve to. */
	this->m_wanted_host_guard = options.vm_group_host_guard;

	std::shared_ptr<VmGroup> best = nullptr;
	unsigned fewest = 0;
	for (const auto& group : m_groups) {
		/* Eligibility: the frozen working-memory ceiling (the partitions of
		   this group were sized from it, and
		   MemoryBanks::init_from_partition() rejects a member asking for more,
		   so a bigger member needs a group whose ceiling froze bigger) and the
		   master's mmap range count as installed at group creation (if the
		   master has grown more since, this group's VM has no memslot for
		   them; a new group installs the current set), and the host guard mode
		   the group resolved to. */
		if (!this->is_eligible(*group)) {
			continue;
		}
		const unsigned live = group->live_members();
		if (live >= group->capacity()) {
			continue;
		}
		if (best == nullptr || live < fewest) {
			best = group;
			fewest = live;
		}
	}
	if (best != nullptr) {
		if (auto* seat = best->acquire_seat(); seat != nullptr) {
			return {std::move(best), seat};
		}
	}

	auto group = std::make_shared<VmGroup>(m_master, options, options.vm_group_size,
		this->weak_from_this());
	auto* seat = group->acquire_seat();
	if (UNLIKELY(seat == nullptr)) {
		Machine::machine_exception("A new VM group could not hand out a seat");
	}
	m_groups.push_back(group);
	return {std::move(group), seat};
}

bool VmGroupSet::is_eligible(const VmGroup& group) const noexcept
{
	/* The host guard mode is frozen at group construction like the
	   working-memory ceiling is, and for the same reason: the group's window
	   was *mapped* according to it (PROT_NONE and opened per seat for Mprotect,
	   RW throughout for the other two), so it cannot be retrofitted onto a live
	   group. A member that explicitly asked for a mode must therefore get a
	   group that resolved to it, not a group that quietly gives it something
	   else - the same rule that makes a 24 MiB member open its own group rather
	   than be clamped into an 8 MiB one.
	   Auto matches any group: it means "whatever this host can give", which a
	   group that already exists has already decided. In practice a process
	   resolves its choice once (fa-serve reads the env at startup), so every
	   member of a master asks for the same thing and this never bifurcates the
	   set. */
	if (m_wanted_host_guard != VmGroupHostGuard::Auto
		&& group.host_guard() != m_wanted_host_guard)
	{
		return false;
	}
	return group.max_cow_mem() / vMemory::PageSize() >= m_wanted_cow_pages
		&& group.mmap_range_count() == m_master_ranges;
}

void VmGroupSet::note_seat_released(VmGroup& group) noexcept
{
	/* Retired groups are moved out here and released *after* the set lock:
	   ~VmGroup closes fds and unmaps windows, and there is no reason to hold up
	   every other acquire() on this master while it does. It also keeps the
	   (rare, but real) case of this being the last reference to a group from
	   running ~VmGroup under the lock. */
	std::vector<std::shared_ptr<VmGroup>> retired;
	{
		std::scoped_lock lock(m_mtx);
		/* Everything below is decided under the set lock, which is the lock
		   acquire() holds across VmGroup::acquire_seat(): a member that joined
		   between release_seat() dropping the group lock and this point is
		   visible here, so no group is retired out from under a live member. */
		const VmGroup* just_emptied =
			(group.live_members() == 0) ? &group : nullptr;

		/* Pass 1: retire every empty group that can never serve anyone again.
		   The eligibility test is the same one acquire() uses to pick a group,
		   so "ineligible" means precisely "acquire() will skip it forever". */
		for (auto it = m_groups.begin(); it != m_groups.end(); ) {
			auto& candidate = *it;
			if (candidate->live_members() == 0 && !this->is_eligible(*candidate)) {
				if (candidate.get() == just_emptied) {
					just_emptied = nullptr;
				}
				retired.push_back(std::move(candidate));
				it = m_groups.erase(it);
			} else {
				++it;
			}
		}

		/* Pass 2: keep exactly one empty (and, by pass 1, eligible) group as a
		   warm spare and retire the rest. The spare is reserved up-front for
		   the group that just emptied - it is the one about to be refilled, and
		   its seats' vCPUs, kvm_run mappings and timers are already warm. */
		bool spare_claimed = (just_emptied != nullptr);
		for (auto it = m_groups.begin(); it != m_groups.end(); ) {
			auto& candidate = *it;
			if (candidate->live_members() != 0 || candidate.get() == just_emptied) {
				++it;
				continue;
			}
			if (!spare_claimed) {
				spare_claimed = true;
				++it;
				continue;
			}
			retired.push_back(std::move(candidate));
			it = m_groups.erase(it);
		}
	}
}

std::vector<std::shared_ptr<VmGroup>> VmGroupSet::groups() const
{
	std::scoped_lock lock(m_mtx);
	return m_groups;
}
size_t VmGroupSet::group_count() const noexcept
{
	std::scoped_lock lock(m_mtx);
	return m_groups.size();
}

#if !defined(NDEBUG) && defined(TINYKVM_ARCH_AMD64)
void Machine::assert_pte_partition_invariant() const
{
	if (this->m_seat == nullptr) {
		return;
	}
	const auto& mem = this->memory;
	const uint64_t main_begin = mem.physbase;
	const uint64_t main_end   = mem.physbase + mem.size;
	const uint64_t part_begin = m_seat->arena_gpa;
	const uint64_t part_end   = m_seat->arena_gpa + m_seat->arena_size;

	/* The group's whole arena range: every seat's partition, materialized or
	   not, and the guard bands between them. Nothing in here is shared, so
	   this is the region a member's page tables must stay out of - except for
	   the slice that is its own. */
	const uint64_t arena_begin = m_group->arena_base();
	const uint64_t arena_end = arena_begin
		+ uint64_t(m_group->capacity()) * m_group->arena_stride();

	/* Shared with every sibling and installed once by the group, so a PTE
	   pointing here carries no cross-tenant information: the master's main
	   memory (slot 0, identity-mapped and frozen) and its mmap ranges, which
	   a pooled member copies without installing. */
	const auto is_shared = [&] (uint64_t addr, uint64_t len) -> bool {
		if (addr >= main_begin && addr + len <= main_end)
			return true;
		for (const auto& range : mem.mmap_ranges) {
			if (addr >= range.physbase && addr + len <= range.physbase + range.size)
				return true;
		}
		return false;
	};
	const auto is_own_partition = [&] (uint64_t addr, uint64_t len) -> bool {
		return addr >= part_begin && addr + len <= part_end;
	};
	/* Overlap, not containment: a 2MB leaf that starts below the arena and
	   reaches into it is as much of a violation as one wholly inside. */
	const auto touches_group_arena = [&] (uint64_t addr, uint64_t len) -> bool {
		return addr < arena_end && addr + len > arena_begin;
	};
	/* NB: a target that is neither shared, nor this member's partition, nor
	   anywhere in the group's arena, is *not* a violation - it is guest-
	   physical space with no memslot in the group's VM, so the guest can only
	   fault on it, exactly as an unpooled VM would. That case is not
	   hypothetical and not caused by pooling: setup_amd64_paging() identity-
	   maps a whole gigapage of 2MB leaves regardless of max_mem
	   (`PD_PAGES = ceil(size / 1GB)`, amd64/paging.cpp), so every VM with a
	   main memory that is not a multiple of 1GB has present leaves pointing
	   past the end of it. Requiring "in main memory or in my partition" for
	   every entry, as the plan's sketch put it, therefore cannot hold for any
	   guest. What pooling adds - and all it adds - is that some unbacked GPAs
	   *became* backed, by siblings; that is exactly what is checked. */

	const uint64_t mask = tinykvm::paging_address_mask();
	/* The check every physical target has to pass, leaf or table alike. */
	const auto in_bounds = [&] (uint64_t addr, uint64_t len) -> bool {
		return is_shared(addr, len) || is_own_partition(addr, len)
			|| !touches_group_arena(addr, len);
	};
	uint64_t bad_vaddr = 0;
	uint64_t bad_entry = 0;
	uint64_t bad_len   = 0;
	const char* bad_what = nullptr;

	/* A local walk rather than foreach_page(), for one reason: foreach_page()
	   resolves a table entry's target (vMemory::page_at()) in order to descend
	   into it, *before* the callback for its children can object - so a
	   page-table pointer aimed out of bounds either throws MemoryException from
	   page_at() or, worse, has the walk reading a sibling's arena as if it were
	   a page table. Every target must be validated before it is followed.
	   levels: 4 = PML4, 3 = PDPT, 2 = PD, 1 = PT. Returns false once a
	   violation has been recorded, unwinding immediately. */
	const std::function<bool(uint64_t, int, uint64_t)> walk =
		[&] (uint64_t table_gpa, int level, uint64_t vbase) -> bool
	{
		const uint64_t* table = mem.page_at(table_gpa);
		const uint64_t entry_span = 1ULL << (12 + 9 * (level - 1));
		for (uint64_t i = 0; i < 512; i++) {
			const uint64_t entry = table[i];
			if ((entry & PDE64_PRESENT) == 0) {
				continue;
			}
			/* A leaf maps entry_span bytes of guest-physical memory; any other
			   entry points at one 4K page of page-table memory, which has to be
			   in bounds too - a page-table page in a sibling's partition is
			   exactly as bad as a data page there, and is followed by the
			   hardware page walker as well as by this one. NB: the PS bit is
			   reserved at PML4 level, so level 4 is never a leaf. */
			const bool leaf = (level == 1)
				|| (level < 4 && (entry & PDE64_PS) != 0);
			const uint64_t len = leaf ? entry_span : vMemory::PageSize();
			const uint64_t target = entry & mask;
			const uint64_t vaddr = vbase + i * entry_span;
			if (UNLIKELY(!in_bounds(target, len))) {
				bad_vaddr = vaddr;
				bad_entry = entry;
				bad_len   = len;
				bad_what  = leaf ? "maps" : "points at a page table in";
				return false;
			}
			if (!leaf && !walk(target, level - 1, vaddr)) {
				return false;
			}
		}
		return true;
	};

	/* F-8: the root itself, which nothing else in the walk covers. CR3 is set
	   from memory.page_tables, so a root outside the partition would have the
	   hardware page walker reading a sibling's arena as this member's PML4. */
	if (UNLIKELY(!in_bounds(mem.page_tables, vMemory::PageSize()))) {
		bad_vaddr = 0;
		bad_entry = mem.page_tables;
		bad_len   = vMemory::PageSize();
		bad_what  = "has its page-table root (CR3) in";
	} else {
		try {
			walk(mem.page_tables, 4, 0);
		} catch (const MemoryException& e) {
			/* An in-bounds target that cannot be resolved to host memory: the
			   walk never follows an out-of-bounds one, so this is a page-table
			   pointer into a part of the partition that has no bank behind it.
			   Report it as the invariant's own failure rather than letting
			   page_at()'s exception surface as if it came from the guest. */
			machine_exception("A pooled member's page tables are unresolvable "
				"inside its arena partition", e.data());
		}
	}

	if (UNLIKELY(bad_what != nullptr)) {
		fprintf(stderr,
			"tinykvm: VM group %u seat %d: page table entry for 0x%lX %s "
			"[0x%lX, 0x%lX), which is inside the group's arena [0x%lX, 0x%lX) but "
			"outside this member's own partition [0x%lX, 0x%lX)\n",
			m_group->id(), m_seat->kvm_vcpu_id, bad_vaddr, bad_what,
			bad_entry & mask, (bad_entry & mask) + bad_len,
			arena_begin, arena_end, part_begin, part_end);
		machine_exception("A pooled member's page tables leave its arena partition",
			bad_entry & mask);
	}
}
#endif

VmGroupSet& Machine::groups() const
{
	/* Lazily created, and only ever from the pooled fork path. The registry
	   mutex is global rather than per-Machine: it is entered once per pooled
	   master, and Machine is a hot, size-sensitive object. */
	static std::mutex registry_mtx;
	std::scoped_lock lock(registry_mtx);
	if (m_groups == nullptr) {
		m_groups = std::make_shared<VmGroupSet>(*this);
	}
	return *m_groups;
}

} // tinykvm
