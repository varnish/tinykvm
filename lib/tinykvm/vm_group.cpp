#include "vm_group.hpp"

#include "machine.hpp"
#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <linux/kvm.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
extern "C" int close(int);

namespace tinykvm {
static constexpr bool VERBOSE_VM_GROUP = false;
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
VmGroup::VmGroup(const Machine& master, const MachineOptions& options,
	unsigned target_size)
	: m_id { g_group_counter.fetch_add(1, std::memory_order_relaxed) }
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

	/* B is the smallest of three walls.
	   1. What was asked for.
	   2. KVM_CAP_MAX_VCPUS, a count wall - and closing a vCPU fd does not
	      reclaim capacity, so it bounds the seats a group may ever hand out,
	      not just the ones it holds at once.
	   3. The guest-physical room the arena has (below). Pooling multiplies
	      the arena by B, so a working-memory budget that is unremarkable for
	      a single VM can walk the span into a neighbouring region. */
	const unsigned wanted = (target_size != 0) ? target_size : DEFAULT_SIZE;
	unsigned wall = 1u;
	if (limits.max_vcpus > VCPU_HEADROOM) {
		wall = limits.max_vcpus - VCPU_HEADROOM;
	}
	const uint64_t span_wall = ARENA_SPAN_LIMIT / m_arena_stride;
	if (UNLIKELY(span_wall == 0)) {
		Machine::machine_exception("VM group working memory exceeds the whole arena range",
			m_arena_stride);
	}
	this->m_capacity = std::min(wanted,
		std::min(wall, std::min(limits.max_vcpu_id, unsigned(span_wall))));
	if (UNLIKELY(this->m_capacity == 0)) {
		Machine::machine_exception("VM group has no vCPU capacity on this host");
	}

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
		close(this->m_fd);
		this->m_fd = -1;
		throw;
	}

	if (options.verbose_loader || VERBOSE_VM_GROUP) {
		printf("VM group %u: B=%u, arena 0x%lX + %u x %lu MiB (%lu MiB span, %lu MiB guard)\n",
			m_id, m_capacity, m_arena_base, m_capacity, m_arena_stride >> 20,
			span >> 20, GUARD_BAND >> 20);
	}
}

TINYKVM_COLD()
VmGroup::~VmGroup()
{
	/* Whole-group teardown is the only place a seat's vCPU may be closed and
	   its kvm_run unmapped. */
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
		if (seat->arena_hva != nullptr) {
			/* The whole stride was reserved, guard band included. */
			munmap(seat->arena_hva, m_arena_stride);
		}
	}
	if (this->m_fd >= 0) {
		close(this->m_fd);
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
	const unsigned index = m_seats.size();
	auto seat = std::make_unique<VmGroupSeat>();
	seat->kvm_vcpu_id = int(index);
	seat->arena_gpa = m_arena_base + uint64_t(index) * m_arena_stride;
	seat->arena_size = m_arena_stride - GUARD_BAND;

	/* One MAP_NORESERVE window per seat, covered by exactly one memslot.
	   MemoryBanks carves its banks out of this at fixed offsets, with no
	   mmap and no install per bank.

	   The window is reserved at the *full* stride but only its first
	   arena_size bytes are made accessible, so the guard band exists on both
	   sides of the boundary: unbacked in guest-physical space (the memslot
	   stops at arena_size), and PROT_NONE in the host address space. The
	   second half matters because seat windows land adjacent in host memory:
	   without it a host-side linear overrun off the end of a partition - a
	   page_duplicate() or memcpy() walking past the last bank - would quietly
	   land in a sibling's guest memory, where an unpooled VM's standalone
	   bank mmap would have SIGSEGV'd. */
	char* window = (char *) mmap(NULL, m_arena_stride, PROT_NONE,
		MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
	if (UNLIKELY(window == MAP_FAILED)) {
		throw MemoryException("Failed to allocate VM group arena partition",
			seat->arena_gpa, m_arena_stride);
	}
	if (UNLIKELY(mprotect(window, seat->arena_size, PROT_READ | PROT_WRITE) < 0)) {
		munmap(window, m_arena_stride);
		throw MemoryException("Failed to open the VM group arena partition window",
			seat->arena_gpa, seat->arena_size);
	}
	seat->arena_hva = window;

	seat->memslot = m_next_slot;
	try {
		this->install_slot(seat->memslot, seat->arena_gpa, seat->arena_hva,
			seat->arena_size);
	} catch (...) {
		munmap(seat->arena_hva, m_arena_stride);
		throw;
	}
	m_next_slot += 1;

	m_seats.push_back(std::move(seat));
	return m_seats.back().get();
}

VmGroupSeat* VmGroup::acquire_seat()
{
	std::scoped_lock lock(m_mtx);
	VmGroupSeat* seat = nullptr;
	if (!m_free.empty()) {
		seat = m_free.back();
		m_free.pop_back();
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
	std::scoped_lock lock(m_mtx);
	seat->live = false;
	m_free.push_back(seat);
	m_live -= 1;
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
	const size_t master_ranges = m_master.main_memory().mmap_ranges.size();
	std::shared_ptr<VmGroup> best = nullptr;
	unsigned fewest = 0;
	for (const auto& group : m_groups) {
		/* The frozen working-memory ceiling. The partitions of this group
		   were sized from it, and MemoryBanks::init_from_partition() rejects
		   a member asking for more - so a bigger member needs a group whose
		   ceiling freezes at the bigger budget.

		   NB: compared in whole pages, exactly as
		   MemoryBanks::init_from_partition() does, so that eligibility here
		   and the ceiling check there can never disagree. */
		if (group->max_cow_mem() / vMemory::PageSize()
			< options.max_cow_mem / vMemory::PageSize())
		{
			continue;
		}
		/* The master's mmap ranges, installed once at group creation. If the
		   master has grown more since, this group's VM has no memslot for
		   them; a new group installs the current set. */
		if (group->mmap_range_count() != master_ranges) {
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

	auto group = std::make_shared<VmGroup>(m_master, options, options.vm_group_size);
	auto* seat = group->acquire_seat();
	if (UNLIKELY(seat == nullptr)) {
		Machine::machine_exception("A new VM group could not hand out a seat");
	}
	m_groups.push_back(group);
	return {std::move(group), seat};
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

VmGroupSet& Machine::groups() const
{
	/* Lazily created, and only ever from the pooled fork path. The registry
	   mutex is global rather than per-Machine: it is entered once per pooled
	   master, and Machine is a hot, size-sensitive object. */
	static std::mutex registry_mtx;
	std::scoped_lock lock(registry_mtx);
	if (m_groups == nullptr) {
		m_groups.reset(new VmGroupSet{*this});
	}
	return *m_groups;
}

} // tinykvm
