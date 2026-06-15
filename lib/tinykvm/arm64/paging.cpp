#include "paging.hpp"

#include "../machine.hpp"
#include "../page_streaming.hpp"
#include "memory_layout.hpp"
#include <array>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <linux/kvm.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

namespace tinykvm {
namespace {

static constexpr uint64_t DESC_VALID = 1ULL << 0;
static constexpr uint64_t DESC_TABLE = 1ULL << 1;
static constexpr uint64_t DESC_PAGE = 1ULL << 1;
static constexpr uint64_t DESC_AF = 1ULL << 10;
static constexpr uint64_t DESC_SH_INNER = 3ULL << 8;
static constexpr uint64_t DESC_AP_USER = 1ULL << 6;
static constexpr uint64_t DESC_AP_RO = 1ULL << 7;
static constexpr uint64_t DESC_PXN = 1ULL << 53;
static constexpr uint64_t DESC_UXN = 1ULL << 54;
static constexpr uint64_t DESC_DIRTY = 1ULL << 55;
static constexpr uint64_t DESC_CLONEABLE = 1ULL << 56;
// Software-defined "accessed since fork" bit, used only by get_accessed_pages().
// Kept separate from DESC_DIRTY because DESC_DIRTY also signals "has content"
// for copy-on-write (see cow_page), and so must not be reset at fork time.
static constexpr uint64_t DESC_ACCESSED = 1ULL << 57;
static constexpr uint64_t ATTR_NORMAL = 0ULL << 2;
static constexpr uint64_t ATTR_DEVICE = 1ULL << 2;
static constexpr uint64_t L1_BLOCK_SIZE = 1ULL << 30;
static constexpr uint64_t L2_BLOCK_SIZE = 1ULL << 21;
static constexpr uint64_t L3_PAGE_SIZE = 1ULL << 12;
static constexpr uint64_t DESC_ADDR_MASK = 0x0000FFFFFFFFF000ULL;
static constexpr uint64_t DESC_FLAGS_MASK = ~DESC_ADDR_MASK;

static inline uint64_t l1_index(uint64_t addr) { return (addr >> 30) & 511; }
static inline uint64_t l2_index(uint64_t addr) { return (addr >> 21) & 511; }
static inline uint64_t l3_index(uint64_t addr) { return (addr >> 12) & 511; }

static inline bool is_valid(uint64_t entry) { return (entry & DESC_VALID) != 0; }
static inline bool is_table(uint64_t entry) { return (entry & (DESC_VALID | DESC_TABLE)) == (DESC_VALID | DESC_TABLE); }
static inline bool is_leaf(uint64_t entry, unsigned level)
{
	if (!is_valid(entry))
		return false;
	return level == 3 ? ((entry & DESC_PAGE) != 0) : ((entry & DESC_TABLE) == 0);
}
static inline bool is_writable(uint64_t entry) { return (entry & DESC_AP_RO) == 0; }
static inline bool has_flags(uint64_t entry, uint64_t flags)
{
	return (entry & flags) == flags;
}

static uint64_t sys_reg_id(unsigned op0, unsigned op1, unsigned crn, unsigned crm, unsigned op2)
{
	return KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM64_SYSREG
		| (((uint64_t)op0 << KVM_REG_ARM64_SYSREG_OP0_SHIFT) & KVM_REG_ARM64_SYSREG_OP0_MASK)
		| (((uint64_t)op1 << KVM_REG_ARM64_SYSREG_OP1_SHIFT) & KVM_REG_ARM64_SYSREG_OP1_MASK)
		| (((uint64_t)crn << KVM_REG_ARM64_SYSREG_CRN_SHIFT) & KVM_REG_ARM64_SYSREG_CRN_MASK)
		| (((uint64_t)crm << KVM_REG_ARM64_SYSREG_CRM_SHIFT) & KVM_REG_ARM64_SYSREG_CRM_MASK)
		| (((uint64_t)op2 << KVM_REG_ARM64_SYSREG_OP2_SHIFT) & KVM_REG_ARM64_SYSREG_OP2_MASK);
}

static void set_sysreg(vCPU& cpu, uint64_t id, uint64_t value)
{
	struct kvm_one_reg reg {
		.id = id,
		.addr = (uint64_t)&value,
	};
	if (ioctl(cpu.fd, KVM_SET_ONE_REG, &reg) < 0) {
		throw MachineException("KVM_SET_ONE_REG sysreg failed", errno);
	}
}

static uint64_t table_desc(uint64_t addr)
{
	return (addr & ~0xFFFULL) | DESC_TABLE | DESC_VALID;
}

static uint64_t block_desc(uint64_t addr, uint64_t attr, uint64_t prot)
{
	return (addr & ~0x1FFFFFULL) | attr | prot | DESC_AF | DESC_SH_INNER | DESC_VALID;
}

static uint64_t page_desc(uint64_t addr, uint64_t flags)
{
	return (addr & ~0xFFFULL) | flags | DESC_PAGE | DESC_AF | DESC_SH_INNER | ATTR_NORMAL | DESC_VALID;
}

static void memory_exception(const char* msg, uint64_t addr, uint64_t sz)
{
	throw MemoryException(msg, addr, sz);
}

static void split_l2_block(vMemory& memory, uint64_t& entry)
{
	const uint64_t base = entry & DESC_ADDR_MASK;
	const uint64_t flags = entry & DESC_FLAGS_MASK;
	auto page = memory.new_page();
	for (size_t i = 0; i < 512; i++) {
		page.pmem[i] = page_desc(base + (i << 12), flags);
	}
	entry = (page.addr & DESC_ADDR_MASK) | DESC_TABLE | DESC_VALID;
}

static void cow_page(vMemory& memory, uint64_t addr, uint64_t& entry, uint64_t*& data,
	WritablePageOptions options)
{
	if ((entry & DESC_CLONEABLE) == 0)
		return;
	if (memory.main_memory_writes) {
		entry &= ~DESC_CLONEABLE;
		entry &= ~DESC_AP_RO;
		memory.increment_unlocked_pages(1);
		return;
	}
	auto page = memory.new_page();
	assert((page.addr & ~DESC_ADDR_MASK) == 0);
	if (options.zeroes || (entry & DESC_DIRTY) == 0) {
		if (page.dirty)
			page_memzero(page.pmem);
	} else {
		page_duplicate(page.pmem, data);
	}
	entry = page.addr | (entry & (DESC_FLAGS_MASK & ~(DESC_CLONEABLE | DESC_AP_RO))) | DESC_VALID | DESC_PAGE;
	data = page.pmem;
	if (entry & DESC_AP_USER)
		memory.record_cow_leaf_user_page(addr);
}

static void install_vectors(Machine& machine)
{
	std::array<uint32_t, 2048 / sizeof(uint32_t)> vectors {};
	const uint32_t fatal[] {
		0xd2be0009, // movz x9, #0xf000, lsl #16
		0xf910013f, // str xzr, [x9, #0x2000 + vector]
		0x14000000, // b .
	};
	for (size_t off = 0; off < vectors.size(); off += 0x80 / sizeof(uint32_t)) {
		std::memcpy(&vectors[off], fatal, sizeof(fatal));
		const uint32_t byte_offset = off * sizeof(uint32_t);
		vectors[off + 1] = 0xf900013f | (((0x2000 + byte_offset) / 8) << 10);
	}

	uint32_t sync_aarch64[] {
		0xd518d089, // msr tpidr_el1, x9
		0xd5385209, // mrs x9, esr_el1
		0xd35afd29, // lsr x9, x9, #26
		0xf100553f, // cmp x9, #0x15 (SVC64)
		0x54000100, // b.eq +0x20
		0xf100913f, // cmp x9, #0x24 (data abort, same EL)
		0x54000140, // b.eq +0x28
		0xf100953f, // cmp x9, #0x25 (data abort, lower EL)
		0x54000100, // b.eq +0x20
		0xd2be0009, // movz x9, #0xf000, lsl #16
		0xf910013f, // str xzr, [x9, #0x2000 + vector]
		0x14000000, // b .
		0xd2be0009, // movz x9, #0xf000, lsl #16
		0xf9080128, // str x8, [x9, #0x1000] (syscall)
		0xd538d089, // mrs x9, tpidr_el1
		0xd69f03e0, // eret
		0xd2be0009, // movz x9, #0xf000, lsl #16
		0xf910013f, // str xzr, [x9, #0x2000 + vector]
		// The host has rewritten the faulting stage-1 PTE (CoW). Invalidate the
		// stale read-only translation for the faulting VA before retrying, or
		// the eret below may re-fault on a cached entry and loop until timeout.
		0xd5386009, // mrs x9, far_el1
		0xd34cfd29, // lsr x9, x9, #12
		0xd5088769, // tlbi vaae1, x9
		0xd5033b9f, // dsb ish
		0xd5033fdf, // isb
		0xd538d089, // mrs x9, tpidr_el1
		0xd69f03e0, // eret
	};
	sync_aarch64[10] = 0xf900013f | (((0x2000 + 0x200) / 8) << 10);
	sync_aarch64[17] = sync_aarch64[10];
	std::memcpy(&vectors[0x200 / sizeof(uint32_t)],
		sync_aarch64, sizeof(sync_aarch64));
	sync_aarch64[10] = 0xf900013f | (((0x2000 + 0x400) / 8) << 10);
	sync_aarch64[17] = sync_aarch64[10];
	std::memcpy(&vectors[0x400 / sizeof(uint32_t)],
		sync_aarch64, sizeof(sync_aarch64));

	const uint32_t return_stop[] {
		0xd2be0009, // movz x9, #0xf000, lsl #16
		0xf900013f, // str xzr, [x9]
	};
	std::memcpy(&vectors[(RET_STOP_ADDR - VECTORS_ADDR) / sizeof(uint32_t)],
		return_stop, sizeof(return_stop));

	// Stage-1 TLB entries survive a host-side TTBR0_EL1 write, so after the
	// page tables are rebuilt (fork reset) the guest must invalidate them
	// itself before resuming, or it keeps translating through recycled bank
	// pages. Entered at EL1 by arm64_flush_guest_tlb().
	const uint32_t tlb_flush[] {
		0xd5033a9f, // dsb ishst (page-table writes visible to the walker)
		0xd508831f, // tlbi vmalle1is
		0xd5033b9f, // dsb ish
		0xd5033fdf, // isb
		0xd2be0009, // movz x9, #0xf000, lsl #16
		0xf900013f, // str xzr, [x9] (STOP MMIO)
	};
	std::memcpy(&vectors[(TLB_FLUSH_ADDR - VECTORS_ADDR) / sizeof(uint32_t)],
		tlb_flush, sizeof(tlb_flush));

	/* rt_sigreturn trampoline, run at EL0 when a signal handler returns. The
	   handler's link register is set to SIGRETURN_TRAMPOLINE_ADDR by
	   Signals::enter; falling through to here issues the rt_sigreturn syscall
	   (number 139 on arm64) which restores the interrupted context. */
	const uint32_t sigreturn_tramp[] {
		0xd2801168, // movz x8, #139 (__NR_rt_sigreturn)
		0xd4000001, // svc #0
	};
	std::memcpy(&vectors[(SIGRETURN_TRAMPOLINE_ADDR - VECTORS_ADDR) / sizeof(uint32_t)],
		sigreturn_tramp, sizeof(sigreturn_tramp));

	std::memcpy(machine.unsafe_memory_at(VECTORS_ADDR, vectors.size() * sizeof(uint32_t)),
		vectors.data(), vectors.size() * sizeof(uint32_t));
}

static void install_identity_map(Machine& machine)
{
	std::array<uint64_t, 512> l1 {};
	std::array<uint64_t, 512> l2 {};
	std::array<uint64_t, 512> l2_trap {};
	std::array<uint64_t, 512> l3_low {};

	/* Guest RAM is EL0-accessible so that loaded programs run in usermode.
	   Usermode is load-bearing for CoW integrity: an EL1 guest could rewrite
	   its own stage-1 tables and strip the read-only bits that protect the
	   master VM's memory. A user-writable page is implicitly PXN at EL1;
	   set it explicitly as well. UXN stays clear: program code is loaded
	   into plain RAM and there are no per-segment protections (yet). */
	const uint64_t USER_RWX = DESC_AP_USER | DESC_PXN;

	l1[0] = table_desc(PT_ADDR + 0x1000);
	for (size_t i = 1; i < 4; i++) {
		l1[i] = block_desc(i * L1_BLOCK_SIZE, ATTR_NORMAL, USER_RWX);
	}
	l1[ARM64_STOP_MMIO_ADDR / L1_BLOCK_SIZE] = table_desc(PT_ADDR + 0x2000);

	l2[0] = table_desc(PT_ADDR + 0x3000);
	for (size_t i = 1; i < l2.size(); i++) {
		const uint64_t addr = i * L2_BLOCK_SIZE;
		l2[i] = block_desc(addr, ATTR_NORMAL, USER_RWX);
	}

	/* The first 2MB at page granularity: the vectors page must remain
	   EL1-executable, which requires it to be user-read-only (user-writable
	   forces PXN). It is also EL0-executable so usermode guests can return
	   through the RET_STOP stub. The page tables and vCPU table are EL1-only.
	   Pages below the vectors page stay unmapped to catch null dereferences. */
	l3_low[VECTORS_ADDR >> 12] = page_desc(VECTORS_ADDR, DESC_AP_USER | DESC_AP_RO);
	for (uint64_t addr = VECTORS_ADDR + 0x1000;
		addr < VCPU_TABLE_ADDR + VCPU_TABLE_SIZE; addr += 0x1000) {
		l3_low[addr >> 12] = page_desc(addr, DESC_UXN | DESC_PXN);
	}
	for (uint64_t addr = VCPU_TABLE_ADDR + VCPU_TABLE_SIZE;
		addr < L2_BLOCK_SIZE; addr += 0x1000) {
		l3_low[addr >> 12] = page_desc(addr, USER_RWX);
	}

	const uint64_t trap_l1_base = (ARM64_STOP_MMIO_ADDR / L1_BLOCK_SIZE) * L1_BLOCK_SIZE;
	for (size_t i = 0; i < l2_trap.size(); i++) {
		const uint64_t addr = trap_l1_base + i * L2_BLOCK_SIZE;
		const bool is_trap_block =
			addr <= ARM64_STOP_MMIO_ADDR && ARM64_STOP_MMIO_ADDR < addr + L2_BLOCK_SIZE;
		/* The trap block is user-accessible: EL0 guests stop through the
		   RET_STOP stub's store to the stop-MMIO address. */
		l2_trap[i] = block_desc(addr,
			is_trap_block ? ATTR_DEVICE : ATTR_NORMAL,
			is_trap_block ? (DESC_AP_USER | DESC_UXN | DESC_PXN) : USER_RWX);
	}

	std::memcpy(machine.unsafe_memory_at(PT_ADDR, l1.size() * sizeof(uint64_t)),
		l1.data(), l1.size() * sizeof(uint64_t));
	std::memcpy(machine.unsafe_memory_at(PT_ADDR + 0x1000, l2.size() * sizeof(uint64_t)),
		l2.data(), l2.size() * sizeof(uint64_t));
	std::memcpy(machine.unsafe_memory_at(PT_ADDR + 0x2000, l2_trap.size() * sizeof(uint64_t)),
		l2_trap.data(), l2_trap.size() * sizeof(uint64_t));
	std::memcpy(machine.unsafe_memory_at(PT_ADDR + 0x3000, l3_low.size() * sizeof(uint64_t)),
		l3_low.data(), l3_low.size() * sizeof(uint64_t));
}

} // namespace

void arm64_setup_el1_mmu(Machine& machine, vCPU& cpu)
{
	install_vectors(machine);
	install_identity_map(machine);

	const uint64_t MAIR_EL1 = sys_reg_id(3, 0, 10, 2, 0);
	const uint64_t TCR_EL1 = sys_reg_id(3, 0, 2, 0, 2);
	const uint64_t TTBR0_EL1 = sys_reg_id(3, 0, 2, 0, 0);
	const uint64_t SCTLR_EL1 = sys_reg_id(3, 0, 1, 0, 0);
	const uint64_t CPACR_EL1 = sys_reg_id(3, 0, 1, 0, 2);
	const uint64_t VBAR_EL1 = sys_reg_id(3, 0, 12, 0, 0);

	/* TCR_EL1.IPS caps stage-1 physical outputs; the identity-mapped RAM
	   sits below 4GB, but file-backed mmap regions are installed at
	   vMemory::MMAP_PHYS_BASE (32GB), so widen IPS to what the VM's
	   stage-2 actually supports. */
	const int pa_bits = arm64_vm_ipa_bits();
	const uint64_t ips =
		(pa_bits >= 48) ? 5 : (pa_bits >= 44) ? 4 : (pa_bits >= 42) ? 3 :
		(pa_bits >= 40) ? 2 : (pa_bits >= 36) ? 1 : 0;

	set_sysreg(cpu, MAIR_EL1, 0x00000000000000FFULL);
	set_sysreg(cpu, TCR_EL1, 32ULL | (1ULL << 8) | (1ULL << 10) | (3ULL << 12)
		| (ips << 32));
	set_sysreg(cpu, TTBR0_EL1, PT_ADDR);
	set_sysreg(cpu, VBAR_EL1, VECTORS_ADDR);
	set_sysreg(cpu, CPACR_EL1, 3ULL << 20);
	/* Beyond MMU+caches and the RES1 bits, EL0 guests need: SPAN keeps
	   PSTATE.PAN clear on exception entry (the vectors store to the
	   user-accessible MMIO trap pages); DZE/UCT/UCI allow EL0 `dc zva`,
	   CTR_EL0 reads and cache maintenance (glibc string routines);
	   nTWI/nTWE make EL0 wfi/wfe non-trapping. */
	set_sysreg(cpu, SCTLR_EL1,
		(1ULL << 0) | (1ULL << 2) | (1ULL << 12) |
		(1ULL << 11) | (1ULL << 20) | (1ULL << 22) |
		(1ULL << 28) | (1ULL << 29) |
		(1ULL << 14) | (1ULL << 15) | (1ULL << 16) |
		(1ULL << 18) | (1ULL << 23) | (1ULL << 26));

	/* CNTKCTL_EL1.EL0VCTEN|EL0PCTEN: let EL0 read the generic-timer counters
	   (CNTVCT_EL0 / CNTPCT_EL0) directly. Without this an `mrs x, cntvct_el0`
	   -- emitted inline by ordinary timing/benchmark code, e.g. numpy's bundled
	   OpenBLAS during CPU detection -- traps to EL1 (ESR EC=0x18) and, with no
	   handler, aborts the guest. The counter is the host's, so it advances and
	   varies per fork (it is not frozen like the gettimeofday path). */
	const uint64_t CNTKCTL_EL1 = sys_reg_id(3, 0, 14, 1, 0);
	set_sysreg(cpu, CNTKCTL_EL1, (1ULL << 0) | (1ULL << 1));
}

void print_pagetables(const vMemory& memory)
{
	foreach_page(memory, [] (uint64_t addr, uint64_t& entry, size_t size) {
		printf("ARM64 PT 0x%016lX size 0x%zX -> 0x%016lX flags 0x%016lX\n",
			addr, size, entry & DESC_ADDR_MASK, entry & ~DESC_ADDR_MASK);
	});
}

void foreach_page(vMemory& memory, foreach_page_t callback, bool skip_oob_addresses)
{
	auto* l1 = memory.page_at(memory.page_tables);
	for (uint64_t i = 0; i < 512; i++) {
		if (!is_valid(l1[i]))
			continue;
		const uint64_t l1_base = i << 30;
		callback(l1_base, l1[i], L1_BLOCK_SIZE);
		if (is_leaf(l1[i], 1))
			continue;
		const uint64_t l2_mem = l1[i] & DESC_ADDR_MASK;
		if (skip_oob_addresses && l2_mem >= memory.physbase + memory.size)
			continue;
		auto* l2 = memory.page_at(l2_mem);
		for (uint64_t j = 0; j < 512; j++) {
			if (!is_valid(l2[j]))
				continue;
			const uint64_t l2_base = l1_base | (j << 21);
			callback(l2_base, l2[j], L2_BLOCK_SIZE);
			if (is_leaf(l2[j], 2))
				continue;
			const uint64_t l3_mem = l2[j] & DESC_ADDR_MASK;
			if (skip_oob_addresses && l3_mem >= memory.physbase + memory.size)
				continue;
			auto* l3 = memory.page_at(l3_mem);
			for (uint64_t k = 0; k < 512; k++) {
				if (is_valid(l3[k])) {
					callback(l2_base | (k << 12), l3[k], L3_PAGE_SIZE);
				}
			}
		}
	}
}

void foreach_page(const vMemory& memory, foreach_page_t callback, bool skip_oob_addresses)
{
	foreach_page(const_cast<vMemory&>(memory), std::move(callback), skip_oob_addresses);
}

void foreach_page_makecow(vMemory& memory, uint64_t kernel_end,
	uint64_t shared_memory_boundary, bool)
{
	if (shared_memory_boundary < kernel_end)
		memory_exception("Shared memory boundary was illegal (zero)", shared_memory_boundary, 0);
	foreach_page(memory, [=] (uint64_t addr, uint64_t& entry, size_t size) {
		if (addr < shared_memory_boundary && is_leaf(entry, size == L3_PAGE_SIZE ? 3 : 2)
			&& is_writable(entry) && (entry & ATTR_DEVICE) != ATTR_DEVICE) {
			entry |= DESC_AP_RO | DESC_CLONEABLE;
		}
		// Reset access tracking for all pages so get_accessed_pages() reports
		// only the pages touched after this fork point.
		entry &= ~DESC_ACCESSED;
	});
}

std::vector<std::pair<uint64_t, uint64_t>> get_accessed_pages(const vMemory& memory)
{
	std::vector<std::pair<uint64_t, uint64_t>> accessed_pages;
	foreach_page(memory,
	[&accessed_pages] (uint64_t addr, uint64_t& entry, size_t size) {
		const unsigned level = size == L3_PAGE_SIZE ? 3 : (size == L2_BLOCK_SIZE ? 2 : 1);
		if (is_leaf(entry, level) && (entry & DESC_ACCESSED)) {
			accessed_pages.push_back({addr, size});
		}
	}, false);
	return accessed_pages;
}

void page_at(vMemory& memory, uint64_t addr, foreach_page_t callback, bool ignore_missing)
{
	auto* l1 = memory.page_at(memory.page_tables);
	uint64_t& e1 = l1[l1_index(addr)];
	if (!is_valid(e1)) {
		if (ignore_missing) return;
		memory_exception("page_at: l1 entry not present", addr, L1_BLOCK_SIZE);
	}
	if (is_leaf(e1, 1)) {
		callback(addr & ~(L1_BLOCK_SIZE - 1), e1, L1_BLOCK_SIZE);
		return;
	}
	auto* l2 = memory.page_at(e1 & DESC_ADDR_MASK);
	uint64_t& e2 = l2[l2_index(addr)];
	if (!is_valid(e2)) {
		if (ignore_missing) return;
		memory_exception("page_at: l2 entry not present", addr, L2_BLOCK_SIZE);
	}
	if (is_leaf(e2, 2)) {
		callback(addr & ~(L2_BLOCK_SIZE - 1), e2, L2_BLOCK_SIZE);
		return;
	}
	auto* l3 = memory.page_at(e2 & DESC_ADDR_MASK);
	uint64_t& e3 = l3[l3_index(addr)];
	if (!is_valid(e3)) {
		if (ignore_missing) return;
		memory_exception("page_at: l3 entry not present", addr, L3_PAGE_SIZE);
	}
	callback(addr & ~(L3_PAGE_SIZE - 1), e3, L3_PAGE_SIZE);
}

WritablePage writable_page_at(vMemory& memory, uint64_t addr, uint64_t verify_flags,
	WritablePageOptions options)
{
	auto* l1 = memory.page_at(memory.page_tables);
	uint64_t& e1 = l1[l1_index(addr)];
	if (!is_valid(e1))
		memory_exception("writable_page_at: l1 entry not present", addr, L1_BLOCK_SIZE);
	if (is_leaf(e1, 1))
		memory_exception("writable_page_at: 1GB blocks are not writable through host API", addr, L1_BLOCK_SIZE);
	auto* l2 = memory.page_at(e1 & DESC_ADDR_MASK);
	uint64_t& e2 = l2[l2_index(addr)];
	if (!is_valid(e2))
		memory_exception("writable_page_at: l2 entry not present", addr, L2_BLOCK_SIZE);
	if (is_leaf(e2, 2)) {
		// Split a cloneable *or* read-only block so the specific 4KB page is
		// resolved (and, where needed, copy-on-write'd) in the L3 path below.
		// A read-only, non-cloneable block is a plain mapping -- e.g. a
		// file-backed .so hugepage installed by mmap_backed_area -- that the
		// host or guest now needs to write to.
		if (((e2 & DESC_CLONEABLE) || !is_writable(e2)) && memory.split_hugepages)
			split_l2_block(memory, e2);
		else if (!has_flags(e2, verify_flags) || !is_writable(e2))
			memory_exception("writable_page_at: l2 entry not writable", addr, e2);
		else {
			auto* data = memory.page_at(e2 & DESC_ADDR_MASK);
			return WritablePage{
				.page = (char*)data + (addr & (L2_BLOCK_SIZE - 1)),
				.entry = e2,
				.size = L2_BLOCK_SIZE,
			};
		}
	}
	auto* l3 = memory.page_at(e2 & DESC_ADDR_MASK);
	uint64_t& e3 = l3[l3_index(addr)];
	if (!is_valid(e3))
		memory_exception("writable_page_at: l3 entry not present", addr, L3_PAGE_SIZE);
	auto* data = memory.page_at(e3 & DESC_ADDR_MASK);
	cow_page(memory, addr, e3, data, options);
	// A present, read-only, non-cloneable page is not a copy-on-write clone
	// source, so cow_page() leaves it untouched -- but the caller still needs to
	// write here (filling a fresh mmap that overlaps a file-backed mapping, or a
	// guest store to it). Promote it: on the identity-mapped master in place
	// (makecow re-marks it copy-on-write at snapshot); on a fork via a private
	// copy, so the write cannot bleed into the shared master page.
	if (is_valid(e3) && !is_writable(e3) && (e3 & DESC_CLONEABLE) == 0) {
		if (memory.machine.is_forked()) {
			auto page = memory.new_page();
			if (options.zeroes || (e3 & DESC_DIRTY) == 0) {
				if (page.dirty)
					page_memzero(page.pmem);
			} else {
				page_duplicate(page.pmem, data);
			}
			e3 = page.addr
				| (e3 & (DESC_FLAGS_MASK & ~(DESC_CLONEABLE | DESC_AP_RO)))
				| DESC_VALID | DESC_PAGE;
			data = page.pmem;
			if (e3 & DESC_AP_USER)
				memory.record_cow_leaf_user_page(addr);
		} else {
			e3 &= ~DESC_AP_RO;
		}
	}
	if (!has_flags(e3, verify_flags) || !is_writable(e3))
		memory_exception("writable_page_at: l3 entry not writable", addr, e3);
	return WritablePage{.page = (char*)data, .entry = e3, .size = L3_PAGE_SIZE};
}

char* readable_page_at(const vMemory& memory, uint64_t addr, uint64_t flags)
{
	auto* l1 = memory.page_at(memory.page_tables);
	const uint64_t e1 = l1[l1_index(addr)];
	if (!is_valid(e1))
		memory_exception("readable_page_at: l1 entry not present", addr, L1_BLOCK_SIZE);
	if (is_leaf(e1, 1)) {
		if (!has_flags(e1, flags))
			memory_exception("readable_page_at: l1 entry not readable", addr, e1);
		return (char*)memory.page_at(e1 & DESC_ADDR_MASK) + (addr & (L1_BLOCK_SIZE - 1));
	}
	auto* l2 = memory.page_at(e1 & DESC_ADDR_MASK);
	const uint64_t e2 = l2[l2_index(addr)];
	if (!is_valid(e2))
		memory_exception("readable_page_at: l2 entry not present", addr, L2_BLOCK_SIZE);
	if (is_leaf(e2, 2)) {
		if (!has_flags(e2, flags))
			memory_exception("readable_page_at: l2 entry not readable", addr, e2);
		return (char*)memory.page_at(e2 & DESC_ADDR_MASK) + (addr & (L2_BLOCK_SIZE - 1));
	}
	auto* l3 = memory.page_at(e2 & DESC_ADDR_MASK);
	const uint64_t e3 = l3[l3_index(addr)];
	if (!has_flags(e3, flags))
		memory_exception("readable_page_at: l3 entry not readable", addr, e3);
	return (char*)memory.page_at(e3 & DESC_ADDR_MASK);
}

void WritablePage::set_dirty()
{
	// A host/guest write is the only access signal we have (DESC_AF is always
	// pre-set, so reads do not fault); record it for get_accessed_pages() too.
	entry |= DESC_DIRTY | DESC_ACCESSED;
}

void WritablePage::set_protections(int prot)
{
	if (prot & PROT_READ)
		entry |= DESC_VALID;
	else
		entry &= ~DESC_VALID;
	if (prot & PROT_WRITE)
		entry &= ~DESC_AP_RO;
	else
		entry |= DESC_AP_RO;
	// Execute permission (EL0). Guest RAM is uniformly EL0-executable: the
	// identity map sets no UXN, and mprotect() is a no-op on this port, so the
	// PROT_EXEC that a loader applies after mapping a segment PROT_READ can
	// never take effect. Setting UXN here (for a file-backed mapping installed
	// by mmap_backed_area) would therefore leave a .so text segment permanently
	// non-executable and fault on first instruction fetch. Keep UXN clear and
	// let PXN alone track PROT_EXEC as EL1 defence in depth.
	entry &= ~DESC_UXN;
	if (prot & PROT_EXEC)
		entry &= ~DESC_PXN;
	else
		entry |= DESC_PXN;
}

size_t paging_merge_leaf_pages_into_hugepages(vMemory& memory, bool merge_if_dirty)
{
	size_t merged_pages = 0;
	auto* l1 = memory.page_at(memory.page_tables);

	for (uint64_t i = 0; i < 512; i++) {
		if (!is_valid(l1[i]) || is_leaf(l1[i], 1))
			continue;

		const uint64_t l2_mem = l1[i] & DESC_ADDR_MASK;
		auto* l2 = memory.page_at(l2_mem);

		for (uint64_t j = 0; j < 512; j++) {
			if (!is_table(l2[j]))
				continue;

			const uint64_t l3_mem = l2[j] & DESC_ADDR_MASK;
			auto* l3 = memory.page_at(l3_mem);

			if (!is_leaf(l3[0], 3))
				continue;

			const uint64_t first_addr = l3[0] & DESC_ADDR_MASK;
			if ((first_addr & (L2_BLOCK_SIZE - 1)) != 0)
				continue;

			// Dirty and accessed bits vary per page and must not block a merge.
			const uint64_t merge_flag_mask =
				DESC_FLAGS_MASK & ~(DESC_PAGE | DESC_DIRTY | DESC_ACCESSED);
			const uint64_t first_flags = l3[0] & merge_flag_mask;
			bool can_merge = true;
			bool any_dirty = (l3[0] & DESC_DIRTY) != 0;
			bool all_dirty = (l3[0] & DESC_DIRTY) != 0;
			bool any_accessed = (l3[0] & DESC_ACCESSED) != 0;
			uint64_t expected_addr = first_addr;

			for (size_t k = 1; k < 512; k++) {
				expected_addr += L3_PAGE_SIZE;
				if (!is_leaf(l3[k], 3)
					|| (l3[k] & DESC_ADDR_MASK) != expected_addr
					|| (l3[k] & merge_flag_mask) != first_flags) {
					can_merge = false;
					break;
				}

				if (l3[k] & DESC_DIRTY)
					any_dirty = true;
				else
					all_dirty = false;
				if (l3[k] & DESC_ACCESSED)
					any_accessed = true;
			}

			if (can_merge && (merge_if_dirty || !any_dirty || all_dirty)) {
				l2[j] = first_addr | first_flags;
				if (any_dirty)
					l2[j] |= DESC_DIRTY;
				if (any_accessed)
					l2[j] |= DESC_ACCESSED;
				merged_pages += 512;
			}
		}
	}

	return merged_pages;
}

uint64_t paging_default_usermode_flags(bool)
{
	/* Used only to verify writability on this arch. UXN must not be part of
	   the check: user pages are mapped executable (no per-segment protections
	   yet), so requiring it would reject every ordinary RAM page. */
	return DESC_VALID;
}

uint64_t paging_address_mask()
{
	return DESC_ADDR_MASK;
}

uint64_t paging_dirty_bit()
{
	return DESC_DIRTY;
}

} // namespace tinykvm
