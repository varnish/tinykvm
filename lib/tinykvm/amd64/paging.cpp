#include "paging.hpp"

#include "amd64.hpp"
#include "memory_layout.hpp"
#include "vdso.hpp"
#include "../machine.hpp"
#include "../page_streaming.hpp"
#include "../util/elf.h"
#include <cassert>
#include <cstring>
#include <stdexcept>
//#define KVM_VERBOSE_PAGETABLES

#ifdef KVM_VERBOSE_PAGETABLES
#define CLPRINT(fmt, ...) printf(fmt, ##__VA_ARGS__);
#else
#define CLPRINT(...) /* ... */
#endif
#define PDE64_CLONEABLE  (1ul << 11)

namespace tinykvm {

/* We want to remove the CLONEABLE bit after a page has been duplicated */
static constexpr uint64_t PDE64_ADDR_MASK = ~0x8000000000000FFF;
static constexpr uint64_t PDE64_CLONED_MASK = 0x8000000000000FFF & ~(PDE64_CLONEABLE | PDE64_G);
static constexpr uint64_t PDE64_PD_SPLIT_MASK = 0x8000000000000FFF & ~(PDE64_RW | PDE64_CLONEABLE | PDE64_G);

__attribute__((cold, noinline, noreturn))
static void memory_exception(const char*, uint64_t addr, uint64_t sz);

using ptentry_pair = std::tuple<uint64_t, uint64_t, uint64_t>;
inline ptentry_pair pdpt_from_index(size_t i, uint64_t* pml4) {
	return {i << 39, pml4[i] & ~(uint64_t) 0xFFF, 1ul << 39};
}
inline ptentry_pair pd_from_index(size_t i, uint64_t pdpt_base, uint64_t* pdpt) {
	return {pdpt_base | (i << 30), pdpt[i] & PDE64_ADDR_MASK, 1ul << 30};
}
inline ptentry_pair pt_from_index(size_t i, uint64_t pd_base, uint64_t* pd) {
	return {pd_base | (i << 21), pd[i] & PDE64_ADDR_MASK, 1ul << 21};
}
inline ptentry_pair pte_from_index(size_t i, uint64_t pt_base, uint64_t* pt) {
	return {pt_base | (i << 12), pt[i] & PDE64_ADDR_MASK, 1ul << 12};
}

inline uint64_t index_from_pdpt_entry(uint64_t addr) {
	return (addr >> 30) & 511;
}
inline uint64_t index_from_pd_entry(uint64_t addr) {
	return (addr >> 21) & 511;
}
inline uint64_t index_from_pt_entry(uint64_t addr) {
	return (addr >> 12) & 511;
}

inline bool is_flagged_page(uint64_t flags, uint64_t entry) {
	return (entry & flags) == flags;
}

static void add_remappings(vMemory& memory,
	const VirtualRemapping& remapping,
	uint64_t* pml4,
	uint64_t flags,
	uint64_t& free_page)
{
	if (remapping.virt <= free_page)
		throw MachineException("Invalid remapping address", remapping.virt);
	if (remapping.size % vMemory::PageSize() != 0)
		throw MachineException("Invalid remapping size", remapping.size);
	const auto virt_tera_page = (remapping.virt >> 39U) & 511;
	auto virt_giga_page = (remapping.virt >> 30U) & 511;

	uint64_t paddr_base = remapping.phys;
	// Blackout remappings are used to reserve/create unmapped virtual memory space
	if (paddr_base == 0x0 && !remapping.blackout) {
		constexpr auto PD_ALIGN_MASK = (1ULL << 21U) - 1;
		// Over-allocate rounding up to nearest 2MB
		paddr_base = memory.machine.mmap_allocate(remapping.size + PD_ALIGN_MASK);
		paddr_base = (paddr_base + PD_ALIGN_MASK) & ~PD_ALIGN_MASK;
	}

	if (pml4[virt_tera_page] == 0) {
		const auto pdpt_addr = free_page;
		free_page += 0x1000;

		pml4[virt_tera_page] = PDE64_PRESENT | PDE64_USER | PDE64_RW | pdpt_addr;
	}

	auto  pdpt_addr = pml4[virt_tera_page] & PDE64_ADDR_MASK;
	auto* pdpt = memory.page_at(pdpt_addr);

	constexpr auto PDPT_ALIGN_MASK = (1ULL << 30U) - 1;
	constexpr auto PD_ALIGN_MASK = (1ULL << 21U) - 1;
	const auto n_pd_pages = ((remapping.size + PDPT_ALIGN_MASK) >> 30UL) & 511;
	const auto n_2mb_pages = (remapping.size + PD_ALIGN_MASK) >> 21UL;
	for (uint64_t n_pd = 0; n_pd < n_pd_pages; n_pd++)
	{
		const bool last_pd = (n_pd == n_pd_pages - 1);
		// Allocate the gigapage with 512x 2MB entries
		if (pdpt[virt_giga_page] == 0) {
			const auto giga_page = free_page;
			free_page += 0x1000;
			pdpt[virt_giga_page] = PDE64_PRESENT | PDE64_USER | PDE64_RW | giga_page;

			if (n_pd > 0 && n_pd-1 < n_pd_pages) {
				// This entire page (all 512x 2MB entries) has a mapping
				if (remapping.blackout) {
					// Unmap the entire page
					pdpt[virt_giga_page] = 0;
					continue;
				}
			}
		}

		auto  pd_addr = pdpt[virt_giga_page] & PDE64_ADDR_MASK;
		auto* pd = memory.page_at(pd_addr);
		const unsigned last_pd_pages = (n_2mb_pages & 511);

		// Create 2MB entries for the gigapage
		for (uint64_t i = 0; i < 512; i++)
		{
			if ((!last_pd || i < last_pd_pages) && !remapping.blackout) {
				const auto paddr = paddr_base + (i << 21UL);
				pd[i] = PDE64_PRESENT | flags | PDE64_PS | paddr;
			}
			else pd[i] = 0; // Unmapped 2MB page (remainder or blackout)
		}

		virt_giga_page++; // Next gigapage
	}

#ifdef KVM_VERBOSE_PAGETABLES
	printf("Remapping 0x%lX -> 0x%lX  size 0x%lX write=%d exec=%d blackout=%d\n",
		remapping.virt, paddr_base, remapping.size,
		remapping.writable, remapping.executable, remapping.blackout);
#endif
}

uint64_t setup_amd64_paging(vMemory& memory,
	std::string_view binary,
	const std::vector<VirtualRemapping>& remappings,
	bool split_hugepages, bool split_all_hugepages_during_loading)
{
	static constexpr uint64_t PD_MASK = (1ULL << 30) - 1;
	const size_t PD_PAGES = (memory.size + PD_MASK) >> 30;
	const uint64_t PD_END = 0x3000 + PD_PAGES * 0x1000;

	// guest physical
	const uint64_t pml4_addr = memory.page_tables;
	const uint64_t pdpt_addr = pml4_addr + 0x1000;
	const uint64_t low1_addr = pml4_addr + 0x2000;

	std::vector<uint64_t> pdpage_addr(PD_PAGES);
	for (size_t i = 0; i < PD_PAGES; i++)
		pdpage_addr.at(i) = pml4_addr + 0x3000 + i * 0x1000;

	// userspace
	char* pagetable = memory.at(memory.page_tables);
	auto* pml4 = (uint64_t*) (pagetable + 0x0);
	auto* pdpt = (uint64_t*) (pagetable + 0x1000);
	auto* lowpage = (uint64_t*) (pagetable + 0x2000);

	auto* pd   = (uint64_t*) (pagetable + 0x3000); /* GB pages */

	const uint64_t vdso_pdpt_addr = pml4_addr + PD_END + 0x0;
	const uint64_t vsyscall_pd_addr = pml4_addr + PD_END + 0x1000;
	const uint64_t vsyscall_pt_addr = pml4_addr + PD_END + 0x2000;
	auto* vdso_pdpt = (uint64_t *)(pagetable + PD_END + 0x0000);
	auto* vsyscall_pd = (uint64_t *)(pagetable + PD_END + 0x1000);
	auto* vsyscall_pt = (uint64_t *)(pagetable + PD_END + 0x2000);

	// next free page for ELF loader
	uint64_t free_page = pml4_addr + PD_END + 0x3000;

	pml4[0] = PDE64_PRESENT | PDE64_USER | PDE64_RW | pdpt_addr;
	pml4[511] = PDE64_PRESENT | PDE64_USER | vdso_pdpt_addr;

	const auto base_giga_page = (memory.physbase >> 30UL) & 511;
	for (size_t n_pd = 0; n_pd < PD_PAGES; n_pd++)
	{
		auto& pdpt_entry = pdpt[base_giga_page+n_pd];
		pdpt_entry = PDE64_PRESENT | PDE64_USER | PDE64_RW | pdpage_addr.at(n_pd);

		// If this is not the first 1GB page, and there is >= 1GB left,
		// treat this as a leaf 1GB page by setting the PS bit.
		//if (n_pd > 0 && n_pd-1 < PD_PAGES) {
		//	pdpt_entry |= PDE64_PS;
		//}
	}

	const auto base_2mb_page = (memory.physbase >> 21UL) & 511;
	pd[base_2mb_page+0] = PDE64_PRESENT | PDE64_USER | PDE64_RW | low1_addr;

	lowpage[0] = 0; /* Null-page at PHYS+0x0 */
	/* GDT, IDT and TSS */
	lowpage[1] = PDE64_PRESENT | PDE64_RW | PDE64_NX | (memory.physbase + 0x1000);
	lowpage[6] = PDE64_PRESENT | PDE64_G | PDE64_NX | (memory.physbase + VSYS_ADDR);
	lowpage[7] = PDE64_PRESENT | PDE64_G | PDE64_NX | (memory.physbase + TSS_SMP_ADDR);

	/* Kernel code: Exceptions, system calls */
	const uint64_t except_page = INTR_ASM_ADDR >> 12;
	lowpage[except_page] = PDE64_PRESENT | PDE64_G | (memory.physbase + INTR_ASM_ADDR);

	/* Exception (IST) stack */
	const uint64_t ist_page = IST_ADDR >> 12;
	lowpage[ist_page+0] = PDE64_PRESENT | PDE64_RW | PDE64_NX | (memory.physbase + IST_ADDR);
	lowpage[ist_page+1] = 0; //PDE64_PRESENT | PDE64_RW | PDE64_NX | (memory.physbase + IST2_ADDR);

	/* Usercode page: Entry, exit */
	const uint64_t user_page = USER_ASM_ADDR >> 12;
	lowpage[user_page] = PDE64_PRESENT | PDE64_USER | PDE64_G | (memory.physbase + USER_ASM_ADDR);

	/* Initial userspace area (no execute) */
	pd[base_2mb_page+1] = PDE64_PRESENT | PDE64_USER | PDE64_RW | free_page;
	{
		// Spend one page pre-splitting the (likely) stack area
		auto* pte = (uint64_t*) memory.at(free_page);
		// Set writable 4k attributes
		for (uint64_t i = 0; i < 512; i++) {
			// Second 2MB page in the physical memory area
			uint64_t addr4k = ((base_giga_page << 30) + ((base_2mb_page+1) << 21)) + (i << 12);
			pte[i] = PDE64_PRESENT | PDE64_USER | PDE64_RW | PDE64_NX | addr4k;
		}
		free_page += 0x1000;
	}

	// Covers 1GB pages with 512x 2MB user-read-write entries
	// NOTE: Even with executable heap, the ELF loader will still correctly
	// apply the NX-bit to its own segments.
	uint64_t heap_flags = PDE64_USER | PDE64_RW;
	if (!memory.executable_heap)
		heap_flags |= PDE64_NX;
	for (uint64_t i = base_2mb_page+2; i < 512*PD_PAGES; i++) {
		pd[i] = PDE64_PRESENT | PDE64_PS | heap_flags
			| ((base_giga_page << 30) + (i << 21));
	}

	if (split_all_hugepages_during_loading)
	{
		static constexpr uint64_t MAX_FREE_PAGE = 509ULL * 0x1000;
		// Stop at 1MB address, to prevent trampling user space
		uint64_t max = 512 * PD_PAGES;
		if (max > 512U * 1U)
			max = 512U * 1U;

		// Split all hugepages into 4k pages for the entire memory area
		for (uint64_t i = base_2mb_page+2; i < max && free_page < MAX_FREE_PAGE; i++)
		{
			if (pd[i] & PDE64_PS) {
				// Set default attributes + free PTE page
				pd[i] = PDE64_PRESENT | heap_flags | free_page;
				// Fill new page with default heap attributes
				auto* pagetable = (uint64_t*) memory.at(free_page);
				for (uint64_t j = 0; j < 512; j++) {
					const uint64_t addr4k = (base_giga_page << 30) | (i << 21) | (j << 12);
					pagetable[j] =
						PDE64_PRESENT | heap_flags | addr4k;
				}
				free_page += 0x1000;
			}
		}
	}

	/* ELF executable area */
	if (!binary.empty())
	{
		const auto* elf = (Elf64_Ehdr*) binary.data();
		const auto program_headers = elf->e_phnum;
		const auto* phdr = (Elf64_Phdr*) (binary.data() + elf->e_phoff);

		for (const auto* hdr = phdr; hdr < phdr + program_headers; hdr++)
		{
			if (hdr->p_type == PT_LOAD)
			{
				const size_t len = hdr->p_filesz;
				const uint64_t load_address = memory.machine.image_base() + hdr->p_vaddr;
				if (!memory.safely_within(load_address, len)) {
					throw MachineException("Unsafe PT_LOAD segment or executable too big");
				}
				const bool read  = (hdr->p_flags & PF_R) != 0;
				const bool write = (hdr->p_flags & PF_W) != 0;
				const bool exec  = (hdr->p_flags & PF_X) != 0;

				/* TODO: Prevent extremely high addresses */
				/* XXX: Prevent crossing gigabyte boundries */
				auto base = load_address & ~PageMask();
				auto end  = ((load_address + len) + PageMask()) & ~PageMask();
	#if 0
				printf("0x%lX->0x%lX --> 0x%lX:0x%lX\n",
					load_address, load_address + len, base, end);
	#endif
				for (size_t addr = base; addr < end;)
				{
					auto pdidx = (addr >> 21) & 511;
					// Look for *complete* 2MB pages within segment
					// If split_hugepages is enabled, we want to avoid writable 2MB pages
					if ((addr & ~0xFFFFFFFFFFE00FFFULL) == 0 && (!split_hugepages || !write))
					{
						auto& ptentry = pd[pdidx];
						// Aligned 2MB _leaf_ page within segment
						if (addr + (1UL << 21) <= end && (ptentry & PDE64_PS) == PDE64_PS) {
							// This is a 2MB-aligned ELF segment, with a leaf 2MB page entry
	#if 0
							printf("Found 2MB segment at 0x%lX -> 0x%lX\n", addr, end);
	#endif
							const uint64_t addr2m = (base_giga_page << 30) | (pdidx << 21);
							ptentry = PDE64_PRESENT | PDE64_USER | PDE64_NX | PDE64_PS | addr2m;
							if (!read) ptentry &= ~PDE64_PRESENT; // A weird one, but... AMD64.
							if (write) ptentry |= PDE64_RW;
							else ptentry |= PDE64_G; // Global bit for read-only pages
							if (exec) ptentry &= ~PDE64_NX;
							// Increment whole 2MB page
							addr += (1UL << 21);
							continue;
						}
					}

					// Un-aligned 2MB pages must be split into 4k array
					if (pd[pdidx] & PDE64_PS) {
						// Set default attributes + free PTE page
						pd[pdidx] = PDE64_PRESENT | PDE64_USER | PDE64_RW | free_page;
						// Fill new page with default attributes
						auto* pagetable = (uint64_t*) memory.at(free_page);
						for (uint64_t i = 0; i < 512; i++) {
							// Set writable 4k attributes
							uint64_t addr4k = (base_giga_page << 30) | (pdidx << 21) | (i << 12);
							pagetable[i] =
								PDE64_PRESENT | PDE64_USER | PDE64_RW | PDE64_NX | addr4k;
						}
						free_page += 0x1000;
					}

					// Get the pagetable array (NB: mask out NX)
					auto ptaddr = pd[pdidx] & PDE64_ADDR_MASK;
					auto* pagetable = (uint64_t*) memory.at(ptaddr);
					// Set read-only 4k attributes
					auto entry = (addr >> 12) & 511;
					auto& ptentry = pagetable[entry];
	/*				if ((ptentry & PDE64_NX) && exec) {
						printf("NX-bit before on 0x%lX, but exec now\n", addr);
					}
					if (!(ptentry & PDE64_NX) && !exec) {
						printf("Execute on 0x%lX, but not exec now\n", addr);
					}*/
					if (exec)
						ptentry &= ~PDE64_NX;
					else
						ptentry |= PDE64_NX;
					if (!read) ptentry &= ~PDE64_PRESENT;
					if (!write) {
						ptentry &= ~PDE64_RW;
						ptentry |= PDE64_G; // Global bit for read-only pages
					}
					addr += 0x1000;
				}
			}
		}
	} // Valid ELF binary

	/* Virtual memory remappings (up to 1GB each, for now) */
	for (const auto& vmem : remappings)
	{
		uint64_t flags = PDE64_USER | PDE64_NX;
		if (vmem.writable) flags |= PDE64_RW;
		else flags |= PDE64_G; // Global bit for read-only pages
		if (vmem.executable) flags &= ~PDE64_NX;
		if (vmem.blackout) flags = 0;
		if constexpr (false) {
			printf("* Remapping 0x%lX -> 0x%lX  size 0x%lX write=%d exec=%d blackout=%d\n",
				vmem.virt, vmem.phys, vmem.size, vmem.writable, vmem.executable, vmem.blackout);
		}
		add_remappings(memory, vmem, pml4, flags, free_page);
	}

	// vDSO / vsyscall
	// vsyscall gettimeofday: 0xFFFFFFFFFF600000
	vdso_pdpt[511] = PDE64_PRESENT | PDE64_USER | PDE64_G | vsyscall_pd_addr;
	vsyscall_pd[507] = PDE64_PRESENT | PDE64_USER | PDE64_G | vsyscall_pt_addr;
	vsyscall_pt[0] = PDE64_PRESENT | PDE64_USER | PDE64_G | (memory.physbase + VSYS_ADDR);

	/* Kernel area ~64KB */
	const size_t kernel_begin_idx = PT_ADDR >> 12;
	const size_t kernel_end_idx = (free_page >> 12) & 511;
	for (unsigned i = kernel_begin_idx; i < kernel_end_idx; i++) {
		lowpage[i] = PDE64_PRESENT | PDE64_G | PDE64_NX;
	}

	/* Stack area ~64KB -> 2MB */
	for (unsigned i = kernel_end_idx; i < 512; i++) {
		lowpage[i] = PDE64_PRESENT | PDE64_USER | PDE64_RW | PDE64_NX
			| (base_giga_page << 30) | (base_2mb_page << 21) | (i << 12);
	}

	if (free_page >= memory.physbase + (2ULL << 20)) {
		throw MachineException("Pagetable setup exceeded 2MB limit");
	}

	/* Verify a kernel page */
	page_at(memory, memory.physbase + 0x1000,
		[&memory] (uint64_t addr, uint64_t& entry, size_t size) {
			if (addr != memory.physbase + 0x1000 || size != PAGE_SIZE
				|| (entry & PDE64_ADDR_MASK) != memory.physbase + 0x1000) {
				throw MachineException("Corrupted kernel-page during paging initialization");
			}
		});

	return free_page;
}

static const char* pagetag_cloneable_and_global(uint64_t entry)
{
	if (entry & PDE64_CLONEABLE) {
		if (entry & PDE64_G) {
			return "CLONEABLE+GLOBAL";
		} else {
			return "CLONEABLE";
		}
	} else if (entry & PDE64_G) {
		return "GLOBAL";
	} else {
		return "";
	}
}

TINYKVM_COLD()
static const char* leaf_pagetable_bits(uint64_t entry)
{
	if ((entry & (PDE64_ACCESSED | PDE64_DIRTY)) == (PDE64_ACCESSED | PDE64_DIRTY)) {
		return " A+D";
	} else if (entry & PDE64_ACCESSED) {
		return " A";
	} else if (entry & PDE64_DIRTY) {
		return " D";
	} else {
		return "";
	}
}
TINYKVM_COLD()
static void print_pte(const vMemory& memory, uint64_t pte_addr, uint64_t pte_mem)
{
	uint64_t* pt = memory.page_at(pte_mem);
	for (uint64_t i = 0; i < 512; i++) {
		if (pt[i] & PDE64_PRESENT) {
			printf("    |-- 4k PT (0x%lX): 0x%lX  W=%lu  E=%d  %s  %s%s\n",
				pte_addr + (i << 12), pt[i] & PDE64_ADDR_MASK,
				pt[i] & PDE64_RW, !(pt[i] & PDE64_NX),
				(pt[i] & PDE64_USER) ? "USER" : "KERNEL",
				pagetag_cloneable_and_global(pt[i]),
				leaf_pagetable_bits(pt[i]));
		}
	}
}
TINYKVM_COLD()
static void print_pd(const vMemory& memory, uint64_t pd_addr, uint64_t pd_mem)
{
	uint64_t* pd = memory.page_at(pd_mem);
	for (uint64_t i = 0; i < 512; i++) {
		if (pd[i] & PDE64_PRESENT) {
			uint64_t addr = pd_addr + (i << 21);
			uint64_t mem  = pd[i] & PDE64_ADDR_MASK;
			const bool is_leaf = (pd[i] & PDE64_PS) != 0;
			printf("  |-* 2MB PD (0x%lX): 0x%lX  W=%lu  E=%d  %s  %s%s\n",
				addr, mem,
				pd[i] & PDE64_RW, !(pd[i] & PDE64_NX),
				(pd[i] & PDE64_USER) ? "USER" : "KERNEL",
				pagetag_cloneable_and_global(pd[i]),
				is_leaf ? leaf_pagetable_bits(pd[i]) : "");
			if (!is_leaf) {
				print_pte(memory, addr, mem);
			}
		}
	}
}
TINYKVM_COLD()
static void print_pdpt(const vMemory& memory, uint64_t pdpt_base, uint64_t pdpt_mem)
{
	uint64_t* pdpt = memory.page_at(pdpt_mem);
	for (uint64_t i = 0; i < 512; i++) {
		if (pdpt[i] & PDE64_PRESENT) {
			uint64_t addr = pdpt_base + (i << 30);
			printf("|-* 1GB PDPT (0x%lX): 0x%lX  W=%lu  E=%d  %s  %s\n",
				addr, pdpt[i] & ~0xFFF,
				pdpt[i] & PDE64_RW, !(pdpt[i] & PDE64_NX),
				(pdpt[i] & PDE64_USER) ? "USER" : "KERNEL",
				pagetag_cloneable_and_global(pdpt[i]));
			print_pd(memory, addr, pdpt[i] & ~0xFFF);
		}
	}
}

TINYKVM_COLD()
void print_pagetables(const vMemory& memory)
{
	uint64_t* pml4 = memory.page_at(memory.page_tables);
	for (size_t i = 0; i < 512; i++) {
		if (pml4[i] & PDE64_PRESENT) {
			printf("* 512GB PML4: W=%lu  E=%d  %s  %s\n",
				pml4[i] & PDE64_RW, !(pml4[i] & PDE64_NX),
				(pml4[i] & PDE64_USER) ? "USER" : "KERNEL",
				pagetag_cloneable_and_global(pml4[i]));
			print_pdpt(memory, i << 39, pml4[i] & ~(uint64_t) 0xFFF);
		}
	}
}

void foreach_page(vMemory& memory, foreach_page_t callback, bool skip_oob_addresses)
{
	auto* pml4 = memory.page_at(memory.page_tables);
	for (size_t i = 0; i < 512; i++)
	{
		if (pml4[i] & PDE64_PRESENT) {
			const auto [pdpt_base, pdpt_mem, pdpt_size] = pdpt_from_index(i, pml4);
			callback(pdpt_base, pml4[i], pdpt_size);

			// Skip out-of-bounds memory, as it may not be relevant for foreach
			if (skip_oob_addresses && pdpt_mem >= memory.physbase + memory.size)
				continue;

			auto* pdpt = memory.page_at(pdpt_mem);
			for (uint64_t j = 0; j < 512; j++)
			{
				if (pdpt[j] & PDE64_PRESENT) {
					const auto [pd_base, pd_mem, pd_size] = pd_from_index(j, pdpt_base, pdpt);
					callback(pd_base, pdpt[j], pd_size);

					if (pdpt[j] & PDE64_PS) { // 1GB page
						continue;
					}

					// Skip out-of-bounds memory, as it may not be relevant for foreach
					// (also, it is impossible to read page-memory out of bounds...)
					if (skip_oob_addresses && pd_mem >= memory.physbase + memory.size)
						continue;

					auto* pd = memory.page_at(pd_mem);
					for (uint64_t k = 0; k < 512; k++)
					{
						if (pd[k] & PDE64_PRESENT) {
							const auto [pt_base, pt_mem, pt_size] = pt_from_index(k, pd_base, pd);
							const bool is_2mb_page = (pd[k] & PDE64_PS) != 0;
							callback(pt_base, pd[k], pt_size);
							if (!is_2mb_page) {
								auto* pt = memory.page_at(pt_mem);
								for (uint64_t e = 0; e < 512; e++) {
									const auto [pte_base, pte_mem, pte_size] = pte_from_index(e, pt_base, pt);
									if (pt[e] & PDE64_PRESENT) { // 4KB page
										callback(pte_base, pt[e], pte_size);
									}
								} // e
							} // 2MB page
						}
					} // k
				}
			} // j
		}
	} // i
} // foreach_page
void foreach_page(const vMemory& mem, foreach_page_t callback, bool skip_oob_addresses)
{
	foreach_page(const_cast<vMemory&>(mem), std::move(callback), skip_oob_addresses);
}

void foreach_page_makecow(vMemory& mem, uint64_t kernel_end,
	uint64_t shared_memory_boundary, bool split_accessed_hugepages)
{
	if (UNLIKELY(shared_memory_boundary < kernel_end)) {
		memory_exception("Shared memory boundary was illegal (zero)", shared_memory_boundary, 0u);
	}
	foreach_page(mem,
	[=, m = &mem] (uint64_t addr, uint64_t& entry, size_t size) {
		if (addr < shared_memory_boundary) {
			const uint64_t flags = (PDE64_PRESENT | PDE64_RW);
			if ((entry & flags) == flags) {
				entry &= ~PDE64_RW;
				entry |= PDE64_CLONEABLE | PDE64_G; // Global bit for read-only pages
			}
			if ((entry & PDE64_ACCESSED) != 0)
			{
				// Since this page has been accessed, check if it's a 2MB leaf page
				// and if it is, split it into 4k pages with the ACCESS bit removed.
				if (size == (1ULL << 21) && (entry & PDE64_PS) != 0 && split_accessed_hugepages)
				{
					// Split 2MB page into 4k pages
					const uint64_t pd_base = entry & PDE64_ADDR_MASK;
					// Allocate new page for page table
					const auto new_page = m->allocate_unmapped_kernelpage();
					if (new_page.addr != 0) {
						// Set default attributes + new page table
						const uint64_t pd_entry_flags = entry & ~(PDE64_ADDR_MASK | PDE64_PS | PDE64_ACCESSED);
						entry = pd_entry_flags | new_page.addr;
						// Fill new page with default attributes
						uint64_t* pagetable = new_page.pmem;
						for (uint64_t i = 0; i < 512; i++) {
							// Set writable 4k attributes
							uint64_t addr4k = pd_base | (i << 12);
							pagetable[i] = pd_entry_flags | addr4k;
						}
						return;
					} // new_page.addr
					// Failing to allocate, so we simply won't
					// split the page, but this may lead to extra
					// memory usage if forks don't need the whole
					// 2MB page.
				}
			}
		}
		// Clear accessed bit for *all* pages
		// Doing this makes it possible to send a dummy request to estimate which
		// pages are needed after a fork, for use with MAP_POPULATE-like optimizations.
		entry &= ~PDE64_ACCESSED;
	});
}
std::vector<std::pair<uint64_t, uint64_t>> get_accessed_pages(const vMemory& memory)
{
	std::vector<std::pair<uint64_t, uint64_t>> accessed_pages;
	foreach_page(memory,
	[&accessed_pages] (uint64_t addr, uint64_t& entry, size_t size) {
		// Leaf pages are either huge pages with the PS bit set or of PAGE_SIZE.
		if ((entry & (PDE64_ACCESSED | PDE64_PRESENT)) == (PDE64_ACCESSED | PDE64_PRESENT) &&
				((entry & PDE64_PS) || (size == PAGE_SIZE))) {
			accessed_pages.push_back({addr & PDE64_ADDR_MASK, size});
		}
	}, false);
	return accessed_pages;
}

void page_at(vMemory& memory, uint64_t addr, foreach_page_t callback, bool ignore_missing)
{
	auto* pml4 = memory.page_at(memory.page_tables);
	const uint64_t i = (addr >> 39) & 511;
	if (pml4[i] & PDE64_PRESENT) {
		const auto [pdpt_base, pdpt_mem, pdpt_size] = pdpt_from_index(i, pml4);
		auto* pdpt = memory.page_at(pdpt_mem);
		const uint64_t j = index_from_pdpt_entry(addr);
		if (pdpt[j] & PDE64_PRESENT) {
			const auto [pd_base, pd_mem, pd_size] = pd_from_index(j, pdpt_base, pdpt);
			auto* pd = memory.page_at(pd_mem);
			const uint64_t k = index_from_pd_entry(addr);
			if (pd[k] & PDE64_PRESENT) {
				const auto [pt_base, pt_mem, pt_size] = pt_from_index(k, pd_base, pd);
				if (pd[k] & PDE64_PS) { // 2MB page
					callback(pt_mem, pd[k], pt_size);
					return;
				} else {
					auto* pt = memory.page_at(pt_mem);
					const uint64_t e = index_from_pt_entry(addr);
					if (pt[e] & PDE64_PRESENT) { // 4KB page
						const auto [pte_base, pte_mem, pte_size] = pte_from_index(e, pt_base, pt);
						callback(pte_base, pt[e], pte_size);
						return;
					} // pt
					if (ignore_missing)
						return;
					memory_exception("page_at: pt entry not present", addr, PDE64_PTE_SIZE);
				}
			} // pd
			if (ignore_missing)
				return;
			memory_exception("page_at: page table not present", addr, PDE64_PT_SIZE);
		} // pdpt
		if (ignore_missing)
			return;
		memory_exception("page_at: page directory not present", addr, PDE64_PD_SIZE);
	} // pml4
	if (ignore_missing)
		return;
	memory_exception("page_at: pml4 entry not present", addr, PDE64_PDPT_SIZE);
}

inline bool is_copy_on_write(uint64_t entry) {
	/* Copy this page if it's marked cloneable
	   and it's not already writable. */
	return (entry & (PDE64_CLONEABLE | PDE64_RW)) == PDE64_CLONEABLE;
}
inline bool is_copy_on_modify(uint64_t entry) {
	/* Copy this page if it's marked cloneable
	   and we are going to change this page right now. */
	return (entry & PDE64_CLONEABLE) == PDE64_CLONEABLE;
}

static void unlock_identity_mapped_entry(uint64_t& entry) {
	/* Make page directly writable */
	entry &= ~(PDE64_CLONEABLE | PDE64_G);
	entry |= PDE64_RW | PDE64_PRESENT;
}
static void clone_and_update_entry(vMemory& memory, uint64_t& entry, uint64_t*& data, uint64_t flags) {
	/* Allocate new page, pass old vaddr to memory banks */
	auto page = memory.new_page();
	assert((page.addr & 0x8000000000000FFF) == 0x0);
	/* Copy all entries from old page */
	tinykvm::page_duplicate(page.pmem, data);
	/* Set new entry, copy flags and set as cloned */
	entry = page.addr | (entry & PDE64_CLONED_MASK) | flags;
	data = page.pmem;
}
static void zero_and_update_entry(vMemory& memory, uint64_t& entry, uint64_t*& data, uint64_t flags) {
	/* Allocate new page, pass old vaddr to memory banks */
	auto page = memory.new_page();
	assert((page.addr & 0x8000000000000FFF) == 0x0);
	/* Zero all entries from old page, if it's dirty */
	if (page.dirty) {
		tinykvm::page_memzero(page.pmem);
	}
	/* Set new entry, copy flags and set as cloned */
	entry = page.addr | (entry & PDE64_CLONED_MASK) | flags;
	data = page.pmem;
}
static void unsafe_update_entry(vMemory& memory, uint64_t& entry, uint64_t*& data, uint64_t flags) {
	/* Allocate new page, pass old vaddr to memory banks */
	auto page = memory.new_page();
	assert((page.addr & 0x8000000000000FFF) == 0x0);
	/* Set new entry, copy flags and set as cloned */
	entry = page.addr | (entry & PDE64_CLONED_MASK) | flags;
	data = page.pmem;
}

WritablePage writable_page_at(vMemory& memory, uint64_t addr, uint64_t verify_flags, WritablePageOptions options)
{
	CLPRINT("Creating a writable page for 0x%lX\n", addr);
	auto* pml4 = memory.page_at(memory.page_tables);
	const uint64_t i = (addr >> 39) & 511;
	if (pml4[i] & PDE64_PRESENT) {
		const auto [pdpt_base, pdpt_mem, pdpt_size] = pdpt_from_index(i, pml4);
		auto* pdpt = memory.page_at(pdpt_mem);
		/* Make copy of page if needed */
		if (is_copy_on_write(pml4[i])) {
			if (memory.main_memory_writes) {
				unlock_identity_mapped_entry(pml4[i]);
			} else {
				clone_and_update_entry(memory, pml4[i], pdpt, PDE64_RW);
				CLPRINT("-> Cloning a PML4 entry %lu: 0x%lX at %p\n", i, pml4[i], pdpt);
			}
			assert(!is_copy_on_write(pml4[i]) && (pml4[i] & PDE64_PRESENT));
		}
		const uint64_t j = index_from_pdpt_entry(addr);
		if (pdpt[j] & PDE64_PRESENT) {
			const auto [pd_base, pd_mem, pd_size] = pd_from_index(j, pdpt_base, pdpt);
			auto* pd = memory.page_at(pd_mem);
			/* Make copy of page if needed */
			if (is_copy_on_write(pdpt[j])) {
				if (memory.main_memory_writes) {
					unlock_identity_mapped_entry(pdpt[j]);
				} else {
					clone_and_update_entry(memory, pdpt[j], pd, PDE64_RW);
					memory.remote_must_update_gigapages = true;
					CLPRINT("-> Cloning a PDPT entry: 0x%lX\n", pdpt[j]);
				}
			}
			const uint64_t k = index_from_pd_entry(addr);
			if (pd[k] & (PDE64_PRESENT | PDE64_CLONEABLE)) {
				const auto [pt_base, pt_mem, pt_size] = pt_from_index(k, pd_base, pd);
				uint64_t* pt;
				if (pd[k] & PDE64_PRESENT) { // A regular copy-on-write entry
					pt = memory.page_at(pd[k] & ~(uint64_t)0x8000000000000FFF);
				} else { // An unpresent copy-on-write entry
					// Reconstruct the page table address
					const uint64_t pd_addr = pd_base + (k << 21);
					pt = memory.page_at(pd_addr);
				}
				/* Make copy of page if needed (not likely) */
				if (UNLIKELY(is_copy_on_write(pd[k]))) {
					/* Copy-on-write 2MB page */

					/* NOTE: Make sure we are re-reading pd[k] */
					if (memory.main_memory_writes) {
						unlock_identity_mapped_entry(pd[k]);
						if (pd[k] & PDE64_PS) {
							memory.increment_unlocked_pages(512);
						}
						goto entry_is_no_longer_copy_on_write;
					} else if (memory.split_hugepages && (pd[k] & PDE64_PS)) { // 2MB page
						CLPRINT("-> Splitting a 2MB page, addr=0x%lX rw=%lu cloneable=%lu\n",
							addr, pd[k] & PDE64_RW, pd[k] & PDE64_CLONEABLE);
						/* Remove PS flag */
						pd[k] &= ~(uint64_t)PDE64_PS;
						/* Copy flags from 2MB page, except read-write */
						uint64_t flags = pd[k] & PDE64_PD_SPLIT_MASK;
						uint64_t branch_flags = flags | PDE64_CLONEABLE | PDE64_G | PDE64_PRESENT;
						/* Allocate pagetable page and fill 4k entries.
						NOTE: new_page() makes page not a candidate for
						sequentialization for eg. vmcommit() later on. */
						auto page = memory.new_page();
						const uint64_t base_address = pd[k] & PDE64_ADDR_MASK;
						for (size_t e = 0; e < 512; e++) {
							page.pmem[e] = base_address | (e << 12) | branch_flags;
						}
						/* Update 2MB entry, add read-write */
						pd[k] = page.addr | flags | PDE64_RW | PDE64_PRESENT;
						pt = page.pmem;
					}
					else if ((pd[k] & PDE64_PS)) {
						CLPRINT("Duplicating 2MB page, addr=0x%lX rw=%lu cloneable=%lu\n",
							addr, pd[k] & PDE64_RW, pd[k] & PDE64_CLONEABLE);

						const bool dirty = pd[k] & PDE64_DIRTY;

						/* Get the physical page at pt_base. */
						auto* data = memory.page_at(pt_mem);

						/* Set the new page address and bits, adding RW and removing DIRTY. */
						auto page = memory.new_hugepage();
						uint64_t flags = (pd[k] & PDE64_PD_SPLIT_MASK) & ~PDE64_DIRTY;
						pd[k] = page.addr | flags | PDE64_RW | PDE64_PRESENT;

						/* Verify flags after CLONEABLE -> RW, in order to match RW. */
						if (UNLIKELY((pd[k] & verify_flags) != verify_flags)) {
							memory_exception("page_at: pt entry not user writable", addr, pd[k]);
						}

						/* We deliberately use DIRTY bit to know when to duplicate memory. */
						if (dirty) {
							/* The source page needs to be duplicated, always duplicate */
							//std::memcpy(page.pmem, data, 2ULL << 20);
							for (size_t e = 0; e < 512; e++) {
								tinykvm::page_duplicate(page.pmem + e * 512, data + e * 512);
							}
						} else if (page.dirty) {
							/* The new page needs to be zeroed, because it's dirty */
							//std::memset(page.pmem, 0, 2ULL << 20); /* 2MB */
							for (size_t e = 0; e < 512; e++) {
								tinykvm::page_memzero(page.pmem + e * 512);
							}
						}

						/* Return 4k page offset to new duplicated page. */
						const uint64_t e = index_from_pt_entry(addr);
						if (pd[k] & PDE64_USER)
							memory.record_cow_leaf_user_page(addr);
						return WritablePage {
							.page = (char *)page.pmem + e * PAGE_SIZE,
							.entry = pd[k],
							.size = PDE64_PT_SIZE,
						};
					}

					clone_and_update_entry(memory, pd[k], pt, PDE64_RW | PDE64_PRESENT);
					CLPRINT("-> Cloning a PD entry: 0x%lX\n", pd[k]);
				}

entry_is_no_longer_copy_on_write:
				if (pd[k] & PDE64_PS) { // 2MB page
					if (UNLIKELY((pd[k] & verify_flags) != verify_flags)) {
						memory_exception("page_at: pt entry not user writable", addr, pd[k]);
					}

					const uint64_t e = index_from_pt_entry(addr);
					auto* data = memory.page_at(pt_mem);
					WritablePage result{
						.page = (char *)data + e * PAGE_SIZE,
						.entry = pd[k],
						.size = PDE64_PT_SIZE,
					};
					return result;
				}

				const uint64_t e = index_from_pt_entry(addr);
				if (pt[e] & (PDE64_PRESENT | PDE64_CLONEABLE)) { // 4KB page
					const auto [pte_base, pte_mem, pte_size] = pte_from_index(e, pt_base, pt);
					uint64_t* data;
					if (pt[e] & PDE64_PRESENT) { // A regular copy-on-write entry
						data = memory.page_at(pt[e] & ~(uint64_t)0x8000000000000FFF);
					} else { // An unpresent copy-on-write entry
						// Reconstruct the address from the page table indices
						const uint64_t pt_addr = pd_base + (k << 21) + (e << 12);
						data = memory.page_at(pt_addr);
					}
					if (is_copy_on_write(pt[e])) {
						if (memory.is_forkable_master() && memory.main_memory_writes) {
							unlock_identity_mapped_entry(pt[e]);
							memory.increment_unlocked_pages(1);
						} else if (UNLIKELY(options.allow_dirty)) {
							unsafe_update_entry(memory, pt[e], data, PDE64_RW | PDE64_PRESENT);
						} else if (options.zeroes || (pt[e] & PDE64_DIRTY) == 0x0) {
							zero_and_update_entry(memory, pt[e], data, PDE64_RW | PDE64_PRESENT);
						} else if (pt[e] & PDE64_PRESENT) {
							clone_and_update_entry(memory, pt[e], data, PDE64_RW | PDE64_PRESENT);
						} else {
							// This entry already points to a new page, but we still need to copy
							// the original page to the new one.
							page_duplicate(memory.page_at(pt[e] & PDE64_ADDR_MASK), data);
							pt[e] &= ~PDE64_CLONEABLE;
							pt[e] |= PDE64_RW | PDE64_PRESENT;
						}
						if (pt[e] & PDE64_USER)
							memory.record_cow_leaf_user_page(addr);
						CLPRINT("-> Cloning a PT entry: 0x%lX\n", pt[e]);
					}
					if ((pt[e] & verify_flags) == verify_flags) {
						CLPRINT("-> Returning data: %p\n", data);
						return WritablePage {
							.page = (char *)data,
							.entry = pt[e],
							.size = PAGE_SIZE,
						};
					} else {
						memory_exception("page_at: pt entry not user writable", addr, pt[e]);
					}
				} // pt
				memory_exception("page_at: pt entry not present", addr, PDE64_PTE_SIZE);
			} // pd
			memory_exception("page_at: page table not present", addr, PDE64_PT_SIZE);
		} // pdpt
		memory_exception("page_at: page directory not present", addr, PDE64_PD_SIZE);
	} // pml4
	memory_exception("page_at: pml4 entry not present", addr, PDE64_PDPT_SIZE);
}

char * readable_page_at(const vMemory& memory, uint64_t addr, uint64_t flags)
{
	CLPRINT("Resolving a readable page for 0x%lX\n", addr);
	auto* pml4 = memory.page_at(memory.page_tables);
	const uint64_t i = (addr >> 39) & 511;
	if (is_flagged_page(flags, pml4[i])) {
		const auto [pdpt_base, pdpt_mem, pdpt_size] = pdpt_from_index(i, pml4);
		auto* pdpt = memory.page_at(pdpt_mem);
		const uint64_t j = index_from_pdpt_entry(addr);
		if (is_flagged_page(flags, pdpt[j])) {
			const auto [pd_base, pd_mem, pd_size] = pd_from_index(j, pdpt_base, pdpt);
			auto* pd = memory.page_at(pd_mem);
			const uint64_t k = index_from_pd_entry(addr);
			if (is_flagged_page(flags, pd[k])) {
				const auto [pt_base, pt_mem, pt_size] = pt_from_index(k, pd_base, pd);
				const uint64_t e = index_from_pt_entry(addr);
				auto* pt = memory.page_at(pt_mem);

				/* Could be a 2MB page */
				if (UNLIKELY(pd[k] & PDE64_PS)) {
					/* Return the 4k segment inside the 2MB page */
					auto* data = (char *)pt + e * PAGE_SIZE;
					CLPRINT("-> Returning 2MB data: %p\n", data);
					return data;
				}

				if (is_flagged_page(flags, pt[e])) { // 4KB page
					const auto [pte_base, pte_mem, pte_size] = pte_from_index(e, pt_base, pt);
					auto* data = memory.page_at(pte_mem);
					CLPRINT("-> Returning 4k data: %p\n", data);
					return (char *)data;
				} // pt
				memory_exception("readable_page_at: pt entry not readable", addr, PDE64_PTE_SIZE);
			} // pd
			memory_exception("readable_page_at: page table not readable", addr, PDE64_PT_SIZE);
		} // pdpt
		memory_exception("readable_page_at: page directory not readable", addr, PDE64_PD_SIZE);
	} // pml4
	memory_exception("readable_page_at: pml4 entry not readable", addr, PDE64_PDPT_SIZE);
}

void memory_exception(const char* msg, uint64_t addr, uint64_t sz)
{
	throw MemoryException(msg, addr, sz);
}

void WritablePage::set_dirty()
{
	entry |= PDE64_DIRTY;
}
void WritablePage::set_protections(int prot)
{
	return;
	if (prot & 1) { // PROT_READ
		entry |= PDE64_PRESENT; // Readable
	}
	else {
		entry &= ~PDE64_PRESENT; // Clear readable
	}
	if (prot & 2) { // PROT_WRITE
		entry |= PDE64_RW; // Writable
	}
	else {
		entry &= ~PDE64_RW; // Clear writable
	}
	if (prot & 4) {
		entry &= ~PDE64_NX; // Clear NX
	}
	else {
		entry |= PDE64_NX; // Set NX
	}
}

size_t paging_merge_leaf_pages_into_hugepages(vMemory& memory, bool merge_if_dirty)
{
	unsigned merged_pages = 0;
	// Try to merge contiguous 4k pages with the same permissions,
	// ignoring accessed/dirty bits, into 2MB pages. We will not
	// try to optimize the page tables, rather just turn 2MB entry
	// pages directly into leaf 2MB pages.
	auto* pml4 = memory.page_at(memory.page_tables);
	for (size_t i = 0; i < 4; i++) { // 512GB entries
		if (pml4[i] & PDE64_PRESENT) {
			const auto [pdpt_base, pdpt_mem, pdpt_size] = pdpt_from_index(i, pml4);
			auto* pdpt = memory.page_at(pdpt_mem);
			for (uint64_t j = 0; j < 512; j++) { // 1GB entries
				if (pdpt[j] & PDE64_PRESENT) {
					const auto [pd_base, pd_mem, pd_size] = pd_from_index(j, pdpt_base, pdpt);
					auto* pd = memory.page_at(pd_mem);
					for (uint64_t k = 0; k < 512; k++) { // 2MB entries
						if (pd[k] & PDE64_PRESENT) {
							// Only consider page tables
							if ((pd[k] & PDE64_PS) != 0)
								continue;
							const auto [pt_base, pt_mem, pt_size] = pt_from_index(k, pd_base, pd);
							auto* pt = memory.page_at(pt_mem);
							// Check if we can merge 512 entries
							bool can_merge = true;
							bool any_dirty = (pt[0] & PDE64_DIRTY) != 0;
							bool all_dirty = (pt[0] & PDE64_DIRTY) != 0;
							static constexpr uint64_t MERGE_MASK =
								PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_NX | PDE64_CLONEABLE | PDE64_G;
							const uint64_t first_entry = pt[0] & MERGE_MASK;
							const uint64_t first_addr = pt[0] & PDE64_ADDR_MASK;
							// 2MB leaf page must be 2MB-aligned
							if ((first_addr & 0x1FFFFF) != 0) {
								continue;
							}
							// All entries must be present and have the same flags
							// and be contiguous in physical memory
							uint64_t expected_addr = first_addr;
							for (size_t e = 1; e < 512; e++) {
								if ((pt[e] & MERGE_MASK) != first_entry) {
									can_merge = false;
									break;
								}
								expected_addr += 0x1000;
								if ((pt[e] & PDE64_ADDR_MASK) != expected_addr) {
									can_merge = false;
									break;
								}
								if (pt[e] & PDE64_DIRTY) {
									any_dirty = true;
								}
								else {
									all_dirty = false;
								}
							}
							// Perform merge if possible:
							// - either all pages are clean
							// - or merge_if_dirty is set (and zero or more pages are dirty)
							// - or all pages are dirty
							if (can_merge && (merge_if_dirty || !any_dirty || all_dirty)) {
								// Merge into 2MB page with same flags
								pd[k] = first_addr | first_entry | PDE64_PS | PDE64_PRESENT;
								if (any_dirty) {
									pd[k] |= PDE64_DIRTY;
								}
								//printf("Entry: PDPT[%lu] PD[%lu] merged 512 pages into 2MB page 0x%lX with flags 0x%lX\n",
								//	j, k, pd[k] & PDE64_ADDR_MASK, pd[k] & ~PDE64_ADDR_MASK);
								merged_pages += 512;
							}
						} // pd present
					} // pd[k]
				} // pdpt present
			} // pdpt[j]
		} // pml4 present
	} // pml4[i]
	return merged_pages;
} // paging_merge_leaf_pages_into_hugepages()

} // tinykvm
