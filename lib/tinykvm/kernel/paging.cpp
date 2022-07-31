#include "paging.hpp"

#include "amd64.hpp"
#include "memory_layout.hpp"
#include "vdso.hpp"
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
#define PDE64_CLONEABLE  (1ull << 11)

namespace tinykvm {

/* We want to remove the CLONEABLE bit after a page has been duplicated */
static constexpr uint64_t PDE64_ADDR_MASK = ~0x8000000000000FFF;
static constexpr uint64_t PDE64_CLONED_MASK = 0x8000000000000FFF & ~PDE64_CLONEABLE;
static constexpr uint64_t PDE64_PD_SPLIT_MASK = 0x8000000000000FFF & ~(PDE64_RW | PDE64_CLONEABLE);

__attribute__((cold, noinline, noreturn))
static void memory_exception(const char*, uint64_t addr, uint64_t sz);

using ptentry_pair = std::tuple<uint64_t, uint64_t, uint64_t>;
inline ptentry_pair pdpt_from_index(size_t i, uint64_t* pml4) {
	return {i << 39, pml4[i] & ~(uint64_t) 0xFFF, 1ul << 39};
}
inline ptentry_pair pd_from_index(size_t i, uint64_t pdpt_base, uint64_t* pdpt) {
	return {pdpt_base | (i << 30), pdpt[i] & ~0x8000000000000FFF, 1ul << 30};
}
inline ptentry_pair pt_from_index(size_t i, uint64_t pd_base, uint64_t* pd) {
	return {pd_base | (i << 21), pd[i] & ~0x8000000000000FFF, 1ul << 21};
}
inline ptentry_pair pte_from_index(size_t i, uint64_t pt_base, uint64_t* pt) {
	return {pt_base | (i << 12), pt[i] & ~0x8000000000000FFF, 1ul << 12};
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

uint64_t setup_amd64_paging(vMemory& memory, std::string_view binary)
{
	// guest physical
	const uint64_t pml4_addr = memory.page_tables;
	const uint64_t pdpt_addr = pml4_addr + 0x1000;
	const uint64_t pd1_addr  = pml4_addr + 0x2000;
	const uint64_t pd2_addr  = pml4_addr + 0x3000;
	const uint64_t low1_addr = pml4_addr + 0x4000;

	// userspace
	char* pagetable = memory.at(memory.page_tables);
	auto* pml4 = (uint64_t*) (pagetable + 0x0);
	auto* pdpt = (uint64_t*) (pagetable + 0x1000);
	auto* pd   = (uint64_t*) (pagetable + 0x2000);
	auto* lowpage = (uint64_t*) (pagetable + 0x4000);

	const uint64_t vdso_pdpt_addr = pml4_addr + 0x5000;
	const uint64_t vsyscall_pd_addr = pml4_addr + 0x6000;
	const uint64_t vsyscall_pt_addr = pml4_addr + 0x7000;
	auto* vdso_pdpt = (uint64_t*) (pagetable + 0x5000);
	auto* vsyscall_pd = (uint64_t*) (pagetable + 0x6000);
	auto* vsyscall_pt = (uint64_t*) (pagetable + 0x7000);

	// next free page for ELF loader
	uint64_t free_page = pml4_addr + 0x8000;

	pml4[0] = PDE64_PRESENT | PDE64_USER | PDE64_RW | pdpt_addr;
	pml4[511] = PDE64_PRESENT | PDE64_USER | vdso_pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_USER | PDE64_RW | pd1_addr;
	pdpt[1] = PDE64_PRESENT | PDE64_USER | PDE64_RW | pd2_addr;

	pd[0] = PDE64_PRESENT | PDE64_USER | PDE64_RW | low1_addr;

	lowpage[0] = 0; /* Null-page at 0x0 */
	/* GDT, IDT and TSS */
	lowpage[1] = PDE64_PRESENT | PDE64_NX | (1 << 12);
	lowpage[6] = PDE64_PRESENT | PDE64_NX | (6 << 12);
	lowpage[7] = PDE64_PRESENT | PDE64_NX | (7 << 12);

	/* Kernel code: Exceptions, system calls */
	const uint64_t except_page = INTR_ASM_ADDR >> 12;
	lowpage[except_page] = PDE64_PRESENT | INTR_ASM_ADDR;

	/* Exception (IST) stack */
	const uint64_t ist_page = IST_ADDR >> 12;
	lowpage[ist_page+0] = PDE64_PRESENT | PDE64_RW | PDE64_NX | IST_ADDR;
	lowpage[ist_page+1] = PDE64_PRESENT | PDE64_RW | PDE64_NX | IST2_ADDR;

	/* Usercode page: Entry, exit */
	const uint64_t user_page = USER_ASM_ADDR >> 12;
	lowpage[user_page] = PDE64_PRESENT | PDE64_USER | USER_ASM_ADDR;

	/* Initial userspace area (no execute) */
	pd[1] = PDE64_PRESENT | PDE64_USER | PDE64_RW | free_page;
	{
		/* Spend one page pre-splitting the (likely) stack area */
		auto* pte = (uint64_t*) memory.at(free_page);
		// Set writable 4k attributes
		for (uint64_t i = 0; i < 512; i++) {
			uint64_t addr4k = (1ul << 21) | (i << 12);
			pte[i] = PDE64_PRESENT | PDE64_USER | PDE64_RW | PDE64_NX | addr4k;
		}
		free_page += 0x1000;
	}
	for (unsigned i = 2; i < 1024; i++) {
		pd[i] = PDE64_PRESENT | PDE64_PS | PDE64_USER | PDE64_RW | PDE64_NX | (i << 21);
	}

	/* ELF executable area */
	const auto* elf = (Elf64_Ehdr*) binary.data();
	const auto program_headers = elf->e_phnum;
	const auto* phdr = (Elf64_Phdr*) (binary.data() + elf->e_phoff);

	for (const auto* hdr = phdr; hdr < phdr + program_headers; hdr++)
	{
		if (hdr->p_type == PT_LOAD)
		{
			const size_t len = hdr->p_filesz;
			if (!memory.safely_within(hdr->p_vaddr, len)) {
				throw std::runtime_error("Unsafe PT_LOAD segment or executable too big");
			}
			const bool read  = (hdr->p_flags & PF_R) != 0;
			const bool write = (hdr->p_flags & PF_W) != 0;
			const bool exec  = (hdr->p_flags & PF_X) != 0;

			auto base = hdr->p_vaddr & ~0xFFF;
			auto end  = ((hdr->p_vaddr + len) + 0xFFF) & ~0xFFF;
#if 0
			printf("0x%lX->0x%lX --> 0x%lX:0x%lX\n",
				hdr->p_vaddr, hdr->p_vaddr + len, base, end);
#endif
			for (size_t addr = base; addr < end; addr += 0x1000)
			{
				// Branch 2MB page
				auto pdidx = addr >> 21;
				if (pd[pdidx] & PDE64_PS) {
					// Set default attributes + free PTE page
					pd[pdidx] = PDE64_PRESENT | PDE64_USER | PDE64_RW | free_page;
					// Fill new page with default attributes
					auto* pagetable = (uint64_t*) memory.at(free_page);
					for (uint64_t i = 0; i < 512; i++) {
						// Set writable 4k attributes
						uint64_t addr4k = (pdidx << 21) | (i << 12);
						pagetable[i] =
							PDE64_PRESENT | PDE64_USER | PDE64_RW | PDE64_NX | addr4k;
					}
					free_page += 0x1000;
				}
				// Get the pagetable array (NB: mask out NX)
				auto ptaddr = pd[pdidx] & ~0x8000000000000FFF;
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
				// We would enforce XO here, but no linker script support...
				if (exec)
					ptentry &= ~PDE64_NX;
				else
					ptentry |= PDE64_NX;
				if (!read) ptentry &= ~PDE64_PRESENT;
				if (!write) ptentry &= ~PDE64_RW;
			}
		}
	}

	// vDSO / vsyscall
	// vsyscall gettimeofday: 0xFFFFFFFFFF600000
	vdso_pdpt[511] = PDE64_PRESENT | PDE64_USER | vsyscall_pd_addr;
	vsyscall_pd[507] = PDE64_PRESENT | PDE64_USER | vsyscall_pt_addr;
	vsyscall_pt[0] = PDE64_PRESENT | PDE64_USER | 0x4000;

	/* Kernel area ~64KB */
	const size_t kernel_begin_idx = PT_ADDR >> 12;
	const size_t kernel_end_idx = free_page >> 12;
	for (unsigned i = kernel_begin_idx; i < kernel_end_idx; i++) {
		lowpage[i] = PDE64_PRESENT | PDE64_RW | PDE64_NX;
	}

	/* Stack area ~64KB -> 2MB */
	for (unsigned i = kernel_end_idx; i < 512; i++) {
		lowpage[i] = PDE64_PRESENT | PDE64_USER | PDE64_RW | PDE64_NX | (i << 12);
	}

	return free_page;
}

TINYKVM_COLD()
void print_pte(const vMemory& memory, uint64_t pte_addr, uint64_t pte_mem)
{
	uint64_t* pt = memory.page_at(pte_mem);
	for (uint64_t i = 0; i < 512; i++) {
		if (pt[i] & PDE64_PRESENT) {
			printf("    |-- 4k PT (0x%lX): 0x%lX  W=%lu  E=%d  %s  %s\n",
				pte_addr + (i << 12), pt[i] & ~0x8000000000000FFF,
				pt[i] & PDE64_RW, !(pt[i] & PDE64_NX),
				(pt[i] & PDE64_USER) ? "USER" : "KERNEL",
				(pt[i] & PDE64_CLONEABLE) ? "CLONEABLE" : "");
		}
	}
}
TINYKVM_COLD()
void print_pd(const vMemory& memory, uint64_t pd_addr, uint64_t pd_mem)
{
	uint64_t* pd = memory.page_at(pd_mem);
	for (uint64_t i = 0; i < 512; i++) {
		if (pd[i] & PDE64_PRESENT) {
			uint64_t addr = pd_addr + (i << 21);
			uint64_t mem  = pd[i] & ~0x8000000000000FFF;
			printf("  |-* 2MB PD (0x%lX): 0x%lX  W=%lu  E=%d  %s  %s\n",
				addr, mem,
				pd[i] & PDE64_RW, !(pd[i] & PDE64_NX),
				(pd[i] & PDE64_USER) ? "USER" : "KERNEL",
				(pd[i] & PDE64_CLONEABLE) ? "CLONEABLE" : "");
			if (!(pd[i] & PDE64_PS)) {
				print_pte(memory, addr, mem);
			}
		}
	}
}
TINYKVM_COLD()
void print_pdpt(const vMemory& memory, uint64_t pdpt_base, uint64_t pdpt_mem)
{
	uint64_t* pdpt = memory.page_at(pdpt_mem);
	for (uint64_t i = 0; i < 512; i++) {
		if (pdpt[i] & PDE64_PRESENT) {
			uint64_t addr = pdpt_base + (i << 30);
			printf("|-* 1GB PDPT (0x%lX): 0x%lX  W=%lu  E=%d  %s  %s\n",
				addr, pdpt[i] & ~0xFFF,
				pdpt[i] & PDE64_RW, !(pdpt[i] & PDE64_NX),
				(pdpt[i] & PDE64_USER) ? "USER" : "KERNEL",
				(pdpt[i] & PDE64_CLONEABLE) ? "CLONEABLE" : "");
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
				(pml4[i] & PDE64_CLONEABLE) ? "CLONEABLE" : "");
			print_pdpt(memory, i << 39, pml4[i] & ~(uint64_t) 0xFFF);
		}
	}
}

void foreach_page(vMemory& memory, foreach_page_t callback)
{
	auto* pml4 = memory.page_at(memory.page_tables);
	for (size_t i = 0; i < 512; i++)
	{
		if (pml4[i] & PDE64_PRESENT) {
			const auto [pdpt_base, pdpt_mem, pdpt_size] = pdpt_from_index(i, pml4);
			callback(pdpt_base, pml4[i], pdpt_size);
			auto* pdpt = memory.page_at(pdpt_mem);
			for (uint64_t j = 0; j < 512; j++)
			{
				if (pdpt[j] & PDE64_PRESENT) {
					const auto [pd_base, pd_mem, pd_size] = pd_from_index(j, pdpt_base, pdpt);
					callback(pd_base, pdpt[j], pd_size);
					auto* pd = memory.page_at(pd_mem);
					for (uint64_t k = 0; k < 512; k++)
					{
						if (pd[k] & PDE64_PRESENT) {
							const auto [pt_base, pt_mem, pt_size] = pt_from_index(k, pd_base, pd);
							callback(pt_base, pd[k], pt_size);
							if (!(pd[k] & PDE64_PS)) { // not 2MB page
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
void foreach_page(const vMemory& mem, foreach_page_t callback)
{
	foreach_page(const_cast<vMemory&>(mem), std::move(callback));
}

void foreach_page_makecow(vMemory& mem, uint64_t shared_memory_boundary)
{
	foreach_page(mem,
	[=] (uint64_t addr, uint64_t& entry, size_t /*size*/) {
		if (addr < shared_memory_boundary && addr != 0xffe00000) {
			const uint64_t flags = (PDE64_PRESENT | PDE64_RW);
			if ((entry & flags) == flags) {
				entry &= ~(uint64_t) PDE64_RW;
				entry |= PDE64_CLONEABLE;
			}
		}
	});
}

void page_at(vMemory& memory, uint64_t addr, foreach_page_t callback)
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
					memory_exception("page_at: pt entry not present", addr, PDE64_PTE_SIZE);
				}
			} // pd
			memory_exception("page_at: page table not present", addr, PDE64_PT_SIZE);
		} // pdpt
		memory_exception("page_at: page directory not present", addr, PDE64_PD_SIZE);
	} // pml4
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
	entry &= ~PDE64_CLONEABLE;
	entry |= PDE64_RW;
}
static void clone_and_update_entry(vMemory& memory, uint64_t& entry, uint64_t*& data, uint64_t flags) {
	/* Allocate new page, pass old vaddr to memory banks */
	auto page = memory.new_page(entry & PDE64_ADDR_MASK);
	assert((page.addr & 0x8000000000000FFF) == 0x0);
	/* Copy all entries from old page */
	tinykvm::page_duplicate(page.pmem, data);
	/* Set new entry, copy flags and set as cloned */
	entry = page.addr | (entry & PDE64_CLONED_MASK) | flags;
	data = page.pmem;
}
static void zero_and_update_entry(vMemory& memory, uint64_t& entry, uint64_t*& data, uint64_t flags) {
	/* Allocate new page, pass old vaddr to memory banks */
	auto page = memory.new_page(entry & PDE64_ADDR_MASK);
	assert((page.addr & 0x8000000000000FFF) == 0x0);
	/* Zero all entries from old page */
	tinykvm::page_memzero(page.pmem);
	/* Set new entry, copy flags and set as cloned */
	entry = page.addr | (entry & PDE64_CLONED_MASK) | flags;
	data = page.pmem;
}

char * writable_page_at(vMemory& memory, uint64_t addr, bool write_zeroes)
{
	CLPRINT("Creating a writable page for 0x%lX\n", addr);
	auto* pml4 = memory.page_at(memory.page_tables);
	const uint64_t i = (addr >> 39) & 511;
	if (pml4[i] & PDE64_PRESENT) {
		const auto [pdpt_base, pdpt_mem, pdpt_size] = pdpt_from_index(i, pml4);
		auto* pdpt = memory.page_at(pdpt_mem);
		/* Make copy of page if needed */
		if (is_copy_on_write(pml4[i])) {
			clone_and_update_entry(memory, pml4[i], pdpt, PDE64_RW);
			CLPRINT("-> Cloning a PML4 entry %lu: 0x%lX at %p\n", i, pml4[i], pdpt);
			assert(!is_copy_on_write(pml4[i]) && (pml4[i] & PDE64_PRESENT));
		}
		const uint64_t j = index_from_pdpt_entry(addr);
		if (pdpt[j] & PDE64_PRESENT) {
			const auto [pd_base, pd_mem, pd_size] = pd_from_index(j, pdpt_base, pdpt);
			auto* pd = memory.page_at(pd_mem);
			/* Make copy of page if needed */
			if (is_copy_on_write(pdpt[j])) {
				clone_and_update_entry(memory, pdpt[j], pd, PDE64_RW);
				CLPRINT("-> Cloning a PDPT entry: 0x%lX\n", pdpt[j]);
			}
			const uint64_t k = index_from_pd_entry(addr);
			if (pd[k] & PDE64_PRESENT) {
				const auto [pt_base, pt_mem, pt_size] = pt_from_index(k, pd_base, pd);
				uint64_t* pt = memory.page_at(pd[k] & ~(uint64_t)0x8000000000000FFF);
				/* Make copy of page if needed (not likely) */
				if (UNLIKELY(is_copy_on_write(pd[k]))) {
					clone_and_update_entry(memory, pd[k], pt, PDE64_RW);
					CLPRINT("-> Cloning a PD entry: 0x%lX\n", pd[k]);
				}

				/* NOTE: Make sure we are re-reading pd[k] */
				if (UNLIKELY(pd[k] & PDE64_PS)) { // 2MB page
					CLPRINT("-> Splitting a 2MB PD entry into 4KB pages\n");
					/* Remove PS flag */
					pd[k] &= ~(uint64_t)PDE64_PS;
					/* Copy flags from 2MB page, except read-write */
					uint64_t flags = pd[k] & PDE64_PD_SPLIT_MASK;
					uint64_t branch_flags = flags | PDE64_CLONEABLE;
					/* Allocate pagetable page and fill 4k entries.
					   NOTE: new_page(0x0) makes page not a candidate for
					   sequentialization for eg. vmcommit() later on. */
					auto page = memory.new_page(0x0);
					for (size_t e = 0; e < 512; e++) {
						page.pmem[e] = pt_base | (e << 12) | branch_flags;
					}
					/* Update 2MB entry, add read-write */
					pd[k] = page.addr | flags | PDE64_RW;
					pt = page.pmem;
				}

				const uint64_t e = index_from_pt_entry(addr);
				if (pt[e] & PDE64_PRESENT) { // 4KB page
					const auto [pte_base, pte_mem, pte_size] = pte_from_index(e, pt_base, pt);
					auto* data = memory.page_at(pte_mem);
					if (is_copy_on_write(pt[e])) {
						if (memory.is_forkable_master() && memory.main_memory_writes) {
							unlock_identity_mapped_entry(pt[e]);
						} else if (write_zeroes) {
							zero_and_update_entry(memory, pt[e], data, PDE64_RW);
						} else {
							clone_and_update_entry(memory, pt[e], data, PDE64_RW);
						}
						CLPRINT("-> Cloning a PT entry: 0x%lX\n", pt[e]);
					}
					CLPRINT("-> Returning data: %p\n", data);
					return (char *)data;
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
				memory_exception("readable_userpage_at: pt entry not readable", addr, PDE64_PTE_SIZE);
			} // pd
			memory_exception("readable_userpage_at: page table not readable", addr, PDE64_PT_SIZE);
		} // pdpt
		memory_exception("readable_userpage_at: page directory not readable", addr, PDE64_PD_SIZE);
	} // pml4
	memory_exception("readable_userpage_at: pml4 entry not readable", addr, PDE64_PDPT_SIZE);
}

void memory_exception(const char* msg, uint64_t addr, uint64_t sz)
{
	throw MemoryException(msg, addr, sz);
}

} // tinykvm
