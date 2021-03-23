#include "paging.hpp"

#include "amd64.hpp"
#include "vdso.hpp"
#include "../util/elf.h"
#include <stdexcept>

namespace tinykvm {

uint64_t setup_amd64_paging(vMemory& memory,
	uint64_t pagetable_base, uint64_t except_asm_addr, uint64_t ist_addr, std::string_view binary)
{
	// guest physical
	const uint64_t pml4_addr = pagetable_base;
	const uint64_t pdpt_addr = pml4_addr + 0x1000;
	const uint64_t pd1_addr  = pml4_addr + 0x2000;
	const uint64_t pd2_addr  = pml4_addr + 0x3000;
	const uint64_t mmio_addr = pml4_addr + 0x4000;
	const uint64_t low1_addr = pml4_addr + 0x5000;

	// userspace
	char* pagetable = memory.at(pagetable_base);
	auto* pml4 = (uint64_t*) (pagetable + 0x0);
	auto* pdpt = (uint64_t*) (pagetable + 0x1000);
	auto* pd   = (uint64_t*) (pagetable + 0x2000);
	auto* mmio = (uint64_t*) (pagetable + 0x4000);
	auto* lowpage = (uint64_t*) (pagetable + 0x5000);

	const uint64_t arena_pdpt_addr = pml4_addr + 0x6000;
	const uint64_t arena_pd_addr   = pml4_addr + 0x7000;
	auto* arena_pdpt = (uint64_t*) (pagetable + 0x6000);
	auto* arena_pd   = (uint64_t*) (pagetable + 0x7000);

	const uint64_t vdso_pdpt_addr = pml4_addr + 0x8000;
	const uint64_t vsyscall_pd_addr = pml4_addr + 0x9000;
	const uint64_t vsyscall_pt_addr = pml4_addr + 0xA000;
	auto* vdso_pdpt = (uint64_t*) (pagetable + 0x8000);
	auto* vsyscall_pd = (uint64_t*) (pagetable + 0x9000);
	auto* vsyscall_pt = (uint64_t*) (pagetable + 0xA000);

	// next free page for ELF loader
	uint64_t free_page = pml4_addr + 0xB000;

	pml4[0] = PDE64_PRESENT | PDE64_USER | PDE64_RW | pdpt_addr;
	pml4[1] = PDE64_PRESENT | PDE64_USER | PDE64_RW | arena_pdpt_addr;
	pml4[511] = PDE64_PRESENT | PDE64_USER | vdso_pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_USER | PDE64_RW | pd1_addr;
	pdpt[1] = PDE64_PRESENT | PDE64_USER | PDE64_RW | pd2_addr;
	pdpt[3] = PDE64_PRESENT | PDE64_USER | PDE64_RW | mmio_addr;
	pd[0] = PDE64_PRESENT | PDE64_USER | PDE64_RW | low1_addr;

	lowpage[0] = 0; /* Null-page at 0x0 */
	/* Kernel area < 1MB */
	for (unsigned i = 1; i < 256; i++) {
		lowpage[i] = PDE64_PRESENT | PDE64_RW | PDE64_NX | (i << 12);
	}
	/* Exception handlers */
	lowpage[except_asm_addr >> 12] = PDE64_PRESENT | PDE64_USER | except_asm_addr;
	/* Exception (IST) stack */
	lowpage[ist_addr >> 12] = PDE64_PRESENT | PDE64_USER | PDE64_RW | PDE64_NX | ist_addr;

	/* Stack area 1MB -> 2MB */
	for (unsigned i = 256; i < 512; i++) {
		lowpage[i] = PDE64_PRESENT | PDE64_USER | PDE64_RW | PDE64_NX | (i << 12);
	}
	/* Initial userspace area (no execute) */
	for (unsigned i = 1; i < 1024; i++) {
		pd[i] = PDE64_PRESENT | PDE64_PS | PDE64_USER | PDE64_RW | PDE64_NX | (i << 21);
	}

	arena_pdpt[256] = PDE64_PRESENT | PDE64_USER | PDE64_RW | arena_pd_addr;

	/* Arena memory mapping at 0xC000000000 */
	for (unsigned i = 0; i < 512; i++) {
		uint64_t dst = 0x2800000 + (i << 21);
		arena_pd[i] = PDE64_PRESENT | PDE64_PS | PDE64_USER | PDE64_RW | PDE64_NX | dst;
	}

	/* ELF executable area */
	const auto* elf = (Elf64_Ehdr*) binary.data();
	const auto program_headers = elf->e_phnum;
	const auto* phdr = (Elf64_Phdr*) (binary.data() + elf->e_phoff);

	for (const auto* hdr = phdr; hdr < phdr + program_headers; hdr++)
	{
		if (hdr->p_type == PT_LOAD)
		{
			const auto*  src = binary.data() + hdr->p_offset;
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

	// MMIO system calls
	mmio[511] = PDE64_PRESENT | PDE64_PS | PDE64_USER | PDE64_RW | PDE64_NX | 0xff000000 | (511 << 21);

	// vDSO / vsyscall
	// vsyscall gettimeofday: 0xFFFFFFFFFF600000
	vdso_pdpt[511] = PDE64_PRESENT | PDE64_USER | vsyscall_pd_addr;
	vsyscall_pd[507] = PDE64_PRESENT | PDE64_USER | vsyscall_pt_addr;
	vsyscall_pt[0] = PDE64_PRESENT | PDE64_USER | 0xFFFF600000;

	return free_page;
}

void print_pte(vMemory& memory, uint64_t pte_addr, uint64_t pte_mem)
{
	uint64_t* pt = (uint64_t*) memory.at(pte_mem);
	for (uint64_t i = 0; i < 512; i++) {
		if (pt[i] & PDE64_PRESENT) {
			printf("    |-- 4k PT (0x%lX): 0x%lX  W=%lu  E=%d  %s\n",
				pte_addr + (i << 12), pt[i] & ~0x8000000000000FFF,
				pt[i] & PDE64_RW, !(pt[i] & PDE64_NX),
				(pt[i] & PDE64_USER) ? "USER" : "KERNEL");
		}
	}
}
void print_pd(vMemory& memory, uint64_t pd_addr, uint64_t pd_mem)
{
	uint64_t* pd = (uint64_t*) memory.at(pd_mem);
	for (uint64_t i = 0; i < 512; i++) {
		if (pd[i] & PDE64_PRESENT) {
			uint64_t addr = pd_addr + (i << 21);
			uint64_t mem  = pd[i] & ~0x8000000000000FFF;
			printf("  |-* 2MB PD (0x%lX): 0x%lX  W=%lu  E=%d  %s\n",
				addr, mem,
				pd[i] & PDE64_RW, !(pd[i] & PDE64_NX),
				(pd[i] & PDE64_USER) ? "USER" : "KERNEL");
			if (!(pd[i] & PDE64_PS))
				print_pte(memory, addr, mem);
		}
	}
}
void print_pdpt(vMemory& memory, uint64_t pdpt_base, uint64_t pdpt_mem)
{
	uint64_t* pdpt = (uint64_t*) memory.at(pdpt_mem);
	for (uint64_t i = 0; i < 512; i++) {
		if (pdpt[i] & PDE64_PRESENT) {
			uint64_t addr = pdpt_base + (i << 30);
			printf("|-* 1GB PDPT (0x%lX): 0x%lX\n",
				addr, pdpt[i] & ~0xFFF);
			print_pd(memory, addr, pdpt[i] & ~0xFFF);
		}
	}
}

void print_pagetables(vMemory& memory, uint64_t pagetable_mem)
{
	uint64_t* pml4 = (uint64_t*) memory.at(pagetable_mem);
	for (size_t i = 0; i < 512; i++) {
		if (pml4[i] & PDE64_PRESENT) {
			printf("* 512GB PML4:\n");
			print_pdpt(memory, i << 39, pml4[i] & ~(uint64_t) 0xFFF);
		}
	}
}

}
