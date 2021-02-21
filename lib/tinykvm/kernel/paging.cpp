#include "paging.hpp"

#include "amd64.hpp"
#include "../util/elf.h"
#include <stdexcept>

namespace tinykvm {

void setup_amd64_paging(vMemory& memory,
	uint64_t pagetable_base, uint64_t except_asm_addr, std::string_view binary)
{
	// guest physical
	const uint64_t pml4_addr = pagetable_base;
	const uint64_t pdpt_addr = pml4_addr + 0x1000;
	const uint64_t pd_addr   = pml4_addr + 0x2000;
	const uint64_t mmio_addr = pml4_addr + 0x4000;
	const uint64_t low1_addr = pml4_addr + 0x5000;
	// next free page for ELF loader
	uint64_t free_page = pml4_addr + 0x6000;
	// userspace
	char* pagetable = memory.at(pagetable_base);
	auto* pml4 = (uint64_t*) (pagetable + 0x0);
	auto* pdpt = (uint64_t*) (pagetable + 0x1000);
	auto* pd   = (uint64_t*) (pagetable + 0x2000);
	auto* mmio = (uint64_t*) (pagetable + 0x4000);
	auto* lowpage = (uint64_t*) (pagetable + 0x5000);

	pml4[0] = PDE64_PRESENT | PDE64_USER | PDE64_RW | pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_USER | PDE64_RW | pd_addr;
	pdpt[3] = PDE64_PRESENT | PDE64_USER | PDE64_RW | mmio_addr;
	pd[0] = PDE64_PRESENT | PDE64_USER | PDE64_RW | low1_addr;

	lowpage[0] = 0; /* Null-page at 0x0 */
	/* Kernel area < 1MB */
	for (unsigned i = 1; i < 256; i++) {
		lowpage[i] = PDE64_PRESENT | PDE64_RW | PDE64_NX | (i << 12);
	}
	/* Exception handlers */
	lowpage[except_asm_addr >> 12] = PDE64_PRESENT | PDE64_USER | except_asm_addr;
	/* Stack area 1MB -> 2MB */
	for (unsigned i = 256; i < 512; i++) {
		lowpage[i] = PDE64_PRESENT | PDE64_USER | PDE64_RW | PDE64_NX | (i << 12);
	}

	/* Initial userspace area */
	for (unsigned i = 1; i < 512; i++) {
		pd[i] = PDE64_PRESENT | PDE64_PS | PDE64_USER | PDE64_RW | (i << 21);
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
			auto end  = hdr->p_vaddr + len;
			for (size_t addr = base; addr < end; addr += 0x1000)
			{
				// Branch 2MB page
				auto pdidx = addr >> 21;
				if (pd[pdidx] & PDE64_PS) {
					// Set default attributes + free PTE page
					pd[pdidx] = PDE64_PRESENT | PDE64_USER | PDE64_RW | free_page;
					free_page += 0x1000;
				}
				// Get the pagetable array (NB: mask out NX)
				auto ptaddr = pd[pdidx] & ~0x8000000000000FFF;
				auto* pagetable = (uint64_t*) memory.at(ptaddr);
				// Set 4k attributes
				auto entry = (addr >> 12) & 511;
				auto& ptentry = pagetable[entry];
				ptentry = PDE64_PRESENT | PDE64_USER | addr;
				// We would enforce XO here, but no linker script support...
				if (write) ptentry |= PDE64_RW;
				if (!exec) ptentry |= PDE64_NX;
			}
		}
	}

	// MMIO system calls
	mmio[511] = PDE64_PRESENT | PDE64_PS | PDE64_USER | PDE64_RW | PDE64_NX | 0xff000000 | (511 << 21);
}

}
