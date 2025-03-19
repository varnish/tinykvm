#include "machine.hpp"

#include <cassert>
#include <cstring>
#include <stdexcept>
#ifdef TINYKVM_ARCH_AMD64
#include "amd64/idt.hpp" // interrupt_header()
#endif
#include "util/elf.hpp"

namespace tinykvm {
static constexpr bool VERBOSE_LOADER = false;
static constexpr int MAX_LOADABLE_SEGMENTS = 8;

void Machine::elf_loader(std::string_view binary, const MachineOptions& options)
{
	if (UNLIKELY(binary.size() < sizeof(Elf64_Ehdr))) {
		throw MachineException("ELF binary too short");
	}
	const auto* elf = (Elf64_Ehdr*) binary.data();
	if (UNLIKELY(!validate_header(elf))) {
		throw MachineException("Invalid ELF header! Not a 64-bit program?");
	}
	bool is_dynamic = false;
	if (elf->e_type == ET_DYN) {
		is_dynamic = true;
		this->m_image_base = DYLINK_BASE;
	}
	else if (elf->e_type == ET_EXEC) {
		this->m_image_base = 0x0;
	} else {
		throw MachineException("Invalid ELF type: Not a static or dynamic executable!");
	}

	// enumerate & load loadable segments
	const auto program_headers = elf->e_phnum;
	if (UNLIKELY(program_headers <= 0)) {
		throw MachineException("ELF with no program-headers");
	}
	if (UNLIKELY(program_headers >= 64)) {
		throw MachineException("ELF with too many program-headers");
	}
	if (UNLIKELY(elf->e_phoff + program_headers * sizeof(Elf64_Phdr) > binary.size())) {
		throw MachineException("ELF program-headers are outside the binary");
	}
	if (UNLIKELY(elf->e_phoff + program_headers * sizeof(Elf64_Phdr) < elf->e_phoff)) {
		throw MachineException("ELF program-header location is bogus");
	}
	if (UNLIKELY(elf->e_phoff % 8 != 0)) {
		throw MachineException("ELF program-headers are misaligned");
	}

	/* Any old binary no longer relevant, just set new one. */
	this->m_binary = binary;

	const auto* phdr = (Elf64_Phdr*) (binary.data() + elf->e_phoff);
	const auto program_begin = phdr->p_vaddr;
	this->m_start_address = this->m_image_base + elf->e_entry;
	this->m_stack_address = this->m_image_base + program_begin;
	this->m_heap_address = 0x0;

	int seg = 0;
	for (const auto* hdr = phdr; hdr < phdr + program_headers; hdr++)
	{
		if constexpr (VERBOSE_LOADER) {
			printf("Program header: 0x%lX -> 0x%lX\n",
				hdr->p_vaddr, hdr->p_vaddr + hdr->p_memsz);
		}

		// Detect overlapping segments
		if (hdr->p_type == PT_LOAD) {
			for (const auto* ph = phdr; ph < hdr; ph++) {
				if (ph->p_type == PT_LOAD &&
					ph->p_vaddr < hdr->p_vaddr + hdr->p_filesz &&
					ph->p_vaddr + ph->p_filesz >= hdr->p_vaddr) {
					// Normally we would not care, but no normal ELF
					// has overlapping segments, so treat as bogus.
					throw MachineException("Overlapping ELF segments", hdr->p_vaddr);
				}
			}
		}

		switch (hdr->p_type)
		{
			case PT_LOAD:
				seg++;
				if (seg > MAX_LOADABLE_SEGMENTS)
					throw MachineException("Too many loadable segments");
				// loadable program segments
				this->elf_load_ph(binary, options, hdr);
				break;
			case PT_GNU_STACK:
				//printf("GNU_STACK: 0x%lX\n", hdr->p_vaddr);
				break;
			case PT_GNU_RELRO:
				//throw MachineException(
				//	"Dynamically linked ELF binaries are not supported");
				break;
		}

		uint64_t endm = hdr->p_vaddr + hdr->p_memsz;
		endm += vMemory::PageSize()-1; endm &= ~(vMemory::PageSize()-1);
		if (this->m_heap_address < endm)
			this->m_heap_address = endm;
	}

	/* Make sure mmap starts at a sane offset */
	this->m_heap_address += this->m_image_base;
	this->m_mm = this->mmap_start();

	/* If there is not enough room for stack, move it */
	const uint32_t STACK_SIZE = options.stack_size & ~0xFFFLL;
	if (this->m_stack_address < STACK_SIZE) {
		this->m_stack_address = this->mmap_allocate(STACK_SIZE) + STACK_SIZE;
	}

	/* Dynamic executables require some extra work, like relocation */
	if (is_dynamic) {
		this->dynamic_linking(binary, options);
	}

	if (options.verbose_loader) {
	printf("* Entry is at %p\n", (void*) m_start_address);
	printf("* Stack is at %p\n", (void*) m_stack_address);
	}
}

void Machine::elf_load_ph(std::string_view binary, const MachineOptions& options, const void* vphdr)
{
	const auto* hdr = (const Elf64_Phdr*) vphdr;

	const auto*  src = binary.data() + hdr->p_offset;
	const size_t len = hdr->p_filesz;
	if (binary.size() <= hdr->p_offset ||
		hdr->p_offset + len <= hdr->p_offset)
	{
		if (len == 0) return; /* Let's just pretend empty segments are OK. */
		throw MachineException("Bogus ELF program segment offset", hdr->p_offset);
	}
	if (binary.size() < hdr->p_offset + len) {
		throw MachineException("Not enough room for ELF program segment", len);
	}
	const address_t load_address = this->m_image_base + hdr->p_vaddr;
	if (load_address + len < load_address) {
		throw MachineException("Bogus ELF segment virtual base", hdr->p_vaddr);
	}

	if (options.verbose_loader) {
	printf("* Loading segment of size %zu from %p to virtual %p\n",
			len, src, (void*) load_address);
	}

	if (UNLIKELY(load_address < this->m_image_base)) {
		throw MachineException("Bogus ELF segment virtual base", hdr->p_vaddr);
	}
	if (memory.safely_within(load_address, len)) {
		std::memcpy(memory.at(load_address), src, len);
	} else {
		if (options.verbose_loader) {
			printf("Segment at %p is too large or not safely within physical base at %p. Size: %zu vs %p\n",
				(void*)load_address, (void*)memory.safebase, len, (void*)(memory.physbase + memory.size));
			fflush(stdout);
		}
		throw MachineException("Unsafe PT_LOAD segment or executable too big", load_address);
	}
}

const Elf64_Shdr* section_by_name(std::string_view binary, const char* name)
{
	const auto* ehdr = elf_header(binary);
	const auto* shdr = elf_offset<Elf64_Shdr> (binary, ehdr->e_shoff);
	const auto& shstrtab = shdr[ehdr->e_shstrndx];
	const char* strings = elf_offset<char>(binary, shstrtab.sh_offset);

	for (auto i = 0; i < ehdr->e_shnum; i++)
	{
		const char* shname = &strings[shdr[i].sh_name];
		if (strcmp(shname, name) == 0) {
			return &shdr[i];
		}
	}
	return nullptr;
}
static const Elf64_Sym* elf_sym_index(std::string_view binary, const Elf64_Shdr* shdr, uint32_t symidx)
{
	assert(symidx < shdr->sh_size / sizeof(Elf64_Sym));
	auto* symtab = elf_offset<Elf64_Sym>(binary, shdr->sh_offset);
	return &symtab[symidx];
}
static const Elf64_Sym* resolve_symbol(std::string_view binary, const char* name)
{
	if (UNLIKELY(binary.empty())) return nullptr;
	const auto* sym_hdr = section_by_name(binary, ".symtab");
	if (UNLIKELY(sym_hdr == nullptr)) return nullptr;
	const auto* str_hdr = section_by_name(binary, ".strtab");
	if (UNLIKELY(str_hdr == nullptr)) return nullptr;

	const auto* symtab = elf_sym_index(binary, sym_hdr, 0);
	const size_t symtab_ents = sym_hdr->sh_size / sizeof(Elf64_Sym);
	const char* strtab = elf_offset<char>(binary, str_hdr->sh_offset);

	for (size_t i = 0; i < symtab_ents; i++)
	{
		const char* symname = &strtab[symtab[i].st_name];
		if (strcmp(symname, name) == 0) {
			return &symtab[i];
		}
	}
	return nullptr;
}

uint64_t Machine::address_of(const char* name) const
{
	const auto* sym = resolve_symbol(m_binary, name);
	return (sym) ? this->m_image_base + sym->st_value : 0x0;
}
std::string Machine::resolve(uint64_t rip) const
{
	if (UNLIKELY(m_binary.empty())) return "";
	const auto* sym_hdr = section_by_name(m_binary, ".symtab");
	if (UNLIKELY(sym_hdr == nullptr)) return "";
	const auto* str_hdr = section_by_name(m_binary, ".strtab");
	if (UNLIKELY(str_hdr == nullptr)) return "";

	if (UNLIKELY(rip < this->m_image_base)) return "";
	const address_t relative_rip = rip - this->m_image_base;

	const auto* symtab = elf_sym_index(m_binary, sym_hdr, 0);
	const size_t symtab_ents = sym_hdr->sh_size / sizeof(Elf64_Sym);
	const char* strtab = elf_offset<char>(m_binary, str_hdr->sh_offset);

	for (size_t i = 0; i < symtab_ents; i++)
	{
		/* Only look at functions (for now). Old-style symbols have no FUNC. */
		if (symtab[i].st_info & STT_FUNC) {
			/* Direct matches only (for now) */
			if (relative_rip >= symtab[i].st_value && relative_rip < symtab[i].st_value + symtab[i].st_size)
			{
				const uint64_t offset = relative_rip - symtab[i].st_value;
				char result[2048];
				int len = snprintf(result, sizeof(result),
					"%s + 0x%lX", &strtab[symtab[i].st_name], offset);
				if (len > 0)
					return std::string(result, len);
				else
					return std::string(&strtab[symtab[i].st_name]);
			}
		}
	}
	return "(unknown)";
}

bool Machine::relocate_section(const char* section_name, const char* sym_section)
{
	const auto* rela = section_by_name(m_binary, section_name);
	if (rela == nullptr) {
		printf("No such section: %s\n", section_name);
		return false;
	}
	const auto* dyn_hdr = section_by_name(m_binary, sym_section);
	if (dyn_hdr == nullptr) {
		printf("No such symbol section: %s\n", sym_section);
		return false;
	}
	const size_t rela_ents = rela->sh_size / sizeof(Elf64_Rela);
	if (rela_ents > 524288) {
		throw MachineException("Too many relocations", rela_ents);
	}

	auto* rela_addr = elf_offset_array<Elf64_Rela>(m_binary, rela->sh_offset, rela_ents);
	for (size_t i = 0; i < rela_ents; i++)
	{
		const auto symidx = ELF64_R_SYM(rela_addr[i].r_info);
		const Elf64_Sym* sym = elf_sym_index(m_binary, dyn_hdr, symidx);

		const auto rtype = ELF64_R_TYPE(rela_addr[i].r_info);
		if (rtype != R_X86_64_RELATIVE) {
			if constexpr (VERBOSE_LOADER) {
				printf("Skipping non-relative relocation: %s\n", &m_binary[sym->st_name]);
			}
			continue;
		}

		const address_t addr = this->m_image_base + rela_addr[i].r_offset;
		if (memory.safely_within(addr, sizeof(address_t))) {
			*(address_t*) memory.safely_at(addr, sizeof(address_t)) = this->m_image_base + sym->st_value;
		} else if (false) {
			if constexpr (VERBOSE_LOADER) {
				printf("Relocation failed: %s\n", &m_binary[sym->st_name]);
			}
		}
	}
	return true;
}

void Machine::dynamic_linking(std::string_view binary, const MachineOptions& options)
{
	(void)binary;
	(void)options;
	this->relocate_section(".rela.dyn", ".dynsym");
	//this->relocate_section(".rela.plt", ".dynsym");
}

}
