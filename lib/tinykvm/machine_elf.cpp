#include "machine.hpp"

#include <cassert>
#include <cstring>
#include <stdexcept>
#include "kernel/idt.hpp"
#include "util/elf.hpp"

namespace tinykvm {

void Machine::elf_loader(const MachineOptions& options)
{
	if (UNLIKELY(m_binary.size() < sizeof(Elf64_Ehdr))) {
		throw std::runtime_error("ELF binary too short");
	}
	const auto* elf = (Elf64_Ehdr*) m_binary.data();
	if (UNLIKELY(!validate_header(elf))) {
		throw std::runtime_error("Invalid ELF header! Mixup between 32- and 64-bit?");
	}

	// enumerate & load loadable segments
	const auto program_headers = elf->e_phnum;
	if (UNLIKELY(program_headers <= 0)) {
		throw std::runtime_error("ELF with no program-headers");
	}
	if (UNLIKELY(program_headers >= 16)) {
		throw std::runtime_error("ELF with too many program-headers");
	}
	if (UNLIKELY(elf->e_phoff > 0x4000)) {
		throw std::runtime_error("ELF program-headers have bogus offset");
	}
	if (UNLIKELY(elf->e_phoff + program_headers * sizeof(Elf64_Phdr) > m_binary.size())) {
		throw std::runtime_error("ELF program-headers are outside the binary");
	}

	const auto* phdr = (Elf64_Phdr*) (m_binary.data() + elf->e_phoff);
	const auto program_begin = phdr->p_vaddr;
	this->m_start_address = elf->e_entry;
	this->m_stack_address = program_begin;
	this->m_heap_address = 0x0;

	int seg = 0;
	for (const auto* hdr = phdr; hdr < phdr + program_headers; hdr++)
	{
		// Detect overlapping segments
		for (const auto* ph = phdr; ph < hdr; ph++) {
			if (hdr->p_type == PT_LOAD && ph->p_type == PT_LOAD)
			if (ph->p_vaddr < hdr->p_vaddr + hdr->p_filesz &&
				ph->p_vaddr + ph->p_filesz >= hdr->p_vaddr) {
				// Normally we would not care, but no normal ELF
				// has overlapping segments, so treat as bogus.
				throw std::runtime_error("Overlapping ELF segments");
			}
		}

		switch (hdr->p_type)
		{
			case PT_LOAD:
				// loadable program segments
				this->elf_load_ph(options, hdr);
				seg++;
				break;
			case PT_GNU_STACK:
				//printf("GNU_STACK: 0x%lX\n", hdr->p_vaddr);
				this->m_stack_address = hdr->p_vaddr; // ??
				break;
			case PT_GNU_RELRO:
				//throw std::runtime_error(
				//	"Dynamically linked ELF binaries are not supported");
				break;
		}

		uint64_t endm = hdr->p_vaddr + hdr->p_memsz;
		endm += 4095; endm &= ~0xFFF;
		if (this->m_heap_address < endm)
			this->m_heap_address = endm;
	}

	if (this->m_stack_address < 0x200000) {
		this->m_stack_address = 0x200000;
	}

	//this->relocate_section(".rela.plt", ".symtab");

	if (options.verbose_loader) {
	printf("* Entry is at %p\n", (void*) m_start_address);
	printf("* Stack is at %p\n", (void*) m_stack_address);
	}
}

void Machine::elf_load_ph(const MachineOptions& options, const void* vphdr)
{
	const auto* hdr = (const Elf64_Phdr*) vphdr;

	const auto*  src = m_binary.data() + hdr->p_offset;
	const size_t len = hdr->p_filesz;
	if (m_binary.size() <= hdr->p_offset ||
		hdr->p_offset + len <= hdr->p_offset)
	{
		throw std::runtime_error("Bogus ELF program segment offset");
	}
	if (m_binary.size() < hdr->p_offset + len) {
		throw std::runtime_error("Not enough room for ELF program segment");
	}
	if (hdr->p_vaddr + len < hdr->p_vaddr) {
		throw std::runtime_error("Bogus ELF segment virtual base");
	}

	if (options.verbose_loader) {
	printf("* Loading segment of size %zu from %p to virtual %p\n",
			len, src, (void*) hdr->p_vaddr);
	}

	if (memory.safely_within(hdr->p_vaddr, len)) {
		std::memcpy(memory.at(hdr->p_vaddr), src, len);
	} else {
		throw std::runtime_error("Unsafe PT_LOAD segment or executable too big");
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
	return (sym) ? sym->st_value : 0x0;
}

void Machine::relocate_section(const char* section_name, const char* sym_section)
{
	const auto* rela = section_by_name(m_binary, section_name);
	if (rela == nullptr) {
		printf("No such section: %s\n", section_name);
		return;
	}
	const auto* dyn_hdr = section_by_name(m_binary, sym_section);
	if (dyn_hdr == nullptr) {
		printf("No such symbol section: %s\n", sym_section);
		return;
	}
	const size_t rela_ents = rela->sh_size / rela->sh_entsize;
	printf("Rela ents: %zu\n", rela_ents);

	auto* rela_addr = elf_offset<Elf64_Rela>(m_binary, rela->sh_offset);
	for (size_t i = 0; i < rela_ents; i++)
	{
		const uint8_t type = ELF64_R_TYPE(rela_addr[i].r_info);
		if (type == R_X86_64_IRELATIVE)
		{
			const uint32_t symidx = ELF64_R_SYM(rela_addr[i].r_info);
			//auto* sym = elf_sym_index(m_binary, dyn_hdr, symidx);
			const int32_t  addend = rela_addr[i].r_addend;
			const uint64_t addr = rela_addr[i].r_offset;
			printf("Rela ent %zu with addend 0x%X = 0x%lX\n", i, addend, addr);
			auto* entry = (address_t*) memory.at(addend, 8);
			*entry = interrupt_header().vm64_dso;

/*			auto* entry = elf_offset<address_t> (m_binary, rela_addr[i].r_offset);
			auto* final = elf_offset<address_t> (m_binary, sym->st_value);
			if constexpr (true)
			{
				printf("Relocating rela %zu with sym idx %u where 0x%lX -> 0x%lX\n",
						i, symidx, rela_addr[i].r_offset, sym->st_value);
			}
			//*(address_t*) entry = (address_t) (uintptr_t) final;
			*(address_t*) entry = interrupt_header().vm64_gettimeofday;
			*/
		}
	}
}

}
