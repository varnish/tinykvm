#include "machine.hpp"

#include <cassert>
#include <cstring>
#include "util/elf.h"

namespace tinykvm {

template <typename T>
inline const T* elf_offset(std::string_view binary, intptr_t ofs) {
	return (const T*) &binary.at(ofs);
}
inline const auto* elf_header(std::string_view binary) {
	return elf_offset<Elf64_Ehdr> (binary, 0);
}
inline bool validate_header(const Elf64_Ehdr* hdr)
{
	if (hdr->e_ident[EI_MAG0] != 0x7F ||
		hdr->e_ident[EI_MAG1] != 'E'  ||
		hdr->e_ident[EI_MAG2] != 'L'  ||
		hdr->e_ident[EI_MAG3] != 'F')
		return false;
	return hdr->e_ident[EI_CLASS] == ELFCLASS64;
}

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
	if (UNLIKELY(program_headers >= 10)) {
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
	}

	if (this->m_stack_address < 0x200000) {
		this->m_stack_address = 0x200000;
	}

	// the default exit function is simply 'exit'
	this->m_exit_address = this->address_of("exit");

	if (options.verbose_loader) {
	printf("* Entry is at %p\n", (void*) m_start_address);
	printf("* Stack is at %p\n", (void*) m_stack_address);
	printf("* Exit is at %p\n", (void*) m_exit_address);
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

static const Elf64_Shdr* section_by_name(std::string_view binary, const char* name)
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

}
