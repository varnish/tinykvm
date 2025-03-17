#pragma once
#include "../common.hpp" // for MachineException
#include "elf.h"

namespace tinykvm {

	template <typename T>
	inline const T* elf_offset(std::string_view binary, intptr_t ofs) {
		if (ofs < 0 || ofs + sizeof(T) > binary.size())
			throw MachineException("Invalid ELF offset", ofs);
		return (const T*) &binary.at(ofs);
	}
	template <typename T>
	inline const T* elf_offset_array(std::string_view binary, intptr_t ofs, size_t count) {
		if (ofs < 0 || ofs + count * sizeof(T) > binary.size())
			throw MachineException("Invalid ELF offset", ofs);
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

}
