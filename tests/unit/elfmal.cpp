#include <catch2/catch_test_macros.hpp>

#include <tinykvm/machine.hpp>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <elf.h>
#include <sys/mman.h>

/* Regression tests for malicious-ELF loader bugs in lib/tinykvm/machine_elf.cpp,
   confirmed by the security audit (see hund.md). Each test crafts the hostile
   ELF in memory -- a C++ port of the audit PoC craft scripts -- and drives the
   same API path as the PoC harness (Machine::resolve, Machine::AddressOf,
   is_dynamic_elf). Every test asserts the SAFE behavior: graceful rejection
   (MachineException, or "symbol not found") instead of an out-of-bounds read
   of host memory.

   On the unpatched tree every test here FAILS: the resolve() test fails its
   size assertion, the others SIGSEGV (or abort under ASan) on the OOB read.
   To make the OOB reads deterministic without sanitizers, each hostile ELF is
   placed flush against a PROT_NONE guard page, so the first out-of-bounds
   byte faults instead of silently consuming neighboring memory. A segfault
   takes down the whole test process, so on an unpatched tree run the cases
   individually by name, e.g.: ./elfmal "section_by_name*"

   Note: Machine::resolve() is also reachable from an unprivileged guest --
   vCPU::handle_exception() (vcpu_run.cpp) calls it to symbolicate a faulting
   RIP -- so these bugs are triggerable by the guest, not just the embedder. */

namespace {
	/* Struct writers mirroring the audit PoC craft scripts (System V ELF64,
	   little-endian, matching the host). */
	std::string elf_ehdr(uint16_t e_type, uint64_t e_entry, uint64_t e_phoff,
		uint64_t e_shoff, uint16_t e_phnum, uint16_t e_shnum, uint16_t e_shstrndx)
	{
		Elf64_Ehdr h{};
		h.e_ident[EI_MAG0] = ELFMAG0;
		h.e_ident[EI_MAG1] = ELFMAG1;
		h.e_ident[EI_MAG2] = ELFMAG2;
		h.e_ident[EI_MAG3] = ELFMAG3;
		h.e_ident[EI_CLASS] = ELFCLASS64;
		h.e_ident[EI_DATA] = ELFDATA2LSB;
		h.e_ident[EI_VERSION] = EV_CURRENT;
		h.e_ident[EI_OSABI] = ELFOSABI_NONE;
		h.e_type = e_type;
		h.e_machine = EM_X86_64;
		h.e_version = EV_CURRENT;
		h.e_entry = e_entry;
		h.e_phoff = e_phoff;
		h.e_shoff = e_shoff;
		h.e_ehsize = sizeof(Elf64_Ehdr);
		h.e_phentsize = sizeof(Elf64_Phdr);
		h.e_phnum = e_phnum;
		h.e_shentsize = sizeof(Elf64_Shdr);
		h.e_shnum = e_shnum;
		h.e_shstrndx = e_shstrndx;
		return std::string(reinterpret_cast<const char*>(&h), sizeof(h));
	}
	std::string elf_phdr(uint32_t p_type, uint32_t p_flags, uint64_t p_offset,
		uint64_t p_vaddr, uint64_t p_filesz, uint64_t p_memsz, uint64_t p_align = 0x1000)
	{
		Elf64_Phdr p{};
		p.p_type = p_type;
		p.p_flags = p_flags;
		p.p_offset = p_offset;
		p.p_vaddr = p_vaddr;
		p.p_paddr = p_vaddr;
		p.p_filesz = p_filesz;
		p.p_memsz = p_memsz;
		p.p_align = p_align;
		return std::string(reinterpret_cast<const char*>(&p), sizeof(p));
	}
	std::string elf_shdr(uint32_t sh_name, uint32_t sh_type,
		uint64_t sh_offset, uint64_t sh_size, uint64_t sh_entsize = 0)
	{
		Elf64_Shdr s{};
		s.sh_name = sh_name;
		s.sh_type = sh_type;
		s.sh_offset = sh_offset;
		s.sh_size = sh_size;
		s.sh_addralign = 1;
		s.sh_entsize = sh_entsize;
		return std::string(reinterpret_cast<const char*>(&s), sizeof(s));
	}
	std::string elf_sym(uint32_t st_name, uint8_t st_info,
		uint64_t st_value, uint64_t st_size)
	{
		Elf64_Sym s{};
		s.st_name = st_name;
		s.st_info = st_info;
		s.st_value = st_value;
		s.st_size = st_size;
		return std::string(reinterpret_cast<const char*>(&s), sizeof(s));
	}

	const std::string SHSTRTAB("\0.shstrtab\0.symtab\0.strtab\0", 27);
	constexpr uint32_t NM_SHSTRTAB = 1, NM_SYMTAB = 11, NM_STRTAB = 19;
	/* mov byte [0], 0 ; jmp $ -- faults immediately if the guest is run. */
	const std::string FAULTING_CODE("\xC6\x04\x25\x00\x00\x00\x00\x00\xEB\xFE", 10);
	constexpr uint64_t VADDR = 0x200000;

	/* cand1: loadable ELF whose .symtab holds one FUNC symbol with a
	   10000-byte name, st_value=0 and st_size=~0, so resolve() takes the
	   direct-match branch for any small RIP. */
	std::string craft_longsym()
	{
		const std::string name(10000, 'S');
		const std::string strtab = std::string(1, '\0') + name + std::string(1, '\0');
		size_t cur = 64 + 56 + FAULTING_CODE.size();
		cur = (cur + 7) & ~size_t(7);
		const size_t off_shdrs = cur; cur += 3 * 64;
		const size_t off_shstrtab = cur; cur += SHSTRTAB.size();
		const size_t off_strtab = cur; cur += strtab.size();
		cur = (cur + 7) & ~size_t(7);
		const size_t off_symtab = cur; cur += 24;
		const size_t filesize = cur;
		std::string d = elf_ehdr(ET_EXEC, VADDR + 64 + 56, 64,
			off_shdrs, /*phnum=*/1, /*shnum=*/3, /*shstrndx=*/0);
		d += elf_phdr(PT_LOAD, 5, 0, VADDR, filesize, filesize); /* R+X */
		d += FAULTING_CODE;
		d.append(off_shdrs - d.size(), '\0');
		d += elf_shdr(NM_SHSTRTAB, SHT_STRTAB, off_shstrtab, SHSTRTAB.size());
		d += elf_shdr(NM_SYMTAB, SHT_SYMTAB, off_symtab, 24, 24);
		d += elf_shdr(NM_STRTAB, SHT_STRTAB, off_strtab, strtab.size());
		d += SHSTRTAB;
		d += strtab;
		d.append(off_symtab - d.size(), '\0');
		d += elf_sym(1, 0x12, 0, ~0ULL); /* GLOBAL FUNC, covers all addresses */
		return d;
	}

	/* cand2: e_shnum = 0xFFFF with a single real section header; the
	   section_by_name() loop walks 65535 headers past the end of the file. */
	std::string craft_shnum_oob()
	{
		std::string d = elf_ehdr(ET_EXEC, 0, 64,
			/*shoff=*/64, /*phnum=*/0, /*shnum=*/0xFFFF, /*shstrndx=*/0);
		d += elf_shdr(0, SHT_STRTAB, 0, 128); /* one shdr; loop continues past EOF */
		return d;
	}

	/* Layout shared by cand3/cand3b: valid .shstrtab/.symtab/.strtab sections
	   with the symtab placed at the very end of the file. */
	std::string craft_symtab_at_eof(uint64_t symtab_sh_size,
		const std::string& first_sym, const std::string& extra_sym)
	{
		const std::string strtab("\0AAAA\0", 6);
		size_t cur = 64 + 3 * 64;
		const size_t off_shstrtab = cur; cur += SHSTRTAB.size();
		const size_t off_strtab = cur; cur += strtab.size();
		cur = (cur + 7) & ~size_t(7);
		const size_t off_symtab = cur; cur += 24 + extra_sym.size();
		std::string d = elf_ehdr(ET_EXEC, 0, 64,
			/*shoff=*/64, /*phnum=*/0, /*shnum=*/3, /*shstrndx=*/0);
		d += elf_shdr(NM_SHSTRTAB, SHT_STRTAB, off_shstrtab, SHSTRTAB.size());
		d += elf_shdr(NM_SYMTAB, SHT_SYMTAB, off_symtab, symtab_sh_size, 24);
		d += elf_shdr(NM_STRTAB, SHT_STRTAB, off_strtab, strtab.size());
		d += SHSTRTAB;
		d += strtab;
		d.append(off_symtab - d.size(), '\0');
		d += first_sym; /* "AAAA", never matches the searched name */
		d += extra_sym;
		return d;
	}

	/* cand3: .symtab sh_size = 16MB but only one real entry at EOF;
	   resolve_symbol() walks entries far past the end of the file. */
	std::string craft_shsize_oob()
	{
		return craft_symtab_at_eof(0x1000000, elf_sym(1, 0x12, 0, 0), "");
	}

	/* cand3b: valid 2-entry .symtab; the second entry has st_name pointing
	   16MB past .strtab -- a wild pointer for strcmp(). */
	std::string craft_stname_wild()
	{
		return craft_symtab_at_eof(48, elf_sym(1, 0x12, 0, 0),
			elf_sym(0xFFFFF0, 0x12, 0, 0));
	}

	/* cand4: PT_INTERP with p_offset = -16, p_filesz = 32; the add-then-check
	   p_offset + p_filesz > size wraps to 16 and passes, after which
	   std::string(data + p_offset, p_filesz) reads before the buffer. */
	std::string craft_interp_wrap()
	{
		std::string d = elf_ehdr(ET_EXEC, 0, 64,
			/*shoff=*/0, /*phnum=*/1, /*shnum=*/0, /*shstrndx=*/0);
		d += elf_phdr(PT_INTERP, 4, 0xFFFFFFFFFFFFFFF0ULL, 0, 0x20, 0x20);
		return d;
	}

	/* Copies bytes into an mmap'd region with a PROT_NONE page immediately
	   before or after, so an out-of-bounds access faults deterministically
	   instead of reading whatever happens to neighbor a heap allocation. */
	struct GuardedView {
		void* mapping = nullptr;
		size_t mapping_len = 0;
		std::string_view view;

		GuardedView(std::string_view bytes, bool guard_before)
		{
			constexpr size_t PAGE = 0x1000;
			const size_t body = (bytes.size() + PAGE - 1) & ~(PAGE - 1);
			mapping_len = body + PAGE;
			mapping = mmap(nullptr, mapping_len, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			REQUIRE(mapping != MAP_FAILED);
			char* guard = guard_before ? (char*)mapping : (char*)mapping + body;
			REQUIRE(mprotect(guard, PAGE, PROT_NONE) == 0);
			char* dst = guard_before ? (char*)mapping + PAGE
				: (char*)mapping + body - bytes.size();
			std::memcpy(dst, bytes.data(), bytes.size());
			view = std::string_view(dst, bytes.size());
		}
		~GuardedView() { if (mapping) munmap(mapping, mapping_len); }
		GuardedView(const GuardedView&) = delete;
	};

	/* Safe behavior for the symbol-lookup bugs: either the loader rejects the
	   malformed section table, or the lookup simply finds nothing. What must
	   not happen is an out-of-bounds read (which the guard page turns into a
	   fatal signal on the unpatched tree). */
	void check_lookup_rejects(std::string_view binary)
	{
		bool rejected = false;
		uint64_t addr = 1;
		try {
			addr = tinykvm::Machine::AddressOf("ZZZ_no_such", binary);
		} catch (const tinykvm::MachineException&) {
			rejected = true;
		}
		REQUIRE((rejected || addr == 0));
	}
}

TEST_CASE("Initialize KVM", "[Initialize]")
{
	tinykvm::Machine::init();
}

TEST_CASE("resolve must not trust snprintf would-be length (cand1)", "[elfmal]")
{
	/* machine_elf.cpp resolve(): snprintf(result, 2048, "%s + 0x%lX", name, off)
	   returns the would-be length (~10008 for the crafted name), and
	   std::string(result, len) then reads ~8KB past the 2048-byte stack
	   buffer, disclosing host stack bytes to the caller (the guest, via the
	   exception printer path). Safe behavior: the returned string is bounded
	   by the buffer it was formatted into. */
	const std::string bin = craft_longsym();
	tinykvm::Machine::init(); /* also covers filtered runs without [Initialize] */
	tinykvm::MachineOptions opts{};
	opts.max_mem = 256ULL << 20;
	tinykvm::Machine machine{std::string_view(bin), opts};
	const std::string resolved = machine.resolve(0x1000);
	CAPTURE(resolved.size());
	REQUIRE(resolved.size() < 2048);
}

TEST_CASE("section_by_name must validate e_shnum against binary size (cand2)", "[elfmal]")
{
	/* machine_elf.cpp section_by_name(): e_shnum/e_shstrndx/sh_name are used
	   without any check against the binary size. With e_shnum = 0xFFFF the
	   loop reads section headers past EOF and strcmp()s name pointers
	   computed from attacker-controlled bytes. */
	const std::string bin = craft_shnum_oob();
	const GuardedView gv(bin, /*guard_before=*/false);
	check_lookup_rejects(gv.view);
}

TEST_CASE("resolve_symbol must validate symtab sh_size against binary size (cand3)", "[elfmal]")
{
	/* machine_elf.cpp resolve_symbol(): symtab_ents = sh_size / sizeof(Sym)
	   is trusted, so a 16MB sh_size with a 1-entry symtab at EOF walks the
	   symbol table far past the end of the file. */
	const std::string bin = craft_shsize_oob();
	const GuardedView gv(bin, /*guard_before=*/false);
	check_lookup_rejects(gv.view);
}

TEST_CASE("resolve_symbol must validate st_name against strtab size (cand3b)", "[elfmal]")
{
	/* machine_elf.cpp resolve_symbol(): &strtab[sym.st_name] is handed to
	   strcmp() with no check that st_name lies inside .strtab. */
	const std::string bin = craft_stname_wild();
	const GuardedView gv(bin, /*guard_before=*/false);
	check_lookup_rejects(gv.view);
}

TEST_CASE("is_dynamic_elf PT_INTERP offset+size must not wrap (cand4)", "[elfmal]")
{
	/* machine_elf.cpp is_dynamic_elf(): the check
	   p_offset + p_filesz > binary.size() is an add-then-check on 64-bit
	   attacker values; p_offset = -16, p_filesz = 32 wraps to 16 and passes,
	   and the interpreter string is then read from 16 bytes BEFORE the
	   buffer. Safe behavior: reject the malformed segment. */
	const std::string bin = craft_interp_wrap();
	const GuardedView gv(bin, /*guard_before=*/true);
	REQUIRE_THROWS_AS(tinykvm::is_dynamic_elf(gv.view), tinykvm::MachineException);
}
