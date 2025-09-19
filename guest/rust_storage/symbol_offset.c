// Generate a C program that loads a 64-bit ELF object file,
// goes through each symbol and adds an offset from argv[1],
// then writes back to the same 64-bit ELF object file.
#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char** argv)
{
	if (argc < 3) {
		fprintf(stderr, "%s  [input ELF object] [offset]\n", argv[0]);
		exit(1);
	}
	const char* input_elf = argv[1];
	// The offset is a hex address (0x...)
	const uint64_t offset = strtoull(argv[2], NULL, 0);
	// Only modify symbols starting with the symbol_prefix
	const char* symbol_prefix = "remote_";
	const char* symbol_contains = NULL; // If set, only modify symbols containing this substring
	if (argc >= 4) {
		symbol_prefix = argv[3];
	}
	if (argc >= 5) {
		symbol_contains = argv[4];
	}
	printf("Input ELF: %s  Offset: 0x%lX  Prefix: %s  Contains: %s\n",
		input_elf, offset, symbol_prefix, symbol_contains ? symbol_contains : "(none)");

	// Get file size
	struct stat st;
	if (stat(input_elf, &st) != 0) {
		fprintf(stderr, "Unable to stat %s, does the file exist?\n", input_elf);
		exit(1);
	}
	const size_t flen = st.st_size;

	const int fd = open(input_elf, O_RDWR);
	if (fd < 0) {
		perror("open input ELF");
		exit(1);
	}
	// Map the file to memory (read+write)
	void* data = mmap(NULL, flen, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED) {
		perror("mmap input ELF");
		exit(1);
	}
	close(fd);

	Elf64_Ehdr* ehdr = (const Elf64_Ehdr*) data;
	if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
		ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
		ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
		ehdr->e_ident[EI_MAG3] != ELFMAG3 ||
		ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
		ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
		ehdr->e_type != ET_DYN ||
		ehdr->e_machine != EM_X86_64) {
		fprintf(stderr, "Not a valid x86-64 ELF object file\n");
		exit(1);
	}
	// If the last argument is "+exec", change the type to ET_EXEC
	if (strcmp(argv[argc-1], "+exec") == 0) {
		// We need a static executable type in order for --just-symbols to work
		ehdr->e_type = ET_EXEC; // Change to executable type
	}

	const Elf64_Shdr* shdr = (const Elf64_Shdr*) (data + ehdr->e_shoff);
	const Elf64_Shdr* strtab_hdr = &shdr[ehdr->e_shstrndx];
	const char* shstrtab = (const char*) (data + strtab_hdr->sh_offset);

	const Elf64_Sym* symtab = NULL;
	size_t symcount = 0;
	const char* strtab = NULL;
	for (int i = 0; i < ehdr->e_shnum; i++) {
		const char* secname = &shstrtab[shdr[i].sh_name];
		if (strcmp(secname, ".symtab") == 0) {
			symtab = (const Elf64_Sym*) (data + shdr[i].sh_offset);
			symcount = shdr[i].sh_size / sizeof(Elf64_Sym);
		} else if (strcmp(secname, ".strtab") == 0) {
			strtab = (const char*) (data + shdr[i].sh_offset);
		}
	}
	if (symtab == NULL || strtab == NULL) {
		fprintf(stderr, "No symbol table in ELF file\n");
		exit(1);
	}
	printf("Found %lu symbols\n", symcount);
	for (size_t i = 0; i < symcount; i++)
	{
		if (ELF64_ST_TYPE(symtab[i].st_info) == STT_NOTYPE ||
			ELF64_ST_TYPE(symtab[i].st_info) == STT_OBJECT ||
			ELF64_ST_TYPE(symtab[i].st_info) == STT_FUNC)
		{
			if (symtab[i].st_value == 0x0)
				continue;
			if (symtab[i].st_shndx != SHN_UNDEF &&
				symtab[i].st_shndx < ehdr->e_shnum &&
				shdr[symtab[i].st_shndx].sh_type != SHT_NOBITS)
			{
				// Valid symbol, check prefix
				if (strncmp(&strtab[symtab[i].st_name], symbol_prefix, strlen(symbol_prefix)) != 0) {
					// Prefix does not match, check if we have a "contains" filter
					if (symbol_contains) {
						if (strstr(&strtab[symtab[i].st_name], symbol_contains) == NULL) {
							// Does not contain the substring, skip
							continue;
						}
					} else {
						continue;
					}
				}
				// Apply the offset
				const uint64_t old_value = symtab[i].st_value;
				((Elf64_Sym *) symtab)[i].st_value += offset;
				printf("Symbol: %s at 0x%lX -> 0x%lX\n", &strtab[symtab[i].st_name], old_value, symtab[i].st_value);
				// Also, make it absolute
				((Elf64_Sym *) symtab)[i].st_shndx = SHN_ABS;
			}
		}
	}
	munmap(data, flen);
	return 0;
}
