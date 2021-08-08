#include "machine.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <random>
#include <sys/auxv.h>
#include "util/elf.hpp"

namespace tinykvm {
using address_t = Machine::address_t;

template<typename T>
struct AuxVec
{
	T a_type;		/* Entry type */
	T a_val;		/* Register value */
};

static inline
void push_arg(Machine& m, std::vector<address_t>& vec, address_t& dst, const std::string& str)
{
	dst -= str.size()+1;
	dst &= ~(uint64_t)0x7; // maintain alignment
	vec.push_back(dst);
	m.copy_to_guest(dst, str.data(), str.size()+1);
}
static inline
void push_aux(std::vector<address_t>& vec, AuxVec<address_t> aux)
{
	vec.push_back(aux.a_type);
	vec.push_back(aux.a_val);
}
static inline
void push_down(Machine& m, address_t& dst, const void* data, size_t size)
{
	dst -= size;
	dst &= ~(uint64_t)0x7; // maintain alignment
	m.copy_to_guest(dst, data, size);
}

void Machine::setup_argv(__u64& rsp,
	const std::vector<std::string>& args,
	const std::vector<std::string>& env)
{
	// Arguments to main()
	std::vector<address_t> argv;
	argv.push_back(args.size()); // argc
	for (const auto& string : args) {
		argv.push_back(stack_push(rsp, string));
	}
	argv.push_back(0x0);
	for (const auto& string : env) {
		argv.push_back(stack_push(rsp, string));
	}
	argv.push_back(0x0);

	// Extra aligned SP and copy the arguments over
	const size_t argsize = argv.size() * sizeof(argv[0]);
	rsp -= argsize;
	rsp &= ~0xF; // mandated 16-byte stack alignment

	this->copy_to_guest(rsp, argv.data(), argsize);
}
void Machine::setup_argv(
	const std::vector<std::string>& args,
	const std::vector<std::string>& env)
{
	struct tinykvm_x86regs regs {};
	this->setup_registers(regs);
	this->setup_argv(regs.rsp, args, env);
	// Set registers back
	this->set_registers(regs);
}

void Machine::setup_linux(__u64& rsp,
	const std::vector<std::string>& args,
	const std::vector<std::string>& env)
{
	address_t dst = rsp;

	/* Generate stack canary */
	auto gen = std::default_random_engine(time(0));
	std::uniform_int_distribution<int> rand(0,256);

	std::array<uint8_t, 16> canary;
	std::generate(canary.begin(), canary.end(), [&] { return rand(gen); });
	push_down(*this, dst, canary.data(), canary.size());
	const auto canary_addr = dst;

	const char platform[] = "AMD64 TinyKVM Guest";
	push_down(*this, dst, platform, sizeof(platform));
	const auto platform_addr = dst;

	/* Push program headers */
	const auto* binary_ehdr = elf_offset<Elf64_Ehdr> (m_binary, 0);
	const auto* binary_phdr = elf_offset<Elf64_Phdr> (m_binary, binary_ehdr->e_phoff);
	const unsigned phdr_count = binary_ehdr->e_phnum;
	for (unsigned i = 0; i < phdr_count; i++)
	{
		const auto* phd = &binary_phdr[i];
		push_down(*this, dst, phd, sizeof(Elf64_Phdr));
	}
	const auto phdr_location = dst;

	/* Push arguments to main() */
	std::vector<address_t> argv;
	argv.push_back(args.size()); // argc
	for (const auto& string : args) {
		push_arg(*this, argv, dst, string);
	}
	argv.push_back(0x0);

	/* Push environment vars */
	for (const auto& string : env) {
		push_arg(*this, argv, dst, string);
	}
	argv.push_back(0x0);

	/* Push auxiliary vector */
	push_aux(argv, {AT_PAGESZ, 0x1000});
	push_aux(argv, {AT_CLKTCK, getauxval(AT_CLKTCK)});

	// ELF related
	push_aux(argv, {AT_PHENT, sizeof(*binary_phdr)});
	push_aux(argv, {AT_PHDR,  phdr_location});
	push_aux(argv, {AT_PHNUM, phdr_count});

	// Misc
	push_aux(argv, {AT_BASE, 0x400000});
	push_aux(argv, {AT_ENTRY, binary_ehdr->e_entry});
	push_aux(argv, {AT_HWCAP,  getauxval(AT_HWCAP)});
	push_aux(argv, {AT_HWCAP2, getauxval(AT_HWCAP2)});
	push_aux(argv, {AT_UID, 1000});
	push_aux(argv, {AT_EUID, 0});
	push_aux(argv, {AT_GID, 0});
	push_aux(argv, {AT_EGID, 0});
	push_aux(argv, {AT_SECURE, 0});
	push_aux(argv, {AT_PLATFORM, platform_addr});

	push_aux(argv, {AT_DCACHEBSIZE, getauxval(AT_DCACHEBSIZE)});
	push_aux(argv, {AT_ICACHEBSIZE, getauxval(AT_ICACHEBSIZE)});
	push_aux(argv, {AT_L1D_CACHEGEOMETRY, getauxval(AT_L1D_CACHEGEOMETRY)});
	push_aux(argv, {AT_L1D_CACHESIZE, getauxval(AT_L1D_CACHESIZE)});
	push_aux(argv, {AT_L1I_CACHEGEOMETRY, getauxval(AT_L1I_CACHEGEOMETRY)});
	push_aux(argv, {AT_L1I_CACHESIZE, getauxval(AT_L1I_CACHESIZE)});
	push_aux(argv, {AT_L2_CACHEGEOMETRY, getauxval(AT_L2_CACHEGEOMETRY)});
	push_aux(argv, {AT_L2_CACHESIZE, getauxval(AT_L2_CACHESIZE)});
	push_aux(argv, {AT_L3_CACHEGEOMETRY, getauxval(AT_L3_CACHEGEOMETRY)});
	push_aux(argv, {AT_L3_CACHESIZE, getauxval(AT_L3_CACHESIZE)});
	push_aux(argv, {AT_UCACHEBSIZE, getauxval(AT_UCACHEBSIZE)});

	// Canary / randomness
	push_aux(argv, {AT_RANDOM, canary_addr});
	push_aux(argv, {AT_NULL, 0});

	// from this point on the stack is starting, pointing @ argc
	// install the arg vector
	const size_t argsize = argv.size() * sizeof(argv[0]);
	dst -= argsize;
	dst &= ~(uint64_t)0xF; // mandated 16-byte stack alignment
	this->copy_to_guest(dst, argv.data(), argsize);
	// re-initialize machine stack-pointer
	rsp = dst;
}
void Machine::setup_linux(
	const std::vector<std::string>& args,
	const std::vector<std::string>& env)
{
	struct tinykvm_x86regs regs {};
	this->setup_registers(regs);
	this->setup_linux(regs.rsp, args, env);
	// Set registers back
	this->set_registers(regs);
}

}
