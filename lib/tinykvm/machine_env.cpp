#include "machine.hpp"
#include <cstring>

namespace tinykvm {

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
	struct tinykvm_x86regs regs {0};
	this->setup_registers(regs);
	this->setup_argv(regs.rsp, args, env);
	// Set registers back
	this->set_registers(regs);
}

void Machine::copy_to_guest(address_t addr, const void* src, size_t size)
{
	auto* dst = memory.safely_at(addr, size);
	std::memcpy(dst, src, size);
}

}
