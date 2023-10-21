#include <tinykvm/machine.hpp>
#include "helpers.cpp"

static const std::vector<uint8_t> empty;
static constexpr float TIMEOUT = 5.0f;

const tinykvm::MachineOptions options {
};
static tinykvm::Machine* machine;

// In order to be able to inspect a coredump we want to
// crash on every ASAN error.
extern "C" void __asan_on_error()
{
	abort();
}
extern "C" void __msan_on_error()
{
	abort();
}

static void fuzz_elf_loader(const uint8_t* data, size_t len)
{
	using namespace tinykvm;
	const std::string_view bin {(const char*) data, len};
	try {
		machine->reset_to(bin, options);
		machine->run(TIMEOUT);
	} catch (const MachineException& e) {
		//printf(">>> Exception: %s\n", e.what());
	}
}

extern "C"
void LLVMFuzzerTestOneInput(const uint8_t* data, size_t len)
{
	if (machine == nullptr) {
		tinykvm::Machine::init();

		machine = new tinykvm::Machine { std::string_view{}, options };
		machine->install_unhandled_syscall_handler([] (auto&, unsigned) {});
	}
#if defined(FUZZ_ELF)
	fuzz_elf_loader(data, len);
#else
	#error "Unknown fuzzing mode"
#endif
}
