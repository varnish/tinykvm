/**
 * Coverage-guided fuzzer for the ELF *symbol* paths in machine_elf.cpp.
 *
 * fuzz.cpp already fuzzes the loader (is_dynamic_elf, elf_load_ph) by handing
 * malformed bytes to Machine::reset_to(). It never reaches section_by_name(),
 * resolve_symbol() or resolve(), because nothing calls them: they hang off
 * AddressOf() / address_of() / resolve(), which the loader does not use.
 *
 * That is not a niche corner. resolve() runs on every guest fault --
 * handle_exception() calls it to symbolise the faulting address
 * (vcpu_run.cpp) -- so an adversarial ELF reaches the section and symbol
 * table walkers with nothing more than a guest that crashes on purpose.
 * Embedders reach the same code directly through AddressOf().
 *
 * This target calls all three on the fuzzer's bytes:
 *
 *   Machine::AddressOf(name, binary)     static, no Machine needed
 *   machine.address_of(name, binary)     instance form
 *   machine.resolve(rip, binary)         with an input-derived rip
 *
 * The symbol name and rip are taken from the head of the input so the fuzzer
 * can steer them, and the remainder is the ELF image. Names matter: the
 * walkers strcmp() against the string table, so a name that matches a
 * (possibly out-of-bounds) entry gets further than a random one.
 *
 * Findings here are host-memory reads driven by header fields -- out-of-range
 * e_shnum/e_shstrndx/sh_name/sh_size/st_name, and offset+size sums that wrap
 * 2^64. Note that ASan does not catch all of them: std::string's large copy
 * compiles to an inline rep movsb, which is not instrumented, so an over-read
 * of a few hundred bytes runs clean. The length assertion below is there for
 * exactly that case.
 */
#include <tinykvm/machine.hpp>
#include "helpers.cpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

/* NB: deliberately no __asan_on_error()/abort() hook, unlike fuzz.cpp.
   Aborting from that callback runs before the sanitizer prints its report, so
   the finding arrives as a bare DEADLYSIGNAL with no stack trace. Use
   ASAN_OPTIONS=abort_on_error=1 when a coredump is wanted. */

static const tinykvm::MachineOptions options {};
static tinykvm::Machine* machine = nullptr;

/* resolve() formats into a fixed 2048-byte stack buffer. Nothing it returns
   can legitimately be longer, whatever the ELF says, so a longer result means
   it copied past the end of that buffer. */
static constexpr size_t RESOLVE_BUFFER = 2048;

static void check_resolved(const std::string& s, const char* who)
{
	if (s.size() >= RESOLVE_BUFFER) {
		fprintf(stderr, "elf_symbols_fuzz: %s returned %zu bytes, "
			"but it formats into a %zu-byte buffer\n",
			who, s.size(), RESOLVE_BUFFER);
		abort();
	}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t len)
{
	if (machine == nullptr) {
		tinykvm::Machine::init();
		machine = new tinykvm::Machine { std::string_view{}, options };
		machine->install_unhandled_syscall_handler([](auto&, unsigned) {});
	}

	/* Header: rip:u64, name_len:u8, name[name_len]. Everything after it is
	   the ELF image. A truncated input just yields an empty name and a short
	   image, which is a fine thing to fuzz too. */
	if (len < sizeof(uint64_t) + 1)
		return 0;

	uint64_t rip = 0;
	memcpy(&rip, data, sizeof(rip));
	data += sizeof(rip);
	len  -= sizeof(rip);

	size_t name_len = *data++;
	len--;
	if (name_len > len)
		name_len = len;
	const std::string name(reinterpret_cast<const char*>(data), name_len);
	data += name_len;
	len  -= name_len;

	/* The image must be copied into a properly aligned buffer, not pointed at
	   in place. machine_elf.cpp casts the base pointer straight to
	   Elf64_Ehdr*, and libFuzzer's input is not 8-byte aligned once the header
	   above has been stripped off it -- every single input would report
	   misaligned access under UBSan and drown out real findings. Real callers
	   pass a std::vector, which is aligned. */
	static std::vector<uint8_t> aligned;
	aligned.assign(data, data + len);
	const std::string_view binary {
		reinterpret_cast<const char*>(aligned.data()), aligned.size() };

	/* Every one of these is documented to throw on a malformed image. Any
	   other exception type, or none at all when the image is nonsense, is
	   what we are looking for -- along with whatever the sanitizers see. */
	try {
		tinykvm::Machine::AddressOf(name, binary);
	} catch (const std::exception&) {
	}

	try {
		machine->address_of(name, binary);
	} catch (const std::exception&) {
	}

	try {
		check_resolved(machine->resolve(rip, binary), "resolve(rip)");
	} catch (const std::exception&) {
	}

	/* An address derived from the image itself is far more likely to land
	   inside a symbol's range than a uniformly random one, which is what
	   drives resolve() down the symtab path rather than straight out. */
	if (len >= sizeof(uint64_t)) {
		uint64_t inner = 0;
		memcpy(&inner, data, sizeof(inner));
		try {
			check_resolved(machine->resolve(inner, binary), "resolve(inner)");
		} catch (const std::exception&) {
		}
	}

	return 0;
}
