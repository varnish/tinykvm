#include <tinykvm/machine.hpp>
#include <cstring>

//#define ENABLE_GUEST_STDOUT
//#define ENABLE_GUEST_VERBOSE
//#define ENABLE_GUEST_CLEAR_MEMORY
#define NUM_ROUNDS   400
#define NUM_GUESTS   8
#define GUEST_MEMORY 0x800000

std::vector<uint8_t> load_file(const std::string& filename);
inline timespec time_now();
inline long nanodiff(timespec start_time, timespec end_time);

int main(int argc, char** argv)
{
	if (argc < 2) {
		fprintf(stderr, "Missing argument: 64-bit ELF binary\n");
		exit(1);
	}
	const auto binary = load_file(argv[1]);
	std::vector<tinykvm::Machine*> vms;

	for (unsigned i = 0; i < NUM_GUESTS; i++)
	{
		tinykvm::MachineOptions options {
			.max_mem = GUEST_MEMORY,
			.verbose_loader = false
		};
		vms.push_back(new tinykvm::Machine {binary, options});
		auto& vm = *vms.back();
		vm.install_unhandled_syscall_handler(
			[] (auto&, unsigned scall) {
				fprintf(stderr,	"Unhandled system call: %u\n", scall);
			});
		vm.install_syscall_handler(
			0, [] (auto& machine) {
				auto regs = machine.registers();
#ifdef ENABLE_GUEST_VERBOSE
				printf("Machine stopped with return value 0x%llX\n", regs.rdi);
#endif
				machine.stop();
			});
		vm.install_syscall_handler(
			1, [] (auto& machine) {
#ifdef ENABLE_GUEST_STDOUT
				auto regs = machine.registers();
				auto view = machine.memory_at(regs.rsi, regs.rdx);
				if (!view.empty()) {
					fwrite(view.begin(), view.size(), 1, stdout);
					fflush(stdout);
				} else {
					fprintf(stderr, "Invalid memory from guest: 0x%llX:%llu\n",
						regs.rsi, regs.rdx);
				}
#endif
			});
		vm.set_exit_address(vm.address_of("rexit"));
	}

	asm("" : : : "memory");
	auto t0 = time_now();
	asm("" : : : "memory");

	for (unsigned rounds = 0; rounds < NUM_ROUNDS; rounds++)
	for (unsigned i = 0; i < NUM_GUESTS; i++)
	{
		auto& vm = *vms[i];
#ifdef ENABLE_GUEST_CLEAR_MEMORY
		vm.reset();
#endif
		vm.setup_argv({"KVM tiny guest\n", "Hello World!\n"});
		/* Normal execution of _start -> main() */
		vm.run();
		/* Execute public function */
		struct Data {
			char   buffer[128];
			size_t len;
		} data;
		strcpy(data.buffer, "Hello Buffered World!\n");
		data.len = strlen(data.buffer);
		vm.vmcall(vm.address_of("empty"), data);
	}

	asm("" : : : "memory");
	auto t1 = time_now();
	auto nanos_per_gr = nanodiff(t0, t1) / NUM_GUESTS / NUM_ROUNDS;
	printf("Time spent: %ldns (%ld micros)\n",
		nanos_per_gr, nanos_per_gr / 1000);

	for (auto* vm : vms) {
		delete vm;
	}
}

std::vector<uint8_t> load_file(const std::string& filename)
{
	size_t size = 0;
	FILE* f = fopen(filename.c_str(), "rb");
	if (f == NULL) throw std::runtime_error("Could not open file: " + filename);

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	fseek(f, 0, SEEK_SET);

	std::vector<uint8_t> result(size);
	if (size != fread(result.data(), 1, size, f))
	{
		fclose(f);
		throw std::runtime_error("Error when reading from file: " + filename);
	}
	fclose(f);
	return result;
}

timespec time_now()
{
	timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t;
}
long nanodiff(timespec start_time, timespec end_time)
{
	return (end_time.tv_sec - start_time.tv_sec) * (long)1e9 + (end_time.tv_nsec - start_time.tv_nsec);
}
