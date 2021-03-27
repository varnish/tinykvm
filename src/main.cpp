#include <tinykvm/machine.hpp>
#include <cstring>
#include <cstdio>

#include <tinykvm/rsp_client.hpp>

#define NUM_GUESTS   20
#define GUEST_MEMORY 0x40000000  /* 1024MB memory */

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

	extern void setup_kvm_system_calls();
	setup_kvm_system_calls();

	asm("" : : : "memory");
	auto t0 = time_now();
	asm("" : : : "memory");

	for (unsigned i = 0; i < NUM_GUESTS; i++)
	{
		tinykvm::MachineOptions options {
			.max_mem = GUEST_MEMORY,
			.verbose_loader = false
		};
		vms.push_back(new tinykvm::Machine {binary, options});
		auto& vm = *vms.back();
		vm.set_exit_address(vm.address_of("rexit"));
		vm.setup_linux(
			{"KVM tiny guest\n", "Hello World!\n"},
			{"LC_TYPE=C", "LC_ALL=C", "USER=root"});
	}

	asm("" : : : "memory");
	auto t1 = time_now();
	asm("" : : : "memory");

	for (unsigned i = 0; i < NUM_GUESTS; i++)
	{
		auto& vm = *vms[i];
		if (getenv("DEBUG"))
		{
			tinykvm::RSP server {vm, 2159};
			printf("Waiting for connection...\n");
			auto client = server.accept();
			if (client != nullptr) {
				/* Debugging session of _start -> main() */
				printf("Connected\n");
				try {
					//client->set_verbose(true);
					while (client->process_one());
				} catch (const tinykvm::MachineException& e) {
					printf("EXCEPTION %s: %lu\n", e.what(), e.data());
					vm.print_registers();
					break;
				}
			} else {
				/* Normal execution of _start -> main() */
				vm.run();
			}
		} else {
			/* Normal execution of _start -> main() */
			vm.run();
		}

		if (false)
		{
			/* Execute public function */
			struct Data {
				char   buffer[128];
				size_t len;
			} data;
			strcpy(data.buffer, "Hello Buffered World!\n");
			data.len = strlen(data.buffer);
			vm.vmcall(vm.address_of("empty"), data);
		}
	}

	asm("" : : : "memory");
	auto t2 = time_now();
	asm("" : : : "memory");

	auto nanos_per_gc = nanodiff(t0, t1) / NUM_GUESTS;
	auto nanos_per_gr = nanodiff(t1, t2) / NUM_GUESTS;
	printf("Construct: %ldns (%ld micros)\n", nanos_per_gc, nanos_per_gc / 1000);
	printf("Runtime: %ldns (%ld micros)\n", nanos_per_gr, nanos_per_gr / 1000);

	for (auto* vm : vms) {
		delete vm;
	}
}

#include <stdexcept>
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
