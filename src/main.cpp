#include "machine.hpp"
#include <sys/mman.h>
#include <cassert>
#include <cstring>
#include <string>
#include <stdexcept>
#include <vector>

//#define ENABLE_GUEST_CLEAR_MEMORY
#define NUM_ROUNDS   4000
#define NUM_GUESTS   8
#define GUEST_MEMORY 0x200000

std::vector<uint8_t> load_file(const std::string& filename);
inline timespec time_now();
inline long nanodiff(timespec start_time, timespec end_time);

int main(int argc, char** argv)
{
	if (argc < 2) {
		fprintf(stderr, "Missing argument: VM64.bin\n");
		exit(1);
	}
	const auto binary = load_file(argv[1]);
	std::vector<tinykvm::Machine*> vms;

	for (unsigned i = 0; i < NUM_GUESTS; i++)
	{
		const size_t pt_size = 0x8000;
		auto* pt_ptr = (char*) mmap(NULL, pt_size, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
		if (pt_ptr == MAP_FAILED) {
			perror("mmap ptmem");
			exit(1);
		}
		madvise(pt_ptr, pt_size, MADV_MERGEABLE);
		const vMemory ptmem {
			.physbase = 0x2000,
			.ptr = pt_ptr,
			.size = pt_size
		};

		const size_t binsize = (binary.size() + 0xFFF) & ~0xFFF;
		auto* bin_ptr = (char*) mmap(NULL, binsize, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
		if (bin_ptr == MAP_FAILED) {
			perror("mmap romem");
			exit(1);
		}
		madvise(bin_ptr, binsize, MADV_MERGEABLE);
		const vMemory romem {
			.physbase = 0x100000,
			.ptr = bin_ptr,
			.size = binsize
		};
		std::memcpy(bin_ptr, binary.data(), binary.size());

		auto* mem_ptr = (char*) mmap(NULL, GUEST_MEMORY, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
		if (mem_ptr == MAP_FAILED) {
			perror("mmap rwmem");
			exit(1);
		}
		madvise(mem_ptr, GUEST_MEMORY, MADV_MERGEABLE);
		const vMemory rwmem {
			.physbase = 0x200000,
			.ptr = mem_ptr,
			.size = GUEST_MEMORY
		};

		vms.push_back(new tinykvm::Machine {
			{binary.begin(), binary.end()},
			ptmem, romem, rwmem
		});
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
		vm.setup_call(
			/* RIP at start of binary */
			0x100000,
			/* Create stack at top of 2 MB page and grow down. */
			0x200000
		);

		assert( vm.run() == 0 );
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
