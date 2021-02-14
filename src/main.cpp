#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <linux/kvm.h>
#include <string>
#include <stdexcept>
#include <vector>

//#define ENABLE_GUEST_STDOUT
//#define ENABLE_GUEST_CLEAR_MEMORY
#define NUM_ROUNDS   400
#define NUM_GUESTS   1000
#define GUEST_MEMORY 0x200000

/* CR0 bits */
#define CR0_PE 1u
#define CR0_MP (1U << 1)
#define CR0_EM (1U << 2)
#define CR0_TS (1U << 3)
#define CR0_ET (1U << 4)
#define CR0_NE (1U << 5)
#define CR0_WP (1U << 16)
#define CR0_AM (1U << 18)
#define CR0_NW (1U << 29)
#define CR0_CD (1U << 30)
#define CR0_PG (1U << 31)

/* CR4 bits */
#define CR4_VME 1
#define CR4_PVI (1U << 1)
#define CR4_TSD (1U << 2)
#define CR4_DE (1U << 3)
#define CR4_PSE (1U << 4)
#define CR4_PAE (1U << 5)
#define CR4_MCE (1U << 6)
#define CR4_PGE (1U << 7)
#define CR4_PCE (1U << 8)
#define CR4_OSFXSR (1U << 8)
#define CR4_OSXMMEXCPT (1U << 10)
#define CR4_UMIP (1U << 11)
#define CR4_VMXE (1U << 13)
#define CR4_SMXE (1U << 14)
#define CR4_FSGSBASE (1U << 16)
#define CR4_PCIDE (1U << 17)
#define CR4_OSXSAVE (1U << 18)
#define CR4_SMEP (1U << 20)
#define CR4_SMAP (1U << 21)

#define EFER_SCE 1
#define EFER_LME (1U << 8)
#define EFER_LMA (1U << 10)
#define EFER_NXE (1U << 11)

/* 32-bit page directory entry bits */
#define PDE32_PRESENT 1
#define PDE32_RW (1U << 1)
#define PDE32_USER (1U << 2)
#define PDE32_PS (1U << 7)

/* 64-bit page * entry bits */
#define PDE64_PRESENT 1
#define PDE64_RW (1U << 1)
#define PDE64_USER (1U << 2)
#define PDE64_ACCESSED (1U << 5)
#define PDE64_DIRTY (1U << 6)
#define PDE64_PS (1U << 7)
#define PDE64_G (1U << 8)


struct vCPU {
	int fd;
	struct kvm_run *kvm_run;
};
struct vMemory {
	uint64_t physbase;
	char*  ptr;
	size_t size;

	void reset() {
		std::memset(this->ptr, 0, this->size);
	}
};
struct VM {
	int fd = 0;
	vCPU vcpu;
	vMemory ptmem; // page tables
	vMemory romem; // binary + rodata
	vMemory rwmem; // stack + heap

	void reset() {
		rwmem.reset();
	}
	int install_memory(uint32_t idx, vMemory mem)
	{
		const struct kvm_userspace_memory_region memreg {
			.slot = idx,
			.flags = 0,
			.guest_phys_addr = mem.physbase,
			.memory_size = mem.size,
			.userspace_addr = (uintptr_t) mem.ptr,
		};
		return ioctl(this->fd, KVM_SET_USER_MEMORY_REGION, &memreg);
	}

	~VM() {
		if (fd > 0) {
			close(fd);
			close(vcpu.fd);
		}
	}
};

static int run_vm(VM& vm);
static int kvm_fd = 0;

void vm_init(VM& vm, vMemory pt, vMemory ro, vMemory rw)
{
	if (kvm_fd == 0)
	{
		kvm_fd = open("/dev/kvm", O_RDWR);
		if (kvm_fd < 0) {
			perror("open /dev/kvm");
			exit(1);
		}
		const int api_ver = ioctl(kvm_fd, KVM_GET_API_VERSION, 0);
		if (api_ver < 0) {
			perror("KVM_GET_API_VERSION");
			exit(1);
		}

		if (api_ver != KVM_API_VERSION) {
			fprintf(stderr, "Got KVM api version %d, expected %d\n",
				api_ver, KVM_API_VERSION);
			exit(1);
		}
	}

	vm.fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
	if (vm.fd < 0) {
		perror("KVM_CREATE_VM");
		exit(1);
	}

	if (ioctl(vm.fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0) {
		perror("KVM_SET_TSS_ADDR");
		exit(1);
	}

	vm.ptmem = pt;
	vm.romem = ro;
	vm.rwmem = rw;
	if (vm.install_memory(0, vm.ptmem) < 0) {
		perror("romem failed: KVM_SET_USER_MEMORY_REGION");
		exit(1);
	}
	if (vm.install_memory(1, vm.romem) < 0) {
		perror("romem failed: KVM_SET_USER_MEMORY_REGION");
		exit(1);
	}
	if (vm.install_memory(2, vm.rwmem) < 0) {
		perror("rwmem failed: KVM_SET_USER_MEMORY_REGION");
		exit(1);
	}
}

void vcpu_init(VM& vm)
{
	auto& vcpu = vm.vcpu;
	vcpu.fd = ioctl(vm.fd, KVM_CREATE_VCPU, 0);
	if (vcpu.fd < 0) {
		perror("KVM_CREATE_VCPU");
		exit(1);
	}

	const int vcpu_mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (vcpu_mmap_size <= 0) {
		perror("KVM_GET_VCPU_MMAP_SIZE");
		exit(1);
	}

	vcpu.kvm_run = (kvm_run*) mmap(NULL, vcpu_mmap_size,
		PROT_READ | PROT_WRITE, MAP_SHARED, vcpu.fd, 0);
	if (vcpu.kvm_run == MAP_FAILED) {
		perror("mmap kvm_run");
		exit(1);
	}
}

static void setup_64bit_code_segment(struct kvm_sregs *sregs)
{
	/* Code segment */
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.selector = 1 << 3,
		.type = 11, /* Code: execute, read, accessed */
		.present = 1,
		.dpl = 0,
		.db = 0,
		.s = 1, /* Code/data */
		.l = 1,
		.g = 1, /* 4KB granularity */
	};
	sregs->cs = seg;

	/* Data segment */
	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 2 << 3;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = seg;
}

static void setup_long_mode(VM& vm, struct kvm_sregs *sregs)
{
	// guest physical
	const uint64_t pml4_addr = vm.ptmem.physbase;
	const uint64_t pdpt_addr = pml4_addr + 0x1000;
	const uint64_t pd_addr   = pml4_addr + 0x2000;
	// userspace
	char* pagetable = vm.ptmem.ptr;
	auto* pml4 = (uint64_t*) (pagetable + 0x0);
	auto* pdpt = (uint64_t*) (pagetable + 0x1000);
	auto* pd = (uint64_t*) (pagetable + 0x2000);

	pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;
	pd[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;

	sregs->cr3 = pml4_addr;
	sregs->cr4 = CR4_PAE;
	sregs->cr0
		= CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs->efer = EFER_LME | EFER_LMA;

	setup_64bit_code_segment(sregs);
}

static struct kvm_sregs master_sregs;

int run_long_mode(VM& vm)
{
	static bool init = false;
	if (!init) {
		init = true;
		if (ioctl(vm.vcpu.fd, KVM_GET_SREGS, &master_sregs) < 0) {
			perror("KVM_GET_SREGS");
			exit(1);
		}
	}

	struct kvm_sregs sregs = master_sregs;
	setup_long_mode(vm, &sregs);

	if (ioctl(vm.vcpu.fd, KVM_SET_SREGS, &sregs) < 0) {
		perror("KVM_SET_SREGS");
		exit(1);
	}

	struct kvm_regs regs;
	memset(&regs, 0, sizeof(regs));
	/* Clear all FLAGS bits, except bit 1 which is always set. */
	regs.rflags = 2;
	regs.rip = vm.romem.physbase;
	/* Create stack at top of 2 MB page and grow down. */
	regs.rsp = 2 << 20;

	if (ioctl(vm.vcpu.fd, KVM_SET_REGS, &regs) < 0) {
		perror("KVM_SET_REGS");
		exit(1);
	}

	return run_vm(vm);
}

int run_vm(VM& vm)
{
	for (;;) {
		if (ioctl(vm.vcpu.fd, KVM_RUN, 0) < 0) {
			perror("KVM_RUN");
			exit(1);
		}

		auto& vcpu = vm.vcpu;
		switch (vcpu.kvm_run->exit_reason) {
		case KVM_EXIT_HLT:
			return 0;

		case KVM_EXIT_IO:
			if (vcpu.kvm_run->io.direction == KVM_EXIT_IO_OUT
				&& vcpu.kvm_run->io.port == 0xE9) {
#ifdef ENABLE_GUEST_STDOUT
				char *p = (char *) vcpu.kvm_run;
				fwrite(p + vcpu.kvm_run->io.data_offset,
					   vcpu.kvm_run->io.size, 1, stdout);
				fflush(stdout);
#endif
				continue;
			}
			fprintf(stderr,	"Unknown IO port %d\n",
				vcpu.kvm_run->io.port);
			continue;
		default:
			fprintf(stderr,	"Got exit_reason %d,"
				" expected KVM_EXIT_HLT (%d)\n",
				vcpu.kvm_run->exit_reason, KVM_EXIT_HLT);
			exit(1);
		}
	}
	return -1;
}

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
	std::vector<VM*> vms;

	for (unsigned i = 0; i < NUM_GUESTS; i++)
	{
		vms.push_back(new VM);
		auto& vm = *vms.back();

		size_t pt_size = 0x8000;
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

		auto binsize = (binary.size() + 0xFFF) & ~0xFFF;
		binsize += 0x8000;
		auto binaddr = 0x0;

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
		memcpy(bin_ptr, binary.data(), binary.size());

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

		vm_init(vm, ptmem, romem, rwmem);
		vcpu_init(vm);
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
		memcpy(vm.romem.ptr, binary.data(), binary.size());
#endif

		assert( run_long_mode(vm) == 0 );
	}

	asm("" : : : "memory");
	auto t1 = time_now();
	auto nanos_per_gr = nanodiff(t0, t1) / NUM_GUESTS / NUM_ROUNDS;
	printf("Time spent: %ldns (%ld micros)\n",
		nanos_per_gr, nanos_per_gr / 1000);

	for (auto* vm : vms) {
		delete vm;
	}
	close(kvm_fd);
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
