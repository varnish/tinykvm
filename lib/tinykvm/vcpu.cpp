#include "machine.hpp"

#define _GNU_SOURCE 1
#include <cassert>
#include <cerrno>
#include <cstring>
#include <cpuid.h>
#include <linux/kvm.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "page_streaming.hpp"
#include "amd64/amd64.hpp"
#include "amd64/idt.hpp"
#include "amd64/gdt.hpp"
#include "amd64/lapic.hpp"
#include "amd64/tss.hpp"
#include "amd64/paging.hpp"
#include "amd64/memory_layout.hpp"
#include "amd64/usercode.hpp"
extern "C" int close(int);
extern "C" void tinykvm_timer_signal_handler(int);
#define TINYKVM_USE_SYNCED_SREGS 1
/* Constructing or resetting a fork from a master inherited over fork() requires
   that reading the master's registers never ioctls the master's vCPU fd, which
   the child process cannot use. With synced sregs, get_special_registers()
   reads the mmap'd kvm_run page instead of KVM_GET_SREGS; FPU is served from
   the prepare-time snapshot (Machine::prepared_fpu_registers()). If this is
   ever disabled, get_special_registers() reverts to KVM_GET_SREGS and
   cross-process fork construction breaks with -EIO. */
#if !TINYKVM_USE_SYNCED_SREGS
#error "TINYKVM_USE_SYNCED_SREGS must be enabled for cross-process fork construction"
#endif

#ifndef SYS_gettid
#error "SYS_gettid unavailable on this system"
#endif
#define gettid() ((pid_t)syscall(SYS_gettid))

struct ksigevent
{
	union sigval sigev_value;
	int sigev_signo;
	int sigev_notify;
	int sigev_tid;
};

namespace tinykvm {
	/* Userspace register storage for a vCPU whose kvm_run page is not mapped
	   yet. See vCPU::init() and vCPU::lazily_map_kvm_run(). */
	struct ShadowRegisters {
		struct kvm_regs  regs {};
		struct kvm_sregs sregs {};
	};
	static struct kvm_xcrs master_xregs;
	static struct {
		__u32 nent;
		__u32 padding;
		struct kvm_cpuid_entry2 entries[100];
	} kvm_cpuid;
	static long vcpu_mmap_size = 0;

TINYKVM_COLD()
void initialize_vcpu_stuff(int kvm_fd)
{
	vcpu_mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (vcpu_mmap_size <= 0) {
		throw MachineException("Failed to KVM_GET_VCPU_MMAP_SIZE");
	}

	/* Retrieve KVM-host CPUID features */
	kvm_cpuid.nent = sizeof(kvm_cpuid.entries) / sizeof(kvm_cpuid.entries[0]);
	if (ioctl(kvm_fd, KVM_GET_SUPPORTED_CPUID, &kvm_cpuid) < 0) {
		throw MachineException("KVM_GET_SUPPORTED_CPUID failed");
	}
}

void* Machine::create_vcpu_timer()
{
	signal(SIGUSR2, tinykvm_timer_signal_handler);

	struct ksigevent sigev {};
	sigev.sigev_notify = SIGEV_SIGNAL | SIGEV_THREAD_ID;
	sigev.sigev_signo = SIGUSR2;
	sigev.sigev_tid = gettid();

	timer_t timer_id {};
	if (timer_create(CLOCK_MONOTONIC, (struct sigevent *)&sigev, &timer_id) < 0)
		throw MachineException("Unable to create timeout timer");
	return timer_id;
}

void vCPU::map_kvm_run()
{
	auto* mapping = (struct kvm_run*) ::mmap(NULL, vcpu_mmap_size,
		PROT_READ | PROT_WRITE, MAP_SHARED, this->fd, 0);
	if (UNLIKELY(mapping == MAP_FAILED)) {
		Machine::machine_exception("Failed to create KVM run-time mapped memory");
	}
	this->adopt_kvm_run(mapping);
}

void vCPU::adopt_kvm_run(struct kvm_run* mapping)
{
	this->kvm_run = mapping;

	/* We only want GPRs and SREGS for now. */
	kvm_run->kvm_valid_regs = KVM_SYNC_X86_REGS;
#ifdef TINYKVM_USE_SYNCED_SREGS
	kvm_run->kvm_valid_regs |= KVM_SYNC_X86_SREGS;
#endif

	/* The synced-registers area is the canonical register storage now. */
	this->m_regs  = &kvm_run->s.regs.regs;
	this->m_sregs = &kvm_run->s.regs.sregs;
}

void vCPU::lazily_map_kvm_run()
{
	/* First run of a fork that deferred its kvm_run mapping: create the
	   mapping, hand the shadow registers to KVM (both GPRs and SREGS must be
	   marked dirty, or the guest would enter with eg. CR3=0), and re-point
	   the register accessors at the mapping, permanently.

	   INVARIANT: this pointer flip happens on the run path only. No caller
	   may hold on to a registers() or get_special_registers() reference
	   across a run, or it would keep writing to the freed shadow. */
	auto* shadow = (ShadowRegisters *)this->m_shadow_regs;
	this->map_kvm_run();

	/* A pooled member's mapping belongs to its seat, which keeps it for the
	   next tenant: lever C's one-time flip is not re-paid on seat reuse. */
	if (UNLIKELY(this->machine().m_seat != nullptr)) {
		this->machine().m_seat->kvm_run = this->kvm_run;
	}

	if (shadow != nullptr) {
		kvm_run->s.regs.regs  = shadow->regs;
		kvm_run->s.regs.sregs = shadow->sregs;
		kvm_run->kvm_dirty_regs |= this->m_shadow_dirty_regs;
		this->m_shadow_regs = nullptr;
		this->m_shadow_dirty_regs = 0;
		delete shadow;
	}
}

void vCPU::init(int kvm_vcpu_id, int guest_cpu_index, Machine& machine, const MachineOptions& options)
{
	this->kvm_vcpu_id = kvm_vcpu_id;
	this->guest_cpu_index = guest_cpu_index;
	this->last_fault_address = 0;
	this->m_machine = &machine;
	if (this->fd < 0) {
		this->fd = ioctl(machine.fd, KVM_CREATE_VCPU, this->kvm_vcpu_id);
		if (UNLIKELY(this->fd < 0)) {
			Machine::machine_exception("Failed to KVM_CREATE_VCPU");
		}
	}
	if (this->timer_id == nullptr) {
		this->timer_id = Machine::create_vcpu_timer();
		this->timer_tid = gettid();
	}
	if (!this->m_initialized) {
		this->m_initialized = true;

		/* A fork may defer the kvm_run mapping to its first run, keeping
		   parked forks out of this address space's VMA count. Masters are
		   always mapped eagerly: fork construction reads the master's
		   registers through the mapping, from a process that may have only
		   inherited the master over fork(). See lazily_map_kvm_run(). */
		if (options.lazy_vcpu_mmap && machine.is_forked()) {
			auto* shadow = new ShadowRegisters {};
			this->m_shadow_regs = shadow;
			this->m_regs  = &shadow->regs;
			this->m_sregs = &shadow->sregs;
		} else {
			this->map_kvm_run();
		}

		/* Assign CPUID features to guest. I don't believe the guest
		   can change of this, so we will only set it once. */
		if (ioctl(this->fd, KVM_SET_CPUID2, &kvm_cpuid) < 0) {
			Machine::machine_exception("KVM_SET_CPUID2 failed");
		}
	}

	// Only master VMs need special registers
	// Forked VMs derive special register from the master VM
	if (!this->machine().is_forked())
	{
		struct kvm_sregs master_sregs {};
		const auto physbase = machine.main_memory().physbase;

		// Check for UMIP, SMEP and SMAP support
		// https://www.felixcloutier.com/x86/cpuid
		int eax, ebx = 0, ecx = 0, edx = 0;
		__cpuid(0, eax, ebx, ecx, edx);
		__cpuid_count(7, 0, eax, ebx, ecx, edx);
		bool has_fsgsbase = (ebx & (1 <<  0)) != 0; // EBX bit 0
		bool has_umip = (ecx & (1 <<  2)) != 0; // ECX bit 2
		bool has_smep = (ebx & (1 <<  7)) != 0; // EBX bit 7
		bool has_smap = (ebx & (1 << 20)) != 0; // EBX bit 20
		if (!has_fsgsbase) {
			throw MachineException("CPU does not support FS/GS base (too old?)");
		}

		master_sregs.cr3 = physbase + PT_ADDR;
		master_sregs.cr4 =
			CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_OSXSAVE |
			CR4_FSGSBASE;
		if (has_umip) {
			master_sregs.cr4 |= CR4_UMIP;
		}
		if (has_smep) {
			master_sregs.cr4 |= CR4_SMEP;
		}
		if (has_smap) {
			master_sregs.cr4 |= CR4_SMAP;
		}
		master_sregs.cr0 =
			CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP;
		master_sregs.efer =
			EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE;
		setup_amd64_segment_regs(master_sregs, physbase + GDT_ADDR);
		master_sregs.gs.base = this->vcpu_table_addr();
		setup_amd64_tss_regs(master_sregs, physbase + TSS_ADDR);
		setup_amd64_exception_regs(master_sregs, physbase + IDT_ADDR);
		this->set_special_registers(master_sregs);
	}

	this->init_extended_state(machine);
}

void vCPU::init_from_seat(VmGroupSeat& seat, Machine& machine,
	const MachineOptions& options)
{
	this->kvm_vcpu_id = seat.kvm_vcpu_id;
	this->guest_cpu_index = 0;
	this->last_fault_address = 0;
	this->m_machine = &machine;

	/* The seat's vCPU was created when the group materialized the seat, and is
	   adopted by every tenant after that; it is never closed while the group
	   lives. Creating it at materialization rather than here is what keeps a
	   KVM_CREATE_VCPU failure (EMFILE, or the group's KVM_CAP_MAX_VCPUS wall)
	   from leaving a seat with no vCPU at the head of the free list, where it
	   would fail every subsequent acquire for the life of the group. */
	if (UNLIKELY(seat.vcpu_fd < 0)) {
		Machine::machine_exception("VM group seat has no vCPU", seat.kvm_vcpu_id);
	}
	this->fd = seat.vcpu_fd;

	/* The seat's timer is bound to the thread that created it (SIGEV_THREAD_ID
	   with sigev_tid), but the seat itself is not thread-bound: any thread may
	   be handed it next. Adopting a foreign-thread timer would break two ways
	   at once - this tenant's execution timeout would never interrupt its
	   KVM_RUN (an infinite guest loop would hang forever), and the 20ms
	   re-arm interval would keep firing at the *original* thread, setting its
	   thread_local timer_was_triggered and timing out whichever innocent
	   sibling happens to be running there. So rebind on adoption, paying
	   exactly what Machine::migrate_to_this_thread() pays. */
	const pid_t this_tid = gettid();
	if (seat.timer_id != nullptr && seat.owner_tid != this_tid) {
		timer_delete((timer_t)seat.timer_id);
		/* Cleared before the create, so a throw cannot leave the seat (and
		   thus the group destructor) holding a deleted timer. */
		seat.timer_id = nullptr;
		seat.owner_tid = 0;
	}
	if (seat.timer_id == nullptr) {
		seat.timer_id = Machine::create_vcpu_timer();
		seat.owner_tid = this_tid;
	}
	this->timer_id = seat.timer_id;
	this->timer_tid = seat.owner_tid;

	this->m_initialized = true;
	if (seat.kvm_run != nullptr) {
		this->adopt_kvm_run((struct kvm_run *)seat.kvm_run);
	} else if (options.lazy_vcpu_mmap) {
		auto* shadow = new ShadowRegisters {};
		this->m_shadow_regs = shadow;
		this->m_regs  = &shadow->regs;
		this->m_sregs = &shadow->sregs;
	} else {
		this->map_kvm_run();
		seat.kvm_run = this->kvm_run;
	}

	if (!seat.vcpu_initialized) {
		seat.vcpu_initialized = true;
		/* Assign CPUID features to guest. Once per seat: KVM rejects a
		   changed CPUID after the vCPU has run. */
		if (ioctl(this->fd, KVM_SET_CPUID2, &kvm_cpuid) < 0) {
			Machine::machine_exception("KVM_SET_CPUID2 failed");
		}
	} else {
		/* The previous tenant may have halted. Parity with smp_init(). */
		const kvm_mp_state state {
			.mp_state = KVM_MP_STATE_RUNNABLE
		};
		if (ioctl(this->fd, KVM_SET_MP_STATE, &state) < 0) {
			Machine::machine_exception("KVM_SET_MP_STATE failed");
		}
	}

	/* Pooled machines are always forks, so they inherit the master's special
	   registers instead of building their own (see init()). */
	this->init_extended_state(machine);
}

void vCPU::detach_to_seat(VmGroupSeat& seat) noexcept
{
	if (this->fd >= 0) {
		seat.vcpu_fd  = this->fd;
		seat.kvm_run  = this->kvm_run;
		/* The live timer, and the thread it is actually bound to - which is
		   not necessarily this thread: Machine::migrate_to_this_thread() may
		   have rebound it elsewhere, and destruction may happen on a third
		   thread entirely. The next tenant compares against this. */
		seat.timer_id  = this->timer_id;
		seat.owner_tid = this->timer_tid;
	}
	this->fd = -1;
	this->kvm_run = nullptr;
	this->timer_id = nullptr;
	this->timer_tid = 0;
	this->m_regs = nullptr;
	this->m_sregs = nullptr;
	delete (ShadowRegisters *)this->m_shadow_regs;
	this->m_shadow_regs = nullptr;
	this->m_shadow_dirty_regs = 0;
	this->m_initialized = false;
}

void vCPU::init_extended_state(Machine& machine)
{
	// Avoid loading X-regs more than once
	static bool minit = false;
	if (!minit) {
		minit = true;
		if (ioctl(this->fd, KVM_GET_XCRS, &master_xregs) < 0) {
			Machine::machine_exception("KVM_GET_XCRS failed");
		}
		/* Enable AVX and AVX512 instructions */
		master_xregs.xcrs[0].xcr = 0;
		master_xregs.xcrs[0].value |= 0x7; // FPU, SSE, YMM

		/* Host supports AVX-512F (most basic AVX-512 feature) */
		if (__builtin_cpu_supports("avx512f")) {
			master_xregs.xcrs[0].value |= 0xE0; // AVX512
		}
		master_xregs.nr_xcrs = 1;
	}

	/* Extended control registers */
	if (ioctl(this->fd, KVM_SET_XCRS, &master_xregs) < 0) {
		Machine::machine_exception("KVM_SET_XCRS failed");
	}

	/* Enable SYSCALL/SYSRET instructions */
	struct {
		__u32 nmsrs; /* number of msrs in entries */
		__u32 pad = 0;

		struct kvm_msr_entry entries[8];
	} msrs;
	msrs.nmsrs = 2;
	msrs.entries[0].index = AMD64_MSR_STAR;
	msrs.entries[1].index = AMD64_MSR_LSTAR;
	msrs.entries[0].data  = (0x8LL << 32) | (0x1BLL << 48);
	msrs.entries[1].data  = interrupt_header().translated_vm_syscall(machine.main_memory());

	if (!this->machine().is_forked())
	{
		// KVM PV wall clock and system time
		msrs.entries[2].index = 0x4b564d00; // MSR_KVM_WALL_CLOCK_NEW
		msrs.entries[2].data  = 0x2010;
		msrs.entries[3].index = 0x4b564d01; // MSR_KVM_SYSTEM_TIME_NEW
		msrs.entries[3].data  = 0x2021;
		msrs.nmsrs += 2; // Add 2 more MSRs
	}

	if (ioctl(this->fd, KVM_SET_MSRS, &msrs) < (int)msrs.nmsrs) {
		Machine::machine_exception("KVM_SET_MSRS: failed to set STAR/LSTAR");
	}
}

void vCPU::smp_init(int id, Machine& machine)
{
	/* SMP vCPUs keep both roles equal: id is dense per-machine today, and a
	   machine's own SMP vCPUs get guest indices 1..k. Pooling refuses SMP. */
	this->kvm_vcpu_id = id;
	this->guest_cpu_index = id;
	this->fd = ioctl(machine.fd, KVM_CREATE_VCPU, this->kvm_vcpu_id);
	this->m_machine = &machine;
	auto& memory = machine.main_memory();
	memory.smp_guards_enabled = true; // Enable pagetable locking

	if (UNLIKELY(this->fd < 0)) {
		Machine::machine_exception("Failed to KVM_CREATE_VCPU");
	}
	this->timer_id = Machine::create_vcpu_timer();
	this->timer_tid = gettid();

	/* SMP vCPUs are only ever created in order to run, and so they are
	   always mapped eagerly. */
	this->m_initialized = true;
	this->map_kvm_run();

	const kvm_mp_state state {
		.mp_state = KVM_MP_STATE_RUNNABLE
	};
	if (ioctl(this->fd, KVM_SET_MP_STATE, &state) < 0) {
		Machine::machine_exception("KVM_SET_MP_STATE failed");
	}

	/* Assign CPUID features to guest */
	if (ioctl(this->fd, KVM_SET_CPUID2, &kvm_cpuid) < 0) {
		Machine::machine_exception("KVM_SET_CPUID2 failed");
	}

	/* Extended control registers */
	if (ioctl(this->fd, KVM_SET_XCRS, &master_xregs) < 0) {
		Machine::machine_exception("KVM_SET_XCRS failed");
	}

	/* Enable SYSCALL/SYSRET instructions */
	struct {
		__u32 nmsrs; /* number of msrs in entries */
		__u32 pad = 0;

		struct kvm_msr_entry entries[2];
	} msrs;
	msrs.nmsrs = 2;
	msrs.entries[0].index = AMD64_MSR_STAR;
	msrs.entries[1].index = AMD64_MSR_LSTAR;
	msrs.entries[0].data  = (0x8LL << 32) | (0x1BLL << 48);
	msrs.entries[1].data  = interrupt_header().translated_vm_syscall(memory);

	if (ioctl(this->fd, KVM_SET_MSRS, &msrs) < (int)msrs.nmsrs) {
		Machine::machine_exception("KVM_SET_MSRS: failed to set STAR/LSTAR");
	}

	auto& sregs = this->get_special_registers();
	/* XXX: Is this correct? */
	sregs = machine.vcpu.get_special_registers();
	sregs.tr.base = memory.physbase + TSS_SMP_ADDR + (id - 1) * 104; /* AMD64_TSS */
	sregs.gs.base = this->vcpu_table_addr();
	/* XXX: Is this correct? */
	sregs.cr3 = memory.page_tables;
	sregs.cr0 &= ~CR0_WP; // XXX: Fix me!
	this->set_special_registers(sregs);
}

void vCPU::deinit()
{
	if (this->fd > 0) {
		close(this->fd);
	}
	/* A never-run lazy fork has nothing to unmap. Never unmap anywhere else
	   than here: munmap fires an mmu-notifier invalidation to every VM
	   registered in this address space. */
	if (kvm_run != nullptr) {
		munmap(kvm_run, vcpu_mmap_size);
	}
	delete (ShadowRegisters *)this->m_shadow_regs;
	this->m_shadow_regs = nullptr;

	timer_delete(this->timer_id);
}

vCPU::~vCPU()
{
	delete (ShadowRegisters *)this->m_shadow_regs;
}

const tinykvm_x86regs& vCPU::registers() const
{
	return *(tinykvm_x86regs *)this->m_regs;
}
tinykvm_x86regs& vCPU::registers()
{
	return *(tinykvm_x86regs *)this->m_regs;
}
void vCPU::set_registers(const struct tinykvm_x86regs& regs)
{
	if (LIKELY(this->kvm_run != nullptr))
		this->kvm_run->kvm_dirty_regs |= KVM_SYNC_X86_REGS;
	else
		this->m_shadow_dirty_regs |= KVM_SYNC_X86_REGS;
	auto* src_regs = (struct kvm_regs *) &regs;
	auto* dest_regs = this->m_regs;
	/* Only assign if there is a mismatch. */
	if (src_regs != dest_regs)
		*dest_regs = *src_regs;
}
tinykvm_fpuregs vCPU::fpu_registers() const
{
	struct tinykvm_fpuregs regs;
	if (ioctl(this->fd, KVM_GET_FPU, &regs) < 0) {
		Machine::machine_exception("KVM_GET_FPU failed");
	}
	return regs;
}
void vCPU::set_fpu_registers(const struct tinykvm_fpuregs& regs)
{
	if (ioctl(this->fd, KVM_SET_FPU, &regs) < 0) {
		Machine::machine_exception("KVM_SET_FPU failed");
	}
}
const kvm_sregs& vCPU::get_special_registers() const
{
#ifndef TINYKVM_USE_SYNCED_SREGS
	if (ioctl(this->fd, KVM_GET_SREGS, this->m_sregs) < 0) {
		Machine::machine_exception("KVM_GET_SREGS failed");
	}
#endif
	return *this->m_sregs;
}
kvm_sregs& vCPU::get_special_registers()
{
#ifndef TINYKVM_USE_SYNCED_SREGS
	if (ioctl(this->fd, KVM_GET_SREGS, this->m_sregs) < 0) {
		Machine::machine_exception("KVM_GET_SREGS failed");
	}
#endif
	return *this->m_sregs;
}
void vCPU::set_special_registers(const kvm_sregs& sregs)
{
#ifdef TINYKVM_USE_SYNCED_SREGS
	if (LIKELY(this->kvm_run != nullptr))
		this->kvm_run->kvm_dirty_regs |= KVM_SYNC_X86_SREGS;
	else
		this->m_shadow_dirty_regs |= KVM_SYNC_X86_SREGS;

	auto* dest_regs = this->m_sregs;
	/* Only assign if there is a mismatch. */
	if (dest_regs != &sregs)
		*dest_regs = sregs;
#else
	if (ioctl(this->fd, KVM_SET_SREGS, &sregs) < 0) {
		Machine::machine_exception("KVM_SET_SREGS failed");
	}
#endif
}

std::string_view vCPU::io_data() const
{
	char *p = (char *) kvm_run;
	return {&p[kvm_run->io.data_offset], kvm_run->io.size};
}

void Machine::setup_long_mode(const MachineOptions& options)
{
	(void)options;
	const auto physbase = this->memory.physbase;

	setup_amd64_exceptions(
		physbase + INTR_ASM_ADDR,
		memory.at(physbase + IDT_ADDR), memory.at(physbase + INTR_ASM_ADDR));
	setup_amd64_segments(
		physbase + GDT_ADDR,
		memory.at(physbase + GDT_ADDR));
	setup_amd64_tss(memory);
	setup_amd64_tss_smp(memory);
	/* Userspace entry/exit code */
	setup_vm64_usercode(
		memory.at(physbase + USER_ASM_ADDR));

	/* Live-patch the interrupt assembly to support remote memory */
	uint64_t* iasm = memory.page_at(physbase + INTR_ASM_ADDR);
	iasm_header& hdr = *(iasm_header*)iasm;
	hdr.vm64_remote_return_addr =
		usercode_header().translated_vm_remote_disconnect(memory);

	this->m_kernel_end = setup_amd64_paging(memory, m_binary, options.remappings,
		options.split_hugepages, options.split_all_hugepages_during_loading);
}

std::pair<__u64, __u64> Machine::get_fsgs() const
{
	const auto& sregs = vcpu.get_special_registers();

	return {sregs.fs.base, sregs.gs.base};
}
void Machine::set_tls_base(__u64 baseaddr)
{
	auto& sregs = vcpu.get_special_registers();

	sregs.fs.base = baseaddr;

	vcpu.set_special_registers(sregs);
}

uint64_t vCPU::vcpu_table_addr() const noexcept
{
	return usercode_header().translated_vm_cpuid(machine().memory)
		+ sizeof(PerVCPUTable) * this->guest_cpu_index;
}
void vCPU::set_vcpu_table_at(unsigned index, int value)
{
	if (index >= 4)
		throw MachineException("Invalid vCPU table index", index);
	if (UNLIKELY(machine().is_pooled())) {
		/* The per-vCPU table lives in the shared master page, and every
		   pooled member is guest CPU 0: a write here hits every sibling. */
		throw MachineException("A pooled VM group member cannot write the vCPU table", index);
	}
	/* The per-vCPU data area is in the usercode area. */
	const auto addr = this->vcpu_table_addr() + index * 4;
	auto* page = machine().main_memory().get_userpage_at(addr & ~0xFFFL);
	if (page != nullptr) {
		auto offset = addr & 0xFFFL;
		*((int *)&page[offset]) = value;
	}
}

void Machine::prepare_copy_on_write(size_t max_work_mem,
	uint64_t shared_memory_boundary, bool split_accessed_hugepages)
{
	this->m_prepped = true;

	/* Snapshot FPU state to userspace while this master's vCPU fd is still
	   ours to ioctl. Fork construction and fork reset consume the snapshot via
	   prepared_fpu_registers(), which keeps both usable from a process that
	   inherited this master over fork(). The master is frozen hereafter, so the
	   snapshot stays equal to a live KVM_GET_FPU. */
	this->m_prepared_fpu_regs = this->fpu_registers();

	/* Make each writable page read-only, causing page fault.
	   any page after the @shared_memory_boundary is untouched,
	   effectively turning it into a shared memory area for all. */
	if (shared_memory_boundary == 0)
		shared_memory_boundary = UINT64_MAX;

	// Visualizing the page tables after makecow should show that all
	// relevant user-writable pages have been made read-only and cloneable
	//print_pagetables(this->memory);

	/* Make this machine runnable again using itself
	   as the master VM. TODO: Enable hugepages for CoW mode? */
	memory.banks.set_max_pages(max_work_mem / PAGE_SIZE, 0u);
	/* Without working memory we will not be able to make
	   this master VM usable after prepare_copy_on_write. */
	if (max_work_mem == 0) {
		/* Zero working memory indicates the unlocking scheme
		   is now pointless/finished, which means we can
		   just disabled it. Also, we can use it to separate
		   unlocking from forking, and prevent forking when
		   it's not really going to work (main_memory_writes). */
		memory.main_memory_writes = false;
		/* If there are previously banked pages, we need to
		   flatten them into the main memory. */
		/// XXX: Implement memory flattening
		memory.page_tables = memory.physbase + PT_ADDR;
		struct kvm_sregs sregs = this->get_special_registers();

		/* Page table entry will be cloned at the start */
		sregs.cr3 = memory.page_tables;
		sregs.cr0 |= CR0_WP;

		vcpu.set_special_registers(sregs);
		this->enter_usermode();

		foreach_page_makecow(this->memory, kernel_end_address(), shared_memory_boundary, split_accessed_hugepages);
		return;
	}

	/* This call makes this VM usable after making every page in the
	   page tables read-only, enabling memory through page faults. */
	foreach_page_makecow(this->memory, kernel_end_address(), shared_memory_boundary, split_accessed_hugepages);
	this->setup_cow_mode(this);
}
void Machine::setup_cow_mode(const Machine* other)
{
	/* Clone master PML4 page. We use the fixed PT_ADDR
	   directly in order to avoid duplicating the memory banked
	   page tables that allow the master VM to execute code
	   separately from its forks, while sharing a master page table. */
	auto pml4 = memory.new_page();
	tinykvm::page_duplicate(pml4.pmem, other->memory.page_at(other->memory.physbase + PT_ADDR));
	memory.page_tables = pml4.addr;

	/* Zero a new page for IST stack */
	// XXX: This is not strictly necessary as we can
	// hand-write a custom handler that only triggers on actual writes?
	// The problem is that in order to handle interrupts, we need these
	// pages to already be there. It would have been much easier with
	// stackless interrupts, to be honest. Something to think about?
	// XXX: In theory we can avoid initializing one of these pages
	// until the guest asks for a certain level of concurrency.
	WritablePageOptions ist_opts;
	ist_opts.allow_dirty = true;
	writable_page_at(memory, memory.physbase + IST_ADDR, PDE64_RW | PDE64_NX, ist_opts);

	struct kvm_sregs sregs = other->get_special_registers();

	/* Page table entry will be cloned at the start */
	sregs.cr3 = memory.page_tables;
	sregs.cr0 &= ~CR0_WP; // XXX: Fix me!

	vcpu.set_special_registers(sregs);
	//print_pagetables(this->memory);
#if 0
	/* It shouldn't be identity-mapped anymore */
	assert(translate(memory.physbase + IST_ADDR) != IST_ADDR);
	//printf("Translate 0x%lX => 0x%lX\n", IST_ADDR, translate(IST_ADDR));
	page_at(memory, memory.physbase + IST_ADDR, [] (auto, auto& entry, auto) {
		assert(entry & (PDE64_PRESENT | PDE64_RW | PDE64_NX));
		(void) entry;
	});
#endif


	/* This blocking message passes the new special registers
	   to every existing vCPU used in multi-processing. In the
	   future there may be more stuff we need to pass onto the
	   vCPUs, but for now we only need updated sregs. */
	if (m_smp != nullptr) {
		smp_vcpu_broadcast([sregs] (auto& cpu) {
			cpu.set_special_registers(sregs);
		});
	}
}
void Machine::make_unpresented_with_callback(vMemory::page_presentable_callback_t on_presentable)
{
	#define PDE64_PRESENTABLE address_t(1ul << 10)
	this->memory.on_page_presentable = std::move(on_presentable);
	foreach_page(this->memory, [this] (auto addr, auto& entry, auto) {
		if (addr >= this->m_kernel_end && (entry & PDE64_PRESENT) != 0) {
			entry &= ~PDE64_PRESENT;
			entry |= PDE64_PRESENTABLE;
		}
	}, false);
}
void Machine::restore_unpresented_pages()
{
	foreach_page(this->memory, [] (auto addr, auto& entry, auto) {
		if (entry & PDE64_PRESENTABLE) {
			entry |= PDE64_PRESENT;
			entry &= ~PDE64_PRESENTABLE;
		}
	}, false, true);
}

void Machine::print_pagetables() const {
	tinykvm::print_pagetables(this->memory);
}
void Machine::print_exception_handlers() const
{
	const auto& sregs = vcpu.get_special_registers();
	tinykvm::print_exception_handlers(memory.at(sregs.idt.base));
}

bool vCPU::is_usermode() const
{
	auto& sregs = this->get_special_registers();
	/* If we are in user-mode ... */
	return (sregs.cs.dpl == 3);
}
bool vCPU::is_kernelmode() const
{
	auto& sregs = this->get_special_registers();
	/* If we are in kernel-mode ... */
	return (sregs.cs.dpl == 0);
}
void vCPU::enter_usermode()
{
	// WARNING: This shortcut *requires* KVM_SYNC_X86_SREGS
	auto& sregs = this->get_special_registers();
	/* If we are in kernel-mode ... */
	if (UNLIKELY(sregs.cs.dpl == 0)) {
		/* Directly enter user-mode. */
		sregs.cs.selector = 0x2B;
		sregs.cs.dpl = 3;
		sregs.ss.selector = 0x23;
		sregs.ss.dpl = 3;
		this->set_special_registers(sregs);
	}
}

void Machine::enter_usermode()
{
	vcpu.enter_usermode();
}

Machine::address_t Machine::entry_address() const noexcept {
	return usercode_header().translated_vm_entry(memory);
}
Machine::address_t Machine::preserving_entry_address() const noexcept {
	return usercode_header().translated_vm_preserving_entry(memory);
}
Machine::address_t Machine::exit_address() const noexcept {
	return usercode_header().translated_vm_rexit(memory);
}

} // tinykvm
