#include "paging.hpp"

#include "../machine.hpp"
#include "memory_layout.hpp"
#include <array>
#include <cerrno>
#include <cstring>
#include <linux/kvm.h>
#include <sys/ioctl.h>

namespace tinykvm {
namespace {

static constexpr uint64_t DESC_VALID = 1ULL << 0;
static constexpr uint64_t DESC_TABLE = 1ULL << 1;
static constexpr uint64_t DESC_AF = 1ULL << 10;
static constexpr uint64_t DESC_SH_INNER = 3ULL << 8;
static constexpr uint64_t ATTR_NORMAL = 0ULL << 2;
static constexpr uint64_t ATTR_DEVICE = 1ULL << 2;
static constexpr uint64_t L1_BLOCK_SIZE = 1ULL << 30;
static constexpr uint64_t L2_BLOCK_SIZE = 1ULL << 21;

static uint64_t sys_reg_id(unsigned op0, unsigned op1, unsigned crn, unsigned crm, unsigned op2)
{
	return KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM64_SYSREG
		| (((uint64_t)op0 << KVM_REG_ARM64_SYSREG_OP0_SHIFT) & KVM_REG_ARM64_SYSREG_OP0_MASK)
		| (((uint64_t)op1 << KVM_REG_ARM64_SYSREG_OP1_SHIFT) & KVM_REG_ARM64_SYSREG_OP1_MASK)
		| (((uint64_t)crn << KVM_REG_ARM64_SYSREG_CRN_SHIFT) & KVM_REG_ARM64_SYSREG_CRN_MASK)
		| (((uint64_t)crm << KVM_REG_ARM64_SYSREG_CRM_SHIFT) & KVM_REG_ARM64_SYSREG_CRM_MASK)
		| (((uint64_t)op2 << KVM_REG_ARM64_SYSREG_OP2_SHIFT) & KVM_REG_ARM64_SYSREG_OP2_MASK);
}

static void set_sysreg(vCPU& cpu, uint64_t id, uint64_t value)
{
	struct kvm_one_reg reg {
		.id = id,
		.addr = (uint64_t)&value,
	};
	if (ioctl(cpu.fd, KVM_SET_ONE_REG, &reg) < 0) {
		throw MachineException("KVM_SET_ONE_REG sysreg failed", errno);
	}
}

static uint64_t table_desc(uint64_t addr)
{
	return (addr & ~0xFFFULL) | DESC_TABLE | DESC_VALID;
}

static uint64_t block_desc(uint64_t addr, uint64_t attr)
{
	return (addr & ~0x1FFFFFULL) | attr | DESC_AF | DESC_SH_INNER | DESC_VALID;
}

static void install_vectors(Machine& machine)
{
	std::array<uint32_t, 2048 / sizeof(uint32_t)> vectors {};
	const uint32_t fatal[] {
		0xd2be0009, // movz x9, #0xf000, lsl #16
		0xf910013f, // str xzr, [x9, #0x2000 + vector]
		0x14000000, // b .
	};
	for (size_t off = 0; off < vectors.size(); off += 0x80 / sizeof(uint32_t)) {
		std::memcpy(&vectors[off], fatal, sizeof(fatal));
		const uint32_t byte_offset = off * sizeof(uint32_t);
		vectors[off + 1] = 0xf900013f | (((0x2000 + byte_offset) / 8) << 10);
	}

	const uint32_t sync_current_el_spx[] {
		0xd518d089, // msr tpidr_el1, x9
		0xd2be0009, // movz x9, #0xf000, lsl #16
		0xf9080128, // str x8, [x9, #0x1000]
		0xd538d089, // mrs x9, tpidr_el1
		0xd69f03e0, // eret
	};
	std::memcpy(&vectors[0x200 / sizeof(uint32_t)],
		sync_current_el_spx, sizeof(sync_current_el_spx));

	const uint32_t return_stop[] {
		0xd2be0009, // movz x9, #0xf000, lsl #16
		0xf900013f, // str xzr, [x9]
	};
	std::memcpy(&vectors[(RET_STOP_ADDR - VECTORS_ADDR) / sizeof(uint32_t)],
		return_stop, sizeof(return_stop));

	std::memcpy(machine.unsafe_memory_at(VECTORS_ADDR, vectors.size() * sizeof(uint32_t)),
		vectors.data(), vectors.size() * sizeof(uint32_t));
}

static void install_identity_map(Machine& machine)
{
	std::array<uint64_t, 512> l1 {};
	std::array<uint64_t, 512> l2 {};
	std::array<uint64_t, 512> l2_trap {};

	l1[0] = table_desc(PT_ADDR + 0x1000);
	for (size_t i = 1; i < 4; i++) {
		l1[i] = block_desc(i * L1_BLOCK_SIZE, ATTR_NORMAL);
	}
	l1[ARM64_STOP_MMIO_ADDR / L1_BLOCK_SIZE] = table_desc(PT_ADDR + 0x2000);

	for (size_t i = 0; i < l2.size(); i++) {
		const uint64_t addr = i * L2_BLOCK_SIZE;
		l2[i] = block_desc(addr, ATTR_NORMAL);
	}
	const uint64_t trap_l1_base = (ARM64_STOP_MMIO_ADDR / L1_BLOCK_SIZE) * L1_BLOCK_SIZE;
	for (size_t i = 0; i < l2_trap.size(); i++) {
		const uint64_t addr = trap_l1_base + i * L2_BLOCK_SIZE;
		const bool is_trap_block =
			addr <= ARM64_STOP_MMIO_ADDR && ARM64_STOP_MMIO_ADDR < addr + L2_BLOCK_SIZE;
		l2_trap[i] = block_desc(addr, is_trap_block ? ATTR_DEVICE : ATTR_NORMAL);
	}

	std::memcpy(machine.unsafe_memory_at(PT_ADDR, l1.size() * sizeof(uint64_t)),
		l1.data(), l1.size() * sizeof(uint64_t));
	std::memcpy(machine.unsafe_memory_at(PT_ADDR + 0x1000, l2.size() * sizeof(uint64_t)),
		l2.data(), l2.size() * sizeof(uint64_t));
	std::memcpy(machine.unsafe_memory_at(PT_ADDR + 0x2000, l2_trap.size() * sizeof(uint64_t)),
		l2_trap.data(), l2_trap.size() * sizeof(uint64_t));
}

} // namespace

void arm64_setup_el1_mmu(Machine& machine, vCPU& cpu)
{
	install_vectors(machine);
	install_identity_map(machine);

	const uint64_t MAIR_EL1 = sys_reg_id(3, 0, 10, 2, 0);
	const uint64_t TCR_EL1 = sys_reg_id(3, 0, 2, 0, 2);
	const uint64_t TTBR0_EL1 = sys_reg_id(3, 0, 2, 0, 0);
	const uint64_t SCTLR_EL1 = sys_reg_id(3, 0, 1, 0, 0);
	const uint64_t CPACR_EL1 = sys_reg_id(3, 0, 1, 0, 2);
	const uint64_t VBAR_EL1 = sys_reg_id(3, 0, 12, 0, 0);

	set_sysreg(cpu, MAIR_EL1, 0x00000000000000FFULL);
	set_sysreg(cpu, TCR_EL1, 32ULL | (1ULL << 8) | (1ULL << 10) | (3ULL << 12));
	set_sysreg(cpu, TTBR0_EL1, PT_ADDR);
	set_sysreg(cpu, VBAR_EL1, VECTORS_ADDR);
	set_sysreg(cpu, CPACR_EL1, 3ULL << 20);
	set_sysreg(cpu, SCTLR_EL1,
		(1ULL << 0) | (1ULL << 2) | (1ULL << 12) |
		(1ULL << 11) | (1ULL << 20) | (1ULL << 22) |
		(1ULL << 28) | (1ULL << 29));
}

} // namespace tinykvm
