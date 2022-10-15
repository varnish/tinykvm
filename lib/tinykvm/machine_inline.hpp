/* APIC timer counter calculations for execution timeouts */
constexpr inline float ticks_to_seconds(uint32_t ticks) {
	return ticks / 1000.0;
}
constexpr inline uint32_t to_ticks(float seconds) {
	const float val = seconds * 1000.0;
	return (val < (float)UINT32_MAX) ? (uint32_t)val : UINT32_MAX;
}

inline void Machine::stop(bool s)
{
	vcpu.stopped = s;
}

inline void Machine::system_call(vCPU& cpu, unsigned idx)
{
	if (idx < m_syscalls.size()) {
		const auto handler = m_syscalls[idx];
		if (handler != nullptr) {
			handler(cpu);
			return;
		}
	}
	m_unhandled_syscall(cpu, idx);
}

inline tinykvm_x86regs& Machine::registers() {
	return vcpu.registers();
}
inline const tinykvm_x86regs& Machine::registers() const {
	return vcpu.registers();
}
inline void Machine::set_registers(const tinykvm_x86regs& regs) {
	vcpu.set_registers(regs);
}
inline tinykvm_fpuregs Machine::fpu_registers() const {
	return vcpu.fpu_registers();
}
inline const struct kvm_sregs& Machine::get_special_registers() const {
	return vcpu.get_special_registers();
}
inline void Machine::set_special_registers(const struct kvm_sregs& sregs) {
	vcpu.set_special_registers(sregs);
}


template <typename... Args> inline constexpr
void Machine::setup_call(tinykvm_x86regs& regs,
	uint64_t addr, uint64_t rsp,
	Args&&... args)
{
	regs = {};
	/* Set IOPL=3 to allow I/O instructions */
	regs.rflags = 2 | (3 << 12);
	regs.r15 = addr;
	regs.rip = this->entry_address();
	regs.rsp = rsp;
	[[maybe_unused]] unsigned iargs = 0;
	([&] {
		auto& reg = [iargs, &regs] () mutable -> unsigned long long& {
			if (iargs == 0)
				return regs.rdi;
			else if (iargs == 1)
				return regs.rsi;
			else if (iargs == 2)
				return regs.rdx;
			else if (iargs == 3)
				return regs.rcx;
			else if (iargs == 4)
				return regs.r8;
			else if (iargs == 5)
				return regs.r9;
			throw MachineException("Too many vmcall arguments");
		}();
		if constexpr (std::is_integral_v<Args>) {
			reg = args;
			iargs ++;
		} else if constexpr (is_stdstring<Args>::value) {
			reg = stack_push(regs.rsp, args.c_str(), args.size()+1);
			iargs ++;
		} else if constexpr (is_string<Args>::value) {
			reg = stack_push_cstr(regs.rsp, args);
			iargs ++;
		} else if constexpr (std::is_pod_v<std::remove_reference<Args>>) {
			reg = stack_push(regs.rsp, args);
			iargs ++;
		} else {
			throw MachineException("Unsupported vmcall argument");
		}
	}(), ...);
	/* Re-align stack for SSE */
	regs.rsp &= ~(uint64_t) 0xF;
	/* Push return value last */
	stack_push<uint64_t> (regs.rsp, exit_address());
}

inline void Machine::setup_clone(tinykvm_x86regs& regs, address_t stack)
{
	/* Set IOPL=3 to allow I/O instructions */
	regs.rflags = 2 | (3 << 12);
	regs.r15 = regs.rip;
	regs.rip = this->entry_address();
	regs.rbp = 0;
	regs.rsp = stack;
}

template <typename... Args> inline constexpr
void Machine::vmcall(uint64_t addr, Args&&... args)
{
	tinykvm_x86regs regs;
	this->setup_call(regs, addr, this->stack_address(), std::forward<Args> (args)...);
	vcpu.set_registers(regs);
	this->run();
}

template <typename... Args> inline
void Machine::vmcall(const char* function, Args&&... args)
{
	auto address = address_of(function);
	vmcall(address, std::forward<Args> (args)...);
}

template <typename... Args> inline constexpr
void Machine::timed_vmcall(uint64_t addr, float timeout, Args&&... args)
{
	tinykvm_x86regs regs;
	this->setup_call(regs, addr,
		this->stack_address(), std::forward<Args> (args)...);
	vcpu.set_registers(regs);
	this->run(timeout);
}

template <typename... Args> inline constexpr
void Machine::timed_vmcall_stack(uint64_t addr, uint64_t stk, float timeout, Args&&... args)
{
	tinykvm_x86regs regs;
	this->setup_call(regs, addr, stk, std::forward<Args> (args)...);
	vcpu.set_registers(regs);
	this->run(timeout);
}

template <typename... Args> inline constexpr
void Machine::timed_reentry(uint64_t addr, float timeout, Args&&... args)
{
	tinykvm_x86regs regs;
	this->setup_call(regs, addr,
		this->stack_address(), std::forward<Args> (args)...);
	regs.rip = this->reentry_address();
	vcpu.set_registers(regs);
	this->run(timeout);
}

template <typename... Args> inline constexpr
void Machine::timed_reentry_stack(uint64_t addr, uint64_t stk, float timeout, Args&&... args)
{
	tinykvm_x86regs regs;
	this->setup_call(regs, addr, stk, std::forward<Args> (args)...);
	regs.rip = this->reentry_address();
	vcpu.set_registers(regs);
	this->run(timeout);
}

inline uint64_t Machine::stack_push(__u64& sp, const std::string& string)
{
	return stack_push(sp, string.data(), string.size()+1); /* zero */
}
template <typename T>
inline uint64_t Machine::stack_push(__u64& sp, const T& type)
{
	return stack_push(sp, &type, sizeof(T));
}

inline std::string_view Machine::memory_at(uint64_t a, size_t s) const
{
	return memory.view(a, s);
}
template <typename T>
inline T* Machine::rw_memory_at(uint64_t a, size_t s)
{
	return (T*) memory.safely_at(a, s);
}
inline bool Machine::memory_safe_at(uint64_t a, size_t s) const
{
	return memory.safely_within(a, s);
}
