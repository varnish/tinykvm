
inline void Machine::stop(bool s)
{
	this->m_stopped = s;
}

inline void Machine::system_call(unsigned idx)
{
	if (idx < m_syscalls.size()) {
		const auto handler = m_syscalls[idx];
		if (handler != nullptr) {
			handler(*this);
			return;
		}
	}
	m_unhandled_syscall(*this, idx);
}

inline tinykvm_x86regs Machine::registers() const {
	return vcpu.registers();
}
inline void Machine::set_registers(const tinykvm_x86regs& regs) {
	vcpu.assign_registers(regs);
}

template <typename... Args> inline constexpr
tinykvm_x86regs Machine::setup_call(uint64_t addr, Args&&... args)
{
	struct tinykvm_x86regs regs {0};
	/* Set IOPL=3 to allow I/O instructions */
	regs.rflags = 2 | (3 << 12);
	regs.rip = addr;
	regs.rsp = this->stack_address();
	[[maybe_unused]] unsigned iargs = 0;
	([&] {
		if constexpr (std::is_integral_v<Args>) {
			if (iargs == 0)
				regs.rdi = args;
			else if (iargs == 1)
				regs.rsi = args;
			else if (iargs == 2)
				regs.rdx = args;
			else if (iargs == 3)
				regs.rcx = args;
			else if (iargs == 4)
				regs.r8 = args;
			else if (iargs == 5)
				regs.r9 = args;
			else {
				/* TODO: stack push */
			}
			iargs ++;
		} else if constexpr (std::is_pod_v<std::remove_reference<Args>>) {
			if (iargs == 0)
				regs.rdi = stack_push(regs.rsp, args);
			else if (iargs == 1)
				regs.rsi = stack_push(regs.rsp, args);
			else if (iargs == 2)
				regs.rdx = stack_push(regs.rsp, args);
			else if (iargs == 3)
				regs.rcx = stack_push(regs.rsp, args);
			else if (iargs == 4)
				regs.r8 = stack_push(regs.rsp, args);
			else if (iargs == 5)
				regs.r9 = stack_push(regs.rsp, args);
			else {
				/* TODO: stack push */
			}
			iargs ++;
		} else {

		}
	}(), ...);
	/* Re-align stack for SSE */
	regs.rsp &= ~0xF;
	/* Push return value last */
	stack_push<uint64_t> (regs.rsp, this->m_exit_address);
	return regs;
}

template <typename... Args> inline constexpr
long Machine::vmcall(uint64_t addr, Args&&... args)
{
	auto regs = this->setup_call(addr, std::forward<Args> (args)...);
	vcpu.assign_registers(regs);
	return this->run();
}

template <typename... Args> inline
long Machine::vmcall(const char* function, Args&&... args)
{
	auto address = address_of(function);
	return vmcall(address, std::forward<Args> (args)...);
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
