
inline void Machine::stop()
{
	this->stopped = true;
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

inline tinykvm_x86regs Machine::registers() const
{
	return vcpu.registers();
}

template <typename... Args> inline constexpr
tinykvm_x86regs Machine::setup_call(uint64_t addr, Args&&... args)
{
	struct tinykvm_x86regs regs {0};
	/* Set IOPL=3 to allow I/O instructions */
	regs.rflags = 2 | (3 << 12);
	regs.rip = addr;
	/* Create stack at top of 2 MB page and grow down */
	regs.rsp = 0x200000;
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
			/* TODO: stack push */
		} else {

		}
	}(), ...);
	return regs;
}

template <typename... Args> inline constexpr
long Machine::vmcall(uint64_t addr, Args&&... args)
{
	auto regs = this->setup_call(addr, std::forward<Args> (args)...);
	vcpu.assign_registers(regs);
	return this->run();
}
