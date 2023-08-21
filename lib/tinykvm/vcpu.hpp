#pragma once
#include "common.hpp"
#include "forward.hpp"

namespace tinykvm
{
    struct Machine;

    struct vCPU
    {
        void init(int id, Machine &);
        void smp_init(int id, Machine &);
        void deinit();
        tinykvm_x86regs& registers();
        const tinykvm_x86regs& registers() const;
        void set_registers(const struct tinykvm_x86regs &);
        tinykvm_fpuregs fpu_registers() const;
        const struct kvm_sregs& get_special_registers() const;
        struct kvm_sregs& get_special_registers();
        void set_special_registers(const struct kvm_sregs &);

        void run(uint32_t tix);
        long run_once();
        void stop() { stopped = true; }
        void disable_timer();
        std::string_view io_data() const;

        void print_registers() const;
        void handle_exception(uint8_t intr);
        void decrement_smp_count();

        auto &machine() { return *m_machine; }
        const auto &machine() const { return *m_machine; }

        int fd = 0;
        int cpu_id = 0;
        bool stopped = true;
        uint32_t timer_ticks = 0;
        void* timer_id = nullptr;

    private:
        struct kvm_run* kvm_run = nullptr;
        Machine* m_machine = nullptr;
		void handle_remote_call(uint64_t addr);
    };

} // namespace tinykvm
