#include <tinykvm/machine.hpp>
#include <cstring>
#include <cstdio>
#include "assert.hpp"
#include "load_file.hpp"

#include <tinykvm/rsp_client.hpp>
#define GUEST_MEMORY   0x10000000  /* 256MB memory */
#define GUEST_WORK_MEM 2*1024*1024 /* 2MB working memory */

std::vector<uint8_t> load_file(const std::string& filename);
static void test_master_vm(tinykvm::Machine&);
static void test_forking(tinykvm::Machine&);
static void test_copy_on_write(tinykvm::Machine&);

static void verify_exists(tinykvm::Machine& vm, const char* name)
{
	if (vm.address_of(name) == 0x0) {
		fprintf(stderr, "Error: '%s' is missing\n", name);
		exit(1);
	}
}

int main(int argc, char** argv)
{
	if (argc < 2) {
		fprintf(stderr, "Missing argument: 64-bit ELF binary\n");
		exit(1);
	}
	const auto binary = load_file(argv[1]);

	tinykvm::Machine::init();
	extern void setup_kvm_system_calls();
	setup_kvm_system_calls();

	/* Setup */
	const tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = GUEST_WORK_MEM,
		.verbose_loader = false,
	};
	tinykvm::Machine master_vm {binary, options};
	master_vm.setup_linux(
		{"kvmtest", "Hello World!\n"},
		{"LC_TYPE=C", "LC_ALL=C", "USER=root"});
	const auto rsp = master_vm.stack_address();

	verify_exists(master_vm, "test_return");
	verify_exists(master_vm, "test_ud2");
	verify_exists(master_vm, "test_read");
	verify_exists(master_vm, "test_copy_on_write");
	verify_exists(master_vm, "write_value");
	verify_exists(master_vm, "test_is_value");
	verify_exists(master_vm, "test_loop");

	/* Remote debugger session */
	if (getenv("DEBUG"))
	{
		auto* vm = &master_vm;
		tinykvm::tinykvm_x86regs regs;

		if (getenv("VMCALL")) {
			master_vm.run();
		}
		if (getenv("FORK")) {
			master_vm.prepare_copy_on_write();
			vm = new tinykvm::Machine {master_vm, options};
			vm->setup_call(regs, vm->address_of("test_return"), rsp);
			vm->set_registers(regs);
		} else {
			master_vm.setup_call(regs, master_vm.address_of("test_return"), rsp);
			master_vm.set_registers(regs);
		}

		tinykvm::RSP server {*vm, 2159};
		printf("Waiting for connection localhost:2159...\n");
		auto client = server.accept();
		if (client != nullptr) {
			/* Debugging session of _start -> main() */
			printf("Connected\n");
			try {
				//client->set_verbose(true);
				while (client->process_one());
			} catch (const tinykvm::MachineException& e) {
				printf("EXCEPTION %s: %lu\n", e.what(), e.data());
				vm->print_registers();
			}
		} else {
			/* Resume execution normally */
			vm->run();
		}
		/* Exit after debugging */
		return 0;
	}
	else {
		/* Normal execution of _start -> main() */
		master_vm.run();
	}
	/* Verify VM exit status */
	auto regs = master_vm.registers();
	KASSERT(regs.rdi == 666);
	printf("*** Program startup OK\n");

	printf("--- Beginning Master VM tests ---\n");
	test_master_vm(master_vm);
	printf("*** Master VM OK\n");

	/* Make the master VM able to mass-produce copies.
	   Make room for 16 CoW-pages enabling usage afterwards. */
	master_vm.prepare_copy_on_write(65536);

	printf("--- Beginning CoW VM master tests ---\n");
	test_master_vm(master_vm);
	printf("*** VM CoW master tests OK\n");

	printf("--- Beginning VM fork tests ---\n");
	for (size_t i = 0; i < 100; i++) {
		test_forking(master_vm);
	}
	printf("*** VM forking OK\n");

	printf("--- Beginning VM copy-on-write tests ---\n");
	for (size_t i = 0; i < 100; i++) {
		test_copy_on_write(master_vm);
	}
	printf("*** VM copy-on-write OK\n");

	printf("Nice! Tests passed.\n");
	return 0;
}

void test_master_vm(tinykvm::Machine& vm)
{
	/* Call into master VM */
	vm.vmcall("test_return");
	KASSERT(vm.return_value() == 666);
	try {
		vm.vmcall("test_ud2");
	} catch (const tinykvm::MachineException& me) {
		/* Allow invalid opcode exception */
		KASSERT(me.data() == 6);
	}
	vm.vmcall("test_syscall");
	KASSERT(vm.return_value() == 555);
	vm.vmcall("test_read");
	KASSERT(vm.return_value() == 200);
	vm.vmcall("test_malloc");
	KASSERT(vm.return_value() != 0);

	printf("--- Testing endless loop ---\n");
	/* To test endless loops we rely on the Machine to
	   throw an exact exception, namely tinykvm::MachineTimeoutException.
	   To make sure this happens we throw another exception right
	   after the timed_vmcall, which throws a runtime_error instead.
	   The program will fail with an uncaught exception if the timeout
	   doesn't happen naturally after 1 second. */
	try {
		const auto addr = vm.address_of("test_loop");
		vm.timed_vmcall(addr, 1.0);
		throw std::runtime_error("Timeout exception failed");
	} catch (const tinykvm::MachineTimeoutException& me) {
		KASSERT(me.seconds() == 1.0);
		printf("*** Timeout OK\n");
	}

	printf("--- Testing multi-processing ---\n");
	//vm.print_exception_handlers();
	auto tr_addr = vm.address_of("test_read");
	auto tret_addr = vm.address_of("test_return");
	vm.timed_smpcall(20, 0x200000, 0x10000, tr_addr, 2.0f);
	auto results = vm.gather_return_values();
	for (const auto res : results) {
		KASSERT(res == 200);
	}
	/* Run SMP vCPUs a 100 times */
	for (int i = 0; i < 100; i++) {
		vm.timed_smpcall(2, 0x200000, 0x10000, tret_addr, 2.0f);
	}
	/* Run test_read (200) */
	vm.timed_smpcall(8, 0x200000, 0x10000, tr_addr, 2.0f);
	/* Run test_return (666) */
	vm.timed_smpcall(8, 0x200000, 0x10000, tret_addr, 2.0f);
	results = vm.gather_return_values(8);
	for (const auto res : results) {
		KASSERT(res == 666);
	}
	printf("*** Multi-processing OK\n");
}

void test_forking(tinykvm::Machine& master_vm)
{
	/* Create VM fork */
	const tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = GUEST_WORK_MEM,
		.verbose_loader = false
	};
	tinykvm::Machine vm {master_vm, options};

	/* Call into VM */
	for (size_t i = 0; i < 20; i++)
	{
		vm.vmcall("test_return");
		KASSERT(vm.return_value() == 666);
		vm.set_printer([] (auto, size_t) {});
		try {
			vm.vmcall("test_ud2");
		} catch (const tinykvm::MachineException& me) {
			/* Allow invalid opcode exception */
			KASSERT(me.data() == 6);
			try {
				/* Retry exception */
				vm.run();
			} catch (const tinykvm::MachineException& me) {
				/* Allow invalid opcode exception */
				KASSERT(me.data() == 6);
			}
		}
		vm.set_printer();
		vm.vmcall("test_syscall");
		KASSERT(vm.return_value() == 555);
		vm.vmcall("test_read");
		KASSERT(vm.return_value() == 200);
		vm.vmcall("test_malloc");
		KASSERT(vm.return_value() != 0);
		static int run_once = 0;
		if (run_once++ == 0) try {
			const auto addr = vm.address_of("test_loop");
			vm.timed_vmcall(addr, 1.0);
			throw std::runtime_error("Timeout exception failed");
		} catch (const tinykvm::MachineTimeoutException& me) {
			KASSERT(me.seconds() == 1.0);
		}
	}

	/* Reset and call into VM */
	for (size_t i = 0; i < 20; i++)
	{
		vm.reset_to(master_vm, options);
		vm.vmcall("test_return");
		KASSERT(vm.return_value() == 666);
		vm.set_printer([] (auto, size_t) {});
		try {
			vm.vmcall("test_ud2");
		} catch (const tinykvm::MachineException& me) {
			/* Allow invalid opcode exception */
			KASSERT(me.data() == 6);
			try {
				/* Retry exception */
				vm.run();
			} catch (const tinykvm::MachineException& me) {
				/* Allow invalid opcode exception */
				KASSERT(me.data() == 6);
			}
		}
		vm.set_printer();
		vm.vmcall("test_syscall");
		KASSERT(vm.return_value() == 555);
		vm.vmcall("test_read");
		KASSERT(vm.return_value() == 200);
		vm.vmcall("test_malloc");
		KASSERT(vm.return_value() != 0);
		/* Timeouts take a second, but should result in exception. */
		static int run_once = 0;
		if (run_once++ == 0) try {
			printf("Testing forked execution timeout\n");
			const auto addr = vm.address_of("test_loop");
			vm.timed_vmcall(addr, 1.0);
			throw std::runtime_error("Timeout exception failed");
		} catch (const tinykvm::MachineTimeoutException& me) {
			KASSERT(me.seconds() == 1.0);
			printf("Forked execution timeout OK\n");
		}
	}
}

void test_copy_on_write(tinykvm::Machine& master_vm)
{
	const tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = GUEST_WORK_MEM,
		.verbose_loader = false
	};
	tinykvm::Machine vm {master_vm, options};

	for (size_t i = 0; i < 10; i++)
	{
		try {
			vm.reset_to(master_vm, options);
			vm.vmcall("test_copy_on_write");
			KASSERT(vm.return_value() == 666);
			vm.vmcall("test_malloc");
			KASSERT(vm.return_value() != 0);
			//vm.vmcall("test_expensive");
			//KASSERT(vm.return_value() != 0);

			vm.vmcall("write_value", 10 + i);
			KASSERT(vm.return_value() == 10 + i);
			vm.vmcall("test_is_value", 10 + i);
			KASSERT(vm.return_value() == 666);
		} catch (...) {
			vm.print_pagetables();
			vm.print_registers();
			fprintf(stderr, "first vm.reset_to(vm) failed\n");
			throw;
		}
		/* We have to acknowledge that the parent VM for 'vm'
		   falls out-of-scope here, which is dangerous, but
		   *must* be supported. */
	}
}
