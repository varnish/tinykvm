#include <tinykvm/machine.hpp>
#include <cstring>
#include <cstdio>
#include "assert.hpp"

#include <tinykvm/rsp_client.hpp>
#define GUEST_MEMORY 0x40000000  /* 1024MB memory */

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
		.verbose_loader = false
	};
	tinykvm::Machine master_vm {binary, options};
	master_vm.setup_linux(
		{"kvmtest", "Hello World!\n"},
		{"LC_TYPE=C", "LC_ALL=C", "USER=root"});

	verify_exists(master_vm, "test_return");
	verify_exists(master_vm, "test_ud2");
	verify_exists(master_vm, "test_read");
	verify_exists(master_vm, "test_copy_on_write");

	/* Remote debugger session */
	if (getenv("DEBUG"))
	{
		auto* vm = &master_vm;

		if (getenv("VMCALL")) {
			master_vm.run();
		}
		if (getenv("FORK")) {
			master_vm.prepare_copy_on_write();
			vm = new tinykvm::Machine {master_vm, options};
			auto regs = vm->setup_call(vm->address_of("test_return"));
			vm->set_registers(regs);
		} else {
			auto regs = master_vm.setup_call(master_vm.address_of("test_return"));
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

	/* Make the master VM able to mass-produce copies */
	master_vm.prepare_copy_on_write();

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

void test_master_vm(tinykvm::Machine& master_vm)
{
	/* Call into master VM */
	master_vm.vmcall("test_return");
	KASSERT(master_vm.return_value() == 666);
	try {
		master_vm.vmcall("test_ud2");
	} catch (const tinykvm::MachineException& me) {
		/* Allow invalid opcode exception */
		KASSERT(me.data() == 6);
	}
	master_vm.vmcall("test_read");
	KASSERT(master_vm.return_value() == 200);
}

void test_forking(tinykvm::Machine& master_vm)
{
	/* Create VM fork */
	const tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.verbose_loader = false
	};
	tinykvm::Machine vm {master_vm, options};

	/* Call into VM */
	for (size_t i = 0; i < 20; i++)
	{
		vm.vmcall("test_return");
		KASSERT(vm.return_value() == 666);
		try {
			printf("test_ud2\n");
			vm.vmcall("test_ud2");
		} catch (const tinykvm::MachineException& me) {
			/* Allow invalid opcode exception */
			KASSERT(me.data() == 6);
			try {
				/* Retry exception */
				printf("Retry\n");
				vm.run();
			} catch (const tinykvm::MachineException& me) {
				/* Allow invalid opcode exception */
				KASSERT(me.data() == 6);
			}
		}
		vm.vmcall("test_read");
		KASSERT(vm.return_value() == 200);
	}

	/* Reset and call into VM */
	for (size_t i = 0; i < 20; i++)
	{
		vm.reset_to(master_vm);
		vm.vmcall("test_return");
		KASSERT(vm.return_value() == 666);
		try {
			printf("test_ud2\n");
			vm.vmcall("test_ud2");
		} catch (const tinykvm::MachineException& me) {
			/* Allow invalid opcode exception */
			KASSERT(me.data() == 6);
			try {
				/* Retry exception */
				printf("Retry\n");
				vm.run();
			} catch (const tinykvm::MachineException& me) {
				/* Allow invalid opcode exception */
				KASSERT(me.data() == 6);
			}
		}
		vm.vmcall("test_read");
		KASSERT(vm.return_value() == 200);
	}
}

void test_copy_on_write(tinykvm::Machine& master_vm)
{
	const tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.verbose_loader = false
	};
	tinykvm::Machine vm {master_vm, options};

	for (size_t i = 0; i < 1; i++)
	{
		vm.reset_to(master_vm);
		vm.vmcall("test_copy_on_write");
		KASSERT(vm.return_value() == 666);
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
