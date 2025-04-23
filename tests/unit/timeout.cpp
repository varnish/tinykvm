#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include <thread>

#include <tinykvm/machine.hpp>
extern std::vector<uint8_t> build_and_load(const std::string& code);
static const uint64_t MAX_MEMORY = 32ul << 20; /* 32MB */
static const uint64_t MAX_COWMEM =  8ul << 20; /* 8MB */
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};

TEST_CASE("Initialize KVM", "[Initialize]")
{
	// Create KVM file descriptors etc.
	tinykvm::Machine::init();
}

TEST_CASE("Multiple timeouts inside guest", "[Timeout]")
{
	const auto good_binary = build_and_load(R"M(
int main() {
	return 0;
})M");
	const auto bad_binary = build_and_load(R"M(
int main() {
	while (1);
})M");

	std::vector<std::thread> threads;

	for (size_t i = 0; i < 100; i++)
	{
		// Good program
		threads.push_back(std::thread([&] {
			tinykvm::Machine machine { good_binary, { .max_mem = MAX_MEMORY } };
			machine.setup_linux({"timeout"}, env);
			// This must *NOT* cause a timeout exception
			try {
				machine.run(1.0f);
			} catch (const tinykvm::MachineTimeoutException& e) {
				throw std::runtime_error("Timeout in good program");
			}
		}));
		// Bad program
		threads.push_back(std::thread([&] {
			tinykvm::Machine machine { bad_binary, { .max_mem = MAX_MEMORY } };
			machine.setup_linux({"timeout"}, env);
			// This must cause a timeout exception
			try {
				machine.run(1.0f);
			} catch (const tinykvm::MachineTimeoutException& e) {
				return;
			}
			throw std::runtime_error("No timeout");
		}));
	}
	for (auto& thread : threads)
		thread.join();
}

TEST_CASE("Multiple timeouts in Linux system call", "[Timeout]")
{
	const auto binary = build_and_load(R"M(
extern long write(int, const void*, unsigned long);
int main() {
	while (1) {
		//for (volatile unsigned long i = 0; i < 40000000UL; i++);
		write(1, "Hello World!", 12);
	}
})M");

	std::vector<std::thread> threads;

	for (size_t i = 0; i < 100; i++)
	{
		threads.push_back(std::thread([&] {
			tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
			machine.setup_linux({"timeout"}, env);
			// This will cause every write to sleep for 1 second.
			machine.set_printer([&] (const char*, size_t) {
				std::this_thread::sleep_for(std::chrono::seconds(1));
			});
			// This must cause a timeout exception
			try {
				machine.run(1.0f);
			} catch (const tinykvm::MachineTimeoutException& e) {
				return;
			}
			throw std::runtime_error("No timeout");
		}));
	}
	for (auto& thread : threads)
		thread.join();
}
