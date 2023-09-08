#include "machine.hpp"
#include <memory>

namespace tinykvm {
struct RSPClient;

struct RSP
{
	// Wait for a connection for @timeout_secs
	std::unique_ptr<RSPClient> accept(int timeout_secs = 10);
	int  fd() const noexcept { return server_fd; }

	RSP(vCPU&, uint16_t);
	RSP(Machine&, uint16_t);
	~RSP();

private:
	vCPU& m_cpu;
	int server_fd;
};

struct RSPClient
{
	using StopFunc = void(*)(RSPClient&);
	bool is_closed() const noexcept { return m_closed; }

	bool process_one();
	bool send(const char* str);
	bool sendf(const char* fmt, ...);
	void reply_ack();
	void reply_ok();
	void interrupt();
	void kill();

	auto& cpu() { return *m_cpu; }
	auto& machine() { return m_cpu->machine(); }
	void set_vcpu(vCPU& cpu) { m_cpu = &cpu; }
	void set_break_limit(uint64_t limit) { m_breaklimit = limit; }
	void set_verbose(bool v) { m_verbose = v; }
	void on_stopped(StopFunc f) { m_on_stopped = f; }

	RSPClient(vCPU& cpu, int fd);
	~RSPClient();

private:
	static constexpr char lut[] = "0123456789abcdef";
	static const int PACKET_SIZE = 2000;
	template <typename T>
	inline void putreg(char*& d, const char* end, const T& reg);
	inline void putreg(char*& d, const char* end, const uint8_t* reg, size_t len);
	int forge_packet(char* dst, size_t dstlen, const char*, int);
	int forge_packet(char* dst, size_t dstlen, const char*, va_list);
	void process_data();
	void handle_query();
	void handle_breakpoint();
	void handle_continue();
	void handle_step();
	void handle_executing();
	void handle_multithread();
	void handle_readreg();
	void handle_writereg();
	void handle_readmem();
	void handle_writemem();
	void report_gprs();
	void report_status();
	void close_now();
	vCPU* m_cpu;
	uint64_t m_breaklimit = 1'000;
	int  sockfd;
	bool m_closed  = false;
	bool m_verbose = false;
	std::string buffer;
	std::array<uint64_t, 4> m_bp = {0};
	size_t bp_iterator = 0;
	StopFunc m_on_stopped = nullptr;
};

}
