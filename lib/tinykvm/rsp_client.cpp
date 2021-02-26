#include "rsp_client.hpp"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <linux/kvm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <cstring>
#include <stdexcept>

/**
**/

namespace tinykvm {

RSP::RSP(Machine& m, uint16_t port)
	: m_machine{m}
{
	this->server_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);

	int opt = 1;
	if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
		&opt, sizeof(opt))) {
		close(server_fd);
		throw std::runtime_error("Failed to enable REUSEADDR/PORT");
	}
	struct sockaddr_in address;
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(port);
	if (bind(server_fd, (struct sockaddr*) &address,
            sizeof(address)) < 0) {
		close(server_fd);
		throw std::runtime_error("GDB listener failed to bind to port");
	}
	if (listen(server_fd, 2) < 0) {
		close(server_fd);
		throw std::runtime_error("GDB listener failed to listen on port");
	}
}
std::unique_ptr<RSPClient> RSP::accept(int timeout_secs)
{
	struct timeval tv {
		.tv_sec = timeout_secs,
		.tv_usec = 0
	};
	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(server_fd, &fds);

	const int ret = select(server_fd + 1, &fds, NULL, NULL, &tv);
	if (ret <= 0) {
		return nullptr;
	}

	struct sockaddr_in address;
	int addrlen = sizeof(address);
	int sockfd = ::accept(server_fd, (struct sockaddr*) &address,
        	(socklen_t*) &addrlen);
    if (sockfd < 0) {
		return nullptr;
	}
	// Disable Nagle
	int opt = 1;
	if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt))) {
		close(sockfd);
		return nullptr;
	}
	// Enable receive and send timeouts
	tv = {
		.tv_sec = 60,
		.tv_usec = 0
	};
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO | SO_SNDTIMEO, &tv, sizeof(tv))) {
		close(sockfd);
		return nullptr;
	}
	return std::make_unique<RSPClient>(m_machine, sockfd);
}
RSP::~RSP() {
	close(server_fd);
}

RSPClient::RSPClient(Machine& m, int fd)
	: m_machine{&m}, sockfd(fd)  {}
RSPClient::~RSPClient() {
	if (!is_closed())
		close(this->sockfd);
}

void RSPClient::close_now() {
	this->m_closed = true;
	close(this->sockfd);
}
int RSPClient::forge_packet(
	char* dst, size_t dstlen, const char* data, int datalen)
{
	char* d = dst;
	*d++ = '$';
	uint8_t csum = 0;
	for (int i = 0; i < datalen; i++) {
		uint8_t c = data[i];
		if (c == '$' || c == '#' || c == '*' || c == '}') {
			c ^= 0x20;
			csum += '}';
			*d++ = '}';
		}
		*d++ = c;
		csum += c;
	}
	*d++ = '#';
	*d++ = lut[(csum >> 4) & 0xF];
	*d++ = lut[(csum >> 0) & 0xF];
	return d - dst;
}
int RSPClient::forge_packet(
	char* dst, size_t dstlen, const char* fmt, va_list args)
{
	char data[4 + 2*PACKET_SIZE];
	int datalen = vsnprintf(data, sizeof(data), fmt, args);
	return forge_packet(dst, dstlen, data, datalen);
}
bool RSPClient::sendf(const char* fmt, ...)
{
	char buffer[PACKET_SIZE];
	va_list args;
	va_start(args, fmt);
	int plen = forge_packet(buffer, sizeof(buffer), fmt, args);
	va_end(args);
	if (UNLIKELY(m_verbose)) {
		printf("TX >>> %.*s\n", plen, buffer);
	}
	int len = ::write(sockfd, buffer, plen);
	if (len <= 0) {
		this->close_now();
		return false;
	}
	// Acknowledgement
	int rlen = ::read(sockfd, buffer, 1);
	if (rlen <= 0) {
		this->close_now();
		return false;
	}
	return (buffer[0] == '+');
}
bool RSPClient::send(const char* str)
{
	char buffer[PACKET_SIZE];
	int plen = forge_packet(buffer, sizeof(buffer), str, strlen(str));
	if (UNLIKELY(m_verbose)) {
		printf("TX >>> %.*s\n", plen, buffer);
	}
	int len = ::write(sockfd, buffer, plen);
	if (len <= 0) {
		this->close_now();
		return false;
	}
	// Acknowledgement
	int rlen = ::read(sockfd, buffer, 1);
	if (rlen <= 0) {
		this->close_now();
		return false;
	}
	return (buffer[0] == '+');
}
bool RSPClient::process_one()
{
	char tmp[1024];
	int len = ::read(this->sockfd, tmp, sizeof(tmp));
	if (len <= 0) {
		this->close_now();
		return false;
	}
	if (UNLIKELY(m_verbose)) {
		printf("RX <<< %.*s\n", len, tmp);
	}
	for (int i = 0; i < len; i++)
	{
		char c = tmp[i];
		if (buffer.empty() && c == '+') {
			/* Ignore acks? */
		}
		else if (c == '$') {
			this->buffer.clear();
		}
		else if (c == '#') {
			reply_ack();
			process_data();
			this->buffer.clear();
			i += 2;
		}
		else {
			this->buffer.append(&c, 1);
			if (buffer.size() >= PACKET_SIZE)
				break;
		}
	}
	return true;
}
void RSPClient::process_data()
{
	switch (buffer[0]) {
	case 'q':
		handle_query();
		break;
	case 'c':
		handle_continue();
		break;
	case 's':
		handle_step();
		break;
	case 'g':
		report_gprs();
		break;
	case 'D':
	case 'k':
		kill();
		return;
	case 'H':
		handle_multithread();
		break;
	case 'm':
		handle_readmem();
		break;
	case 'P':
		handle_writereg();
		break;
	case 'v':
		handle_executing();
		break;
	case 'X':
		handle_writemem();
		break;
	case 'Z':
	case 'z':
		handle_breakpoint();
		break;
	case '?':
		report_status();
		break;
	default:
		if (UNLIKELY(m_verbose)) {
			fprintf(stderr, "Unhandled packet: %c\n",
				buffer[0]);
		}
	}
}
void RSPClient::handle_query()
{
	if (strncmp("qSupported", buffer.data(), strlen("qSupported")) == 0)
	{
		sendf("PacketSize=%x;swbreak-;hwbreak+", PACKET_SIZE);
	}
	else if (strncmp("qAttached", buffer.data(), strlen("qC")) == 0)
	{
		send("1");
	}
	else if (strncmp("qC", buffer.data(), strlen("qC")) == 0)
	{
		// Current thread ID
		send("QC0");
	}
	else if (strncmp("qOffsets", buffer.data(), strlen("qOffsets")) == 0)
	{
		// Section relocation offsets
		send("Text=0;Data=0;Bss=0");
	}
	else if (strncmp("qfThreadInfo", buffer.data(), strlen("qfThreadInfo")) == 0)
	{
		// Start of threads list
		send("m0");
	}
	else if (strncmp("qsThreadInfo", buffer.data(), strlen("qfThreadInfo")) == 0)
	{
		// End of threads list
		send("l");
	}
	else if (strncmp("qSymbol::", buffer.data(), strlen("qSymbol::")) == 0)
	{
		send("OK");
	}
	else if (strncmp("qTStatus", buffer.data(), strlen("qTStatus")) == 0)
	{
		send("");
	}
	else {
		if (UNLIKELY(m_verbose)) {
			fprintf(stderr, "Unknown query: %s\n",
				buffer.data());
		}
		send("");
	}
}
void RSPClient::handle_continue()
{
	auto regs = m_machine->registers();
	if (m_bp0 == regs.rip || m_bp1 == regs.rip) {
		send("S05");
		return;
	}
restart:
	try {
		uint64_t n = m_ilimit;
		while (!m_machine->stopped()) {
			auto reason = m_machine->run_with_breakpoint(m_bp0, m_bp1);
			// Hardware breakpoint
			if (reason == KVM_EXIT_DEBUG)
				break;
			// Instruction limit
			if (n-- == 0)
				break;
		}
	} catch (const tinykvm::MachineException& e) {
		// Hardware breakpoints are exceptions
		if (e.data() != 3) {
			// Guest crashed
			fprintf(stderr, "Exception: %s (%lu)\n", e.what(), e.data());
			send("S11");
			return;
		}
	} catch (const std::exception& e) {
		fprintf(stderr, "Exception: %s\n", e.what());
		send("S11");
		return;
	}
	report_status();
}
void RSPClient::handle_step()
{
	try {
		if (!m_machine->stopped()) {
			m_machine->step_one();
		} else {
			send("S00");
			return;
		}
	} catch (const MachineException& e) {
		fprintf(stderr, "Exception: %s (%lu)\n", e.what(), e.data());
		send("S11");
		return;
	} catch (const std::exception& e) {
		fprintf(stderr, "Exception: %s\n", e.what());
		send("S11");
		return;
	}
	report_status();
}
void RSPClient::handle_breakpoint()
{
	uint32_t type = 0;
	uint64_t addr = 0;
	sscanf(&buffer[1], "%1u,%lx", &type, &addr);
	if (buffer[0] == 'Z') {
		if (m_bp0 == 0)
			m_bp0 = addr;
		else if (m_bp1 == 0)
			m_bp1 = addr;
		else {
			fprintf(stderr, "RSP: No more room for breakpoints\n");
			send("");
			return;
		}
	} else {
		this->m_bp0 = 0;
		this->m_bp1 = 0;
	}
	//printf("Breakpoint 0: 0x%lX   Breakpoint 1: 0x%lX\n", m_bp0, m_bp1);
	reply_ok();
}
void RSPClient::handle_executing()
{
	if (strncmp("vCont?", buffer.data(), strlen("vCont?")) == 0)
	{
		send("vCont;c;s");
	}
	else if (strncmp("vCont;c", buffer.data(), strlen("vCont;c")) == 0)
	{
		this->handle_continue();
	}
	else if (strncmp("vCont;s", buffer.data(), strlen("vCont;s")) == 0)
	{
		this->handle_step();
	}
	else if (strncmp("vKill", buffer.data(), strlen("vKill")) == 0)
	{
		this->kill();
	}
	else if (strncmp("vMustReplyEmpty", buffer.data(), strlen("vMustReplyEmpty")) == 0)
	{
		send("");
	}
	else {
		if (UNLIKELY(m_verbose)) {
			fprintf(stderr, "Unknown executor: %s\n",
				buffer.data());
		}
		send("");
	}
}
void RSPClient::handle_multithread() {
	reply_ok();
}
void RSPClient::handle_readmem()
{
	uint64_t addr = 0;
	uint32_t len = 0;
	sscanf(buffer.c_str(), "m%lx,%x", &addr, &len);
	if (len >= 500) {
		send("E01");
		return;
	}

	char data[1024];
	char* d = data;
	try {
		for (unsigned i = 0; i < len; i++) {
			uint8_t val = *m_machine->unsafe_memory_at(addr + i, 1);
			*d++ = lut[(val >> 4) & 0xF];
			*d++ = lut[(val >> 0) & 0xF];
		}
	} catch (...) {
		send("E11");
		return;
	}
	*d++ = 0;
	send(data);
}
void RSPClient::handle_writemem()
{
	uint64_t addr = 0;
	uint32_t len = 0;
	int ret = sscanf(buffer.c_str(), "X%lx,%x:", &addr, &len);
	if (ret <= 0) {
		send("E01");
		return;
	}
	char* bin = (char*)
		memchr(buffer.data(), ':', buffer.size());
	if (bin == nullptr) {
		send("E01");
		return;
	}
	bin += 1; // Move past colon
	const char* end = buffer.c_str() + buffer.size();
	uint32_t rlen = std::min(len, (uint32_t) (end - bin));
	try {
		for (auto i = 0u; i < rlen; i++) {
			char data = bin[i];
			if (data == '{' && i+1 < rlen) {
				data = bin[++i] ^ 0x20;
			}
			auto* mem = m_machine->rw_memory_at(addr+i, 1);
			mem[0] = data;
		}
		reply_ok();
	} catch (...) {
		send("E11");
	}
}
void RSPClient::report_status()
{
	if (!m_machine->stopped())
		send("S05"); /* Just send TRAP */
	else {
		if (m_on_stopped != nullptr) {
			m_on_stopped(*this);
		} else {
			//send("vStopped");
			send("S05"); /* Just send TRAP */
		}
	}
}
template <typename T>
void RSPClient::putreg(char*& d, const char* end, const T& reg)
{
	for (auto j = 0u; j < sizeof(reg) && d < end; j++) {
		*d++ = lut[(reg >> (j*8+4)) & 0xF];
		*d++ = lut[(reg >> (j*8+0)) & 0xF];
	}
}

static __u64&
reg_at(struct tinykvm_x86regs& regs, size_t idx)
{
	switch (idx) {
	case 0: return regs.rax;
	case 1: return regs.rbx;
	case 2: return regs.rcx;
	case 3: return regs.rdx;
	case 4: return regs.rsi;
	case 5: return regs.rdi;
	case 6: return regs.rbp;
	case 7: return regs.rsp;
	case 8: return regs.r8;
	case 9: return regs.r9;
	case 10: return regs.r10;
	case 11: return regs.r11;
	case 12: return regs.r12;
	case 13: return regs.r13;
	case 14: return regs.r14;
	case 15: return regs.r15;
	case 16: return regs.rip;
	}
	throw std::runtime_error("Invalid register index");
}
static __u32&
reg32_at(Machine& m, struct tinykvm_x86regs& regs, size_t idx)
{
	static __u32 cs = 0x8;
	static __u32 fs = 0x0, gs = 0x0;
	switch (idx) {
	case 17: return *(uint32_t *)&regs.rflags;
	case 18:
	case 19:
	case 20:
	case 21:
		return cs;
	case 22:
		fs = m.get_fsgs().first;
		return fs;
	case 23:
		gs = m.get_fsgs().second;
		return gs;
	}
	throw std::runtime_error("Invalid register index");
}

void RSPClient::handle_writereg()
{
	uint64_t value = 0;
	uint32_t idx = 0;
	sscanf(buffer.c_str(), "P%x=%lx", &idx, &value);
	value = __builtin_bswap64(value);

	if (idx < 17) {
		auto regs = m_machine->registers();
		reg_at(regs, idx) = value;
		m_machine->set_registers(regs);
		send("OK");
	} else if (idx < 24) {
		auto regs = m_machine->registers();
		reg32_at(*m_machine, regs, idx) = value;
		m_machine->set_registers(regs);
		send("OK");
	} else {
		send("E01");
	}
}

void RSPClient::report_gprs()
{
	auto regs = m_machine->registers();
	char data[1024];
	char* d = data;
	/* GPRs, RIP, RFLAGS, segments */
	for (size_t i = 0; i < 17; i++) {
		putreg(d, &data[sizeof(data)], (uint64_t) reg_at(regs, i));
	}
	for (size_t i = 17; i < 24; i++) {
		putreg(d, &data[sizeof(data)], (uint32_t) reg32_at(*m_machine, regs, i));
	}
	*d++ = 0;
	send(data);
}

void RSPClient::reply_ack() {
	write(sockfd, "+", 1);
}
void RSPClient::reply_ok() {
	send("OK");
}
void RSPClient::interrupt() {
	send("S05");
}
void RSPClient::kill() {
	close(sockfd);
}

} // riscv
