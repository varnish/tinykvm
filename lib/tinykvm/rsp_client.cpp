#include "rsp_client.hpp"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <linux/kvm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <cstdarg>
#include <cstring>
#include <stdexcept>
#include "amd64/memory_layout.hpp"

/**
**/
#define HIDE_CPU_EXCEPTIONS

namespace tinykvm {

RSP::RSP(vCPU& cpu, uint16_t port)
	: m_cpu{cpu}
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
	/* We need to make sure the VM can be stepped through */
	m_cpu.machine().stop(false);
}
RSP::RSP(Machine& machine, uint16_t port)
	: RSP(machine.cpu(), port)
{}
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
	return std::make_unique<RSPClient>(m_cpu, sockfd);
}
RSP::~RSP() {
	close(server_fd);
}

RSPClient::RSPClient(vCPU& cpu, int fd)
	: m_cpu{&cpu}, sockfd(fd)  {}
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
	(void)dstlen;
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
	/* NOTE: vsnprintf has an insane return value. */
	if (datalen > 0 && (size_t)datalen < sizeof(data))
		return forge_packet(dst, dstlen, data, datalen);
	else
		return -1;
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
	case 'p':
		handle_readreg();
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
	auto regs = machine().registers();
	for (const auto bp : m_bp) {
		if (bp == regs.rip) {
			send("S05");
			return;
		}
	}
	try {
		uint64_t n = m_breaklimit;
		while (!machine().stopped()) {
			auto reason = machine().run_with_breakpoints(m_bp);
			// Hardware breakpoint
			if (reason == KVM_EXIT_DEBUG)
				break;
			// Break limit (in case of loop)
			if (n-- == 0)
				break;
		}
	} catch (const tinykvm::MachineException& e) {
		// Guest crashed
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
void RSPClient::handle_step()
{
	auto regs = machine().registers();
	for (const auto bp : m_bp) {
		if (bp == regs.rip) {
			send("S05");
			return;
		}
	}
	try {
		if (!machine().stopped()) {
			//machine().run_with_breakpoints(m_bp);
			machine().step_one();
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
		m_bp[bp_iterator] = addr;
		bp_iterator = (bp_iterator + 1) % m_bp.size();
	} else {
		for (auto& bp : m_bp) {
			if (bp == addr) bp = 0;
		}
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
			uint8_t val;
			machine().unsafe_copy_from_guest(&val, addr + i, 1);
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
			machine().copy_to_guest(addr+i, &data, 1);
		}
		reply_ok();
	} catch (...) {
		send("E11");
	}
}
void RSPClient::report_status()
{
	if (!machine().stopped())
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
void RSPClient::putreg(char*& d, const char* end, const uint8_t* reg, size_t len)
{
	for (auto j = 0u; j < len && d < end; j++) {
		*d++ = lut[(reg[j] >> 4) & 0xF];
		*d++ = lut[(reg[j] >> 0) & 0xF];
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
reg32_at(vCPU& cpu, struct tinykvm_x86regs& regs, size_t idx)
{
	auto& sregs = cpu.get_special_registers();

	static __u32 seg = 0x0;
	static __u32 fs = 0x0, gs = 0x0;
	switch (idx) {
	case 17:
		return *(__u32 *)&regs.rflags;
	case 18:
		return seg = sregs.cs.selector;
	case 19:
		return seg = sregs.ss.selector;
	case 20:
		return seg = sregs.ds.selector;
	case 21:
		return seg = sregs.es.selector;
	case 22:
		fs = cpu.machine().get_fsgs().first;
		return fs;
	case 23:
		gs = cpu.machine().get_fsgs().second;
		return gs;
	}
	throw std::runtime_error("Invalid register index");
}

void RSPClient::handle_readreg()
{
	uint32_t idx = 0;
	sscanf(buffer.c_str(), "p%x", &idx);
	if (idx > 58) {
		send("E01");
		return;
	}

	char valdata[32];
	size_t vallen = 0;

	if (idx >= 18)
	{
		const auto fpu = machine().fpu_registers();
		if (idx <= 26) {
			const auto* fpreg = &fpu.fpr[idx - 18][0];
			vallen = 16;
			std::memcpy(valdata, fpreg, vallen);
		} else if (idx >= 31 && idx < 39) {
			// STMM0-7
			const auto* fpreg = &fpu.fpr[idx - 31][0];
			vallen = 16;
			std::memcpy(valdata, fpreg, vallen);
		} else if (idx >= 39 && idx < 55) {
			// XMM0-15
			const auto* fpreg = &fpu.xmm[idx - 39][0];
			vallen = 16;
			std::memcpy(valdata, fpreg, vallen);
		} else if (idx == 56 || idx == 57) {
			vallen = 4;
			uint32_t value = 0;
			std::memcpy(valdata, &value, vallen);
		} else if (idx == 58) {
			vallen = 8;
			uint64_t value = 0;
			std::memcpy(valdata, &value, vallen);
		} else {
			const auto* fpreg = &fpu.fcw;
			vallen = 4;
			std::memcpy(valdata, &fpreg[idx - 26], vallen);
		}
	}
	else /* GPRs */
	{
		const auto regs = machine().registers();
		const auto* regarray = (__u64 *)&regs;
		vallen = sizeof(__u64);
		std::memcpy(valdata, &regarray[idx], vallen);
	}

	char data[65];
	char* d = data;
	try {
		for (unsigned i = 0; i < vallen; i++) {
			*d++ = lut[(valdata[i] >> 4) & 0xF];
			*d++ = lut[(valdata[i] >> 0) & 0xF];
		}
	} catch (...) {
		send("E01");
		return;
	}
	*d++ = 0;
	send(data);
}
void RSPClient::handle_writereg()
{
	uint64_t value = 0;
	uint32_t idx = 0;
	sscanf(buffer.c_str(), "P%x=%lx", &idx, &value);
	value = __builtin_bswap64(value);

	if (idx < 17) {
		auto regs = machine().registers();
		reg_at(regs, idx) = value;
		machine().set_registers(regs);
		send("OK");
	} else if (idx < 24) {
		auto regs = machine().registers();
		reg32_at(cpu(), regs, idx) = value;
		machine().set_registers(regs);
		send("OK");
	} else {
		send("E01");
	}
}

void RSPClient::report_gprs()
{
	auto regs = machine().registers();
	char data[1100];
	const char* end = &data[sizeof(data)];
	char* d = data;
	/* GPRs, RIP, RFLAGS, segments */
	for (size_t i = 0; i < 17; i++) {
#ifdef HIDE_CPU_EXCEPTIONS
		/* vCPU on the exception/interrupt stack */
		if (regs.rsp >= IST_ADDR && regs.rsp < IST_END_ADDR)
		{
			const auto offset = cpu().exception_extra_offset(cpu().current_exception);
			if (i == 16)
			{
				uint64_t rip;
				machine().unsafe_copy_from_guest(&rip, regs.rsp+offset, 8);
				putreg(d, end, rip);
				continue;
			} else if (i == 7) {
				uint64_t rip;
				machine().unsafe_copy_from_guest(&rip, regs.rsp+offset+24, 8);
				putreg(d, end, rip);
				continue;
			}
		}
		/* vCPU handling a system call */
		if (regs.rip >= INTR_ASM_ADDR && regs.rip < IST_ADDR)
		{
			/* RCX and R11 is clobbered by SYSCALL (these values are *LOST*) */
			if (i == 16)
			{
				/* RCX == old RIP */
				const auto rip = regs.rcx;
				putreg(d, end, rip);
				continue;
			}
		}
#endif
		putreg(d, end, (uint64_t) reg_at(regs, i));
	}
	/* 7x special/segment registers */
	for (size_t i = 17; i < 24; i++) {
		putreg(d, end, (uint32_t) reg32_at(cpu(), regs, i));
	}

	// AMD64 SSE: 17 * 8 + 7 * 4 + 8 * 10 + 8 * 4 + 16 * 16 + 4
	// AMD64 AVX: 17 * 8 + 7 * 4 + 8 * 10 + 8 * 4 + 16 * 32 + 4
	const auto fpu = machine().fpu_registers();

	/* 8x 80-bit FP-registers */
	for (size_t i = 0; i < 8; i++) {
		putreg(d, end, &fpu.fpr[i][0], 10);
	}

	putreg(d, end, (uint32_t)fpu.fcw);  // FCTRL 16
	putreg(d, end, (uint32_t)fpu.fsw);  // FSTAT 16
	putreg(d, end, (uint32_t)fpu.ftwx); // FTAG  8
	putreg(d, end, (uint32_t)0); // FIOFF
	putreg(d, end, (uint32_t)0); // FISEG
	putreg(d, end, (uint32_t)0); // FOOFF
	putreg(d, end, (uint32_t)0); // FOSEG
	putreg(d, end, (uint32_t)fpu.last_opcode); // FOP 16

	/* 16x 128-bit XMM-registers */
	for (size_t i = 0; i < 16; i++) {
		putreg(d, end, &fpu.xmm[i][0], 16);
	}

	putreg(d, end, (uint32_t)fpu.mxcsr); // MXCSR
	//putreg(d, end, (uint64_t)0); // ORIG RAX

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
