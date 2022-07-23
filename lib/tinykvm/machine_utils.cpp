#include "machine.hpp"

#include <cstring>

namespace tinykvm {
static constexpr uint64_t PageMask() {
	return vMemory::PageSize() - 1UL;
}

void Machine::copy_to_guest(address_t addr, const void* vsrc, size_t len, bool zeroes)
{
	if (uses_cow_memory())
	{
		auto* src = (const uint8_t *)vsrc;
		while (len != 0)
		{
			const size_t offset = addr & PageMask();
			const size_t size = std::min(vMemory::PageSize() - offset, len);
			auto* page = memory.get_writable_page(addr & ~PageMask(), zeroes);
			std::copy(src, src + size, &page[offset]);

			addr += size;
			src += size;
			len -= size;
		}
		return;
	}
	/* Original VM uses identity-mapped memory */
	auto* dst = memory.safely_at(addr, len);
	std::memcpy(dst, vsrc, len);
}

void Machine::copy_from_guest(void* vdst, address_t addr, size_t len)
{
	if (uses_cow_memory())
	{
		auto* dst = (uint8_t *)vdst;
		while (len != 0)
		{
			const size_t offset = addr & PageMask();
			const size_t size = std::min(vMemory::PageSize() - offset, len);
			auto* page = memory.get_userpage_at(addr & ~PageMask());
			std::copy(&page[offset], &page[offset + size], dst);

			addr += size;
			dst += size;
			len -= size;
		}
		return;
	}
	/* Original VM uses identity-mapped memory */
	auto* src = memory.safely_at(addr, len);
	std::memcpy(vdst, src, len);
}

void Machine::unsafe_copy_from_guest(void* vdst, address_t addr, size_t len)
{
	if (uses_cow_memory())
	{
		auto* dst = (uint8_t *)vdst;
		while (len != 0)
		{
			const size_t offset = addr & PageMask();
			const size_t size = std::min(vMemory::PageSize() - offset, len);
			auto* page = memory.get_kernelpage_at(addr & ~PageMask());
			std::copy(&page[offset], &page[offset + size], dst);

			addr += size;
			dst += size;
			len -= size;
		}
		return;
	}
	/* Original VM uses identity-mapped memory */
	auto* src = memory.at(addr, len);
	std::memcpy(vdst, src, len);
}

size_t Machine::gather_buffers_from_range(
	size_t cnt, Buffer buffers[], address_t addr, size_t len)
{
	size_t index = 0;
	Buffer* last = nullptr;
	while (len != 0 && index < cnt)
	{
		const size_t offset = addr & PageMask();
		const size_t size = std::min(vMemory::PageSize() - offset, len);
		auto* page = memory.get_userpage_at(addr & ~PageMask());

		auto* ptr = (const char*) &page[offset];
		if (last && ptr == last->ptr + last->len) {
			last->len += size;
		} else {
			last = &buffers[index];
			last->ptr = ptr;
			last->len = size;
			index ++;
		}
		addr += size;
		len -= size;
	}
	if (UNLIKELY(len != 0)) {
		throw MemoryException("Out of buffers", index, cnt);
	}
	return index;
}

void Machine::copy_from_machine(address_t addr, Machine& src, address_t sa, size_t len)
{
	/* Over-estimate the number of buffers needed */
	const size_t nbuffers = 2 + (len / vMemory::PageSize());
	Buffer buffers[nbuffers];
	const size_t count =
		src.gather_buffers_from_range(nbuffers, buffers, sa, len);
	/* NOTE: Forked and some prepared VMs use CoW pages */
	if (uses_cow_memory())
	{
		/* Copy buffers one by one to this Machine */
		size_t index = 0;
		while (index < count)
		{
			auto& buf = buffers[index];
			const size_t offset = addr & PageMask();
			const size_t size = std::min(vMemory::PageSize() - offset, buf.len);
			/* NOTE: We could use zeroes if remaining is >= PageSize() */
			auto* page = memory.get_writable_page(addr & ~PageMask(), false);
			std::copy(buf.ptr, buf.ptr + size, &page[offset]);

			if (size == buf.len) {
				index += 1;
			} else {
				buf.ptr += size;
				buf.len -= size;
			}
			addr += size;
		}
		return;
	}
	/* Copy buffers one by one to sequential memory */
	size_t index = 0;
	while (index < count)
	{
		const auto& buf = buffers[index++];

		auto* dst = memory.safely_at(addr, buf.len);
		std::memcpy(dst, buf.ptr, buf.len);

		addr += buf.len;
	}
}

std::string_view Machine::sequential_view(address_t dst, size_t len)
{
	const size_t offset = dst & PageMask();
	const size_t size = std::min(vMemory::PageSize() - offset, len);
	auto* page = memory.get_userpage_at(dst & ~PageMask());

	Buffer buf {(const char*) &page[offset], size};
	dst += size;
	len -= size;

	while (len != 0)
	{
		const size_t offset = dst & PageMask();
		const size_t size = std::min(vMemory::PageSize() - offset, len);
		auto* page = memory.get_userpage_at(dst & ~PageMask());

		auto* ptr = (const char*) &page[offset];
		if (ptr != buf.ptr + buf.len)
			return {nullptr, 0};

		buf.len += size;
		dst += size;
		len -= size;
	}
	return {buf.ptr, buf.len};
}

void Machine::foreach_memory(address_t src, size_t len,
	std::function<void(const std::string_view)> callback) const
{
	const size_t offset = src & PageMask();
	const size_t size = std::min(vMemory::PageSize() - offset, len);
	auto* page = memory.get_userpage_at(src & ~PageMask());

	std::string_view view {(const char*) &page[offset], size};
	src += size;
	len -= size;

	while (len != 0)
	{
		const size_t offset = src & PageMask();
		const size_t size = std::min(vMemory::PageSize() - offset, len);
		auto *page = memory.get_userpage_at(src & ~PageMask());

		auto *ptr = (const char *)&page[offset];
		/* Either extend view, or pass it to callback. */
		if (ptr == view.end()) {
			view = {view.begin(), view.size() + size};
		} else {
			callback(view);
			view = nullptr;
		}

		src += size;
		len -= size;
	}
	if (view != nullptr)
		callback(view);
}

} // tinykvm
