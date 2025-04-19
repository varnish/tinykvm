#include "machine.hpp"

#include <cstring>
#include "amd64/paging.hpp"

namespace tinykvm {
static constexpr uint64_t PageMask() {
	return vMemory::PageSize() - 1UL;
}

void Machine::memzero(address_t addr, size_t len)
{
	if (uses_cow_memory() || !memory.safely_within(addr, len))
	{
		while (len != 0)
		{
			const size_t offset = addr & PageMask();
			const size_t size = std::min(vMemory::PageSize() - offset, len);
			bool must_be_zeroed = false;
			page_at(memory, addr & ~PageMask(),
				[&must_be_zeroed] (address_t /*page_addr*/, uint64_t flags, size_t /*page_size*/) {
					if ((flags & (1UL << 6)) == 0) {
						/* This is not a dirty page, so we can skip zeroing it */
						must_be_zeroed = false;
					} else {
						/* This is a dirty page, so we need to zero it */
						must_be_zeroed = true;
					}
				}, true); // Ignore missing pages
			if (UNLIKELY(must_be_zeroed)) {
				auto* page = memory.get_writable_page(addr & ~PageMask(), memory.expectedUsermodeFlags(), true);
				std::memset(&page[offset], 0, size);
			}

			addr += size;
			len -= size;
		}
		return;
	}
	/* Original VM uses identity-mapped memory */
	auto* dst = memory.safely_at(addr, len);
	std::memset(dst, 0, len);
}

void Machine::copy_to_guest(address_t addr, const void* vsrc, size_t len, bool zeroes)
{
	if (uses_cow_memory() || !memory.safely_within(addr, len))
	{
		auto* src = (const uint8_t *)vsrc;
		while (len != 0)
		{
			const size_t offset = addr & PageMask();
			const size_t size = std::min(vMemory::PageSize() - offset, len);
			auto* page = memory.get_writable_page(addr & ~PageMask(), memory.expectedUsermodeFlags(), zeroes);
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

void Machine::copy_from_guest(void* vdst, address_t addr, size_t len) const
{
	if (uses_cow_memory() || !memory.safely_within(addr, len))
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

void Machine::unsafe_copy_from_guest(void* vdst, address_t addr, size_t len) const
{
	if (uses_cow_memory() || !memory.safely_within(addr, len))
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
	size_t cnt, Buffer buffers[], address_t addr, size_t len) const
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
size_t Machine::writable_buffers_from_range(
	size_t cnt, WrBuffer buffers[], address_t addr, size_t len)
{
	size_t index = 0;
	WrBuffer* last = nullptr;
	while (len != 0 && index < cnt)
	{
		const size_t offset = addr & PageMask();
		const size_t size = std::min(vMemory::PageSize() - offset, len);
		auto *page = memory.get_writable_page(addr & ~PageMask(), memory.expectedUsermodeFlags(), false);

		auto* ptr = (char*) &page[offset];
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
			auto *page = memory.get_writable_page(addr & ~PageMask(), memory.expectedUsermodeFlags(), false);
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

void Machine::string_or_view(address_t src, size_t len,
	std::function<void(std::string_view)> sv_cb, std::function<void(std::string)> str_cb) const
{
	const size_t offset = src & PageMask();
	const size_t size = std::min(vMemory::PageSize() - offset, len);
	const auto* page = memory.get_userpage_at(src & ~PageMask());

	std::string str;
	Buffer buf {(const char*) &page[offset], size};
	src += size;
	len -= size;

	while (len != 0)
	{
		const size_t offset = src & PageMask();
		const size_t size = std::min(vMemory::PageSize() - offset, len);
		const auto* page = memory.get_userpage_at(src & ~PageMask());

		auto* ptr = (const char*) &page[offset];
		if (buf.len == 0) {
			str.append(ptr, ptr + size);
		}
		else if (ptr != buf.ptr + buf.len) {
			str = std::string(buf.ptr, buf.ptr + buf.len);
			str.append(ptr, ptr + size);
			buf.len = 0;
		} else {
			buf.len += size;
		}

		src += size;
		len -= size;
	}
	if (buf.len > 0) {
		sv_cb({buf.ptr, buf.len});
	} else {
		str_cb(std::move(str));
	}
}
Machine::StringOrView Machine::string_or_view(address_t src, size_t len) const
{
	const size_t offset = src & PageMask();
	const size_t size = std::min(vMemory::PageSize() - offset, len);
	const auto* page = memory.get_userpage_at(src & ~PageMask());

	std::string str;
	Buffer buf {(const char*) &page[offset], size};
	src += size;
	len -= size;

	while (len != 0)
	{
		const size_t offset = src & PageMask();
		const size_t size = std::min(vMemory::PageSize() - offset, len);
		const auto* page = memory.get_userpage_at(src & ~PageMask());

		auto* ptr = (const char*) &page[offset];
		if (buf.len == 0) {
			str.append(ptr, ptr + size);
		}
		else if (ptr != buf.ptr + buf.len) {
			str.reserve(buf.len + len);
			str.append(buf.ptr, buf.ptr + buf.len);
			str.append(ptr, ptr + size);
			buf.len = 0;
		} else {
			buf.len += size;
		}

		src += size;
		len -= size;
	}
	if (buf.len > 0) {
		return StringOrView{std::string_view{buf.ptr, buf.len}};
	} else {
		return StringOrView{std::move(str)};
	}
}

std::span<uint8_t> Machine::writable_memview(address_t src, size_t len)
{
	const size_t offset = src & PageMask();
	const size_t size = std::min(vMemory::PageSize() - offset, len);
	auto* page = memory.get_writable_page(src & ~PageMask(),
		memory.expectedUsermodeFlags(), false);

	std::span<uint8_t> view {(uint8_t*) &page[offset], size};
	src += size;
	len -= size;

	while (len != 0)
	{
		const size_t offset = src & PageMask();
		const size_t size = std::min(vMemory::PageSize() - offset, len);
		auto *page = memory.get_writable_page(src & ~PageMask(),
			memory.expectedUsermodeFlags(), false);

		auto *ptr = (uint8_t *)&page[offset];
		if (ptr == view.data() + view.size()) {
			view = std::span<uint8_t>{view.data(), view.size() + size};
		} else {
			machine_exception("Memory not sequential", src);
		}

		src += size;
		len -= size;
	}
	return view;
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
			view = {"", 0};
		}

		src += size;
		len -= size;
	}
	if (!view.empty())
		callback(view);
}

std::string Machine::copy_from_cstring(address_t src, size_t maxlen) const
{
	std::string result;
	while (result.size() < maxlen)
	{
		const size_t max_size = std::min(vMemory::PageSize(), maxlen - result.size());
		const size_t offset = src & PageMask();
		const auto* page = memory.get_userpage_at(src & ~PageMask());

		const auto* start = (const char *)&page[offset];
		const auto* end = (const char *)&page[max_size];

		const char* reader = start + strnlen(start, max_size);
		result.append(start, reader);

		if (reader < end)
			return result;
		src += max_size;
	}
	return result;
}

std::string Machine::buffer_to_string(address_t src, size_t len, size_t maxlen) const
{
	if (UNLIKELY(len > maxlen))
		machine_exception("String buffer too large", len);

	std::string result;
	result.resize(len);
	this->copy_from_guest(result.data(), src, len);
	return result;
}

std::string Machine::memcstring(address_t src, size_t maxlen) const
{
	std::string result;
	while (result.size() < maxlen)
	{
		const size_t max_size = std::min(vMemory::PageSize(), maxlen - result.size());
		const size_t offset = src & PageMask();
		const auto* page = memory.get_userpage_at(src & ~PageMask());

		const auto* start = (const char *)&page[offset];
		const auto* end = (const char *)&page[max_size];

		const char* reader = start + strnlen(start, max_size);
		result.append(start, reader);

		if (reader < end)
			return result;
		src += max_size;
	}
	return result;
}

} // tinykvm
