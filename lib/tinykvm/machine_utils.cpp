#include "machine.hpp"

#include <cstring>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include "amd64/paging.hpp"
static constexpr bool VERBOSE_FILE_BACKED_MMAP = false;

namespace tinykvm {

void Machine::memzero(address_t addr, size_t len)
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
			auto* page = memory.get_writable_page(addr & ~PageMask(), memory.expectedUsermodeFlags(), true, false);
			std::memset(&page[offset], 0, size);
		}

		addr += size;
		len -= size;
	}
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
			auto* page = memory.get_writable_page(addr & ~PageMask(), memory.expectedUsermodeFlags(), zeroes, true);
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
size_t Machine::gather_buffers_from_range(
	std::vector<Buffer>& buffers, address_t addr, size_t len) const
{
	Buffer* last = nullptr;
	while (len != 0)
	{
		const size_t offset = addr & PageMask();
		const size_t size = std::min(vMemory::PageSize() - offset, len);
		auto* page = memory.get_userpage_at(addr & ~PageMask());

		auto* ptr = (const char*) &page[offset];
		if (last && ptr == last->ptr + last->len) {
			last->len += size;
		} else {
			buffers.emplace_back();
			last = &buffers.back();
			last->ptr = ptr;
			last->len = size;
		}
		addr += size;
		len -= size;
	}
	return buffers.size();
}
size_t Machine::writable_buffers_from_range(
	std::vector<WrBuffer>& buffers, address_t addr, size_t len)
{
	WrBuffer* last = nullptr;
	while (len != 0)
	{
		auto wpage = writable_page_at(memory, addr & ~PageMask(), memory.expectedUsermodeFlags(), false);
		if (wpage.page == nullptr) {
			throw MemoryException("Failed to allocate writable page for range", addr, vMemory::PageSize());
		}
		wpage.set_dirty();
		size_t offset = 0;
		size_t size = 0;
		char* page = wpage.page;
		if constexpr (true) {
			// Find the pages real size and realign the 4k-offset page pointer
			offset = addr & (wpage.size - 1);
			size = std::min(wpage.size - offset, len);
			page = (char *)((uintptr_t)wpage.page & ~(wpage.size - 1));
		} else {
			offset = addr & PageMask();
			size = std::min(vMemory::PageSize() - offset, len);
		}

		auto* ptr = (char*) &page[offset];
		if (last && ptr == last->ptr + last->len) {
			last->len += size;
		} else {
			buffers.emplace_back();
			last = &buffers.back();
			last->ptr = ptr;
			last->len = size;
		}
		addr += size;
		len -= size;
	}
	return buffers.size();
}

void* Machine::mmap_backed_area(
	int fd, int off, int prot, address_t virt_base, size_t size)
{
	address_t size_memory = size & ~0x1FFFFFLL; // Align *DOWN* to 2MB
	if constexpr (VERBOSE_FILE_BACKED_MMAP) {
		printf("mmap: allocating %zu bytes at 0x%lX -> 0x%lX\n",
			   size_t(size_memory), virt_base, virt_base + size_memory);
	}

	// Check if the mmap area overlaps with existing memory ranges
	for (const auto& range : memory.mmap_ranges) {
		if (range.overlaps(virt_base, size_memory)) {
			if constexpr (VERBOSE_FILE_BACKED_MMAP) {
				printf("mmap: overlapping range at 0x%lX -> 0x%lX, size %zu\n",
					range.virtbase, range.virtbase + range.size, range.size);
			}
			// Figure out if it extends past the end of the existing range
			if (virt_base + size_memory <= range.virtbase + range.size) {
				if constexpr (VERBOSE_FILE_BACKED_MMAP) {
					// The range is already allocated, so we can return it
					printf("mmap: already allocated at 0x%lX -> 0x%lX, size %zu\n",
						range.virtbase, range.virtbase + range.size, range.size);
				}
				// We can return the existing memory
				return range.ptr;
			}
			// Find the remaining size, then shift the virt_base
			const address_t virt_end = virt_base + size_memory;
			const auto remaining_size = virt_end - (range.virtbase + range.size);
			if (remaining_size > 0) {
				virt_base += remaining_size;
				size_memory -= remaining_size;
				break;
			}
			return nullptr; // Already allocated
		}
	}

	static constexpr bool MANUAL_PREADV = false;
	void* real_addr;
	if constexpr (!MANUAL_PREADV) {
		real_addr = mmap(nullptr, size_memory, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_NORESERVE, fd, off);
	} else {
		real_addr = mmap(nullptr, size_memory, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	}
	if (real_addr == MAP_FAILED) {
		return nullptr;
	}

	static constexpr address_t MMAP_PHYS_BASE = 0x4000000000;
	static address_t mmap_phys_base = MMAP_PHYS_BASE;
	// XXX: This isn't so important because you can only create these
	// in master VMs, which don't use memory banks.
	const int region_idx = memory.banks.allocate_region_idx();
	if constexpr (VERBOSE_FILE_BACKED_MMAP) {
		printf("mmap: allocating %zu kB at 0x%lX -> 0x%lX, phys 0x%lX region %d\n",
			size_memory / 1024, virt_base, virt_base + size_memory, mmap_phys_base, region_idx);
	}
	// Now we need to install this memory region as guest physical memory
	this->install_memory(region_idx, VirtualMem(mmap_phys_base, (char*)real_addr, size_memory), false);
	this->memory.mmap_ranges.emplace_back(mmap_phys_base, (char*)real_addr, virt_base, size_memory);
	// With the new physical memory, we now need to create pagetable entries
	// we'll do it the slow way by allocating the same range and for each page redirect it to the new phys
	for (address_t i = 0; i < size_memory; )
	{
		static constexpr address_t PDE64_USER = (1UL << 2);
		const address_t phys = mmap_phys_base + i;
		const address_t virt = virt_base + i;
		WritablePage writable_page = writable_page_at(memory, virt, PDE64_USER | 1, false);
		if (writable_page.page == nullptr) {
			throw MemoryException("Failed to allocate writable page for mmap", virt, vMemory::PageSize());
		}

		static constexpr uint64_t PDE64_ADDR_MASK = ~0x8000000000000FFF;
		if (writable_page.size != vMemory::PageSize()) {
			const address_t pv = writable_page.entry & PDE64_ADDR_MASK;
			// Check if the page is unaligned
			if ((pv & (writable_page.size - 1)) != 0) {
				throw MemoryException("Unaligned page for mmap (cannot use)", virt, writable_page.size);
			}
		}

		writable_page.entry &= ~PDE64_ADDR_MASK; // Clear the address bits
		writable_page.entry |= (phys & PDE64_ADDR_MASK); // Set the new physical
		writable_page.set_protections(prot);
		writable_page.set_dirty(); // Mark the page as dirty
		if constexpr (VERBOSE_FILE_BACKED_MMAP) {
			printf("mmap: allocating page at 0x%lX -> 0x%lX, phys 0x%lX size %zu entry 0x%lX prot 0x%X\n",
				virt, virt + vMemory::PageSize(), phys, writable_page.size, writable_page.entry, prot);
		}
		i += writable_page.size;
	}

	if constexpr (MANUAL_PREADV) {
		std::vector<tinykvm::Machine::WrBuffer> buffers;
		const size_t cnt =
			this->writable_buffers_from_range(buffers, virt_base, size);
		syscall(SYS_preadv, fd, (const iovec*)buffers.data(), cnt, off);
	} else if (size > size_memory) {
		// If the size is larger than the mmap area, we need to read the rest
		// from the file descriptor
		const size_t remaining = size - size_memory;
		if (remaining > 0) {
			std::vector<tinykvm::Machine::WrBuffer> buffers;
			const size_t cnt =
				this->writable_buffers_from_range(buffers, virt_base + size_memory, remaining);
			syscall(SYS_preadv, fd, (const iovec*)buffers.data(), cnt, off + size_memory);
		}
	}

	if constexpr (VERBOSE_FILE_BACKED_MMAP) {
		printf("mmap: allocated %zu bytes at 0x%lX, phys 0x%lX\n",
			size_memory, virt_base, mmap_phys_base);
	}
	mmap_phys_base += size_memory;
	// Force-align mmap_phys_base to 2MB
	mmap_phys_base = (mmap_phys_base + 0x1FFFFFLL) & ~0x1FFFFFLL;
	return real_addr;
}

void Machine::copy_from_machine(address_t addr, Machine& src, address_t sa, size_t len)
{
	std::vector<Buffer> buffers;
	const size_t count =
		src.gather_buffers_from_range(buffers, sa, len);
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
			auto *page = memory.get_writable_page(addr & ~PageMask(), memory.expectedUsermodeFlags(), false, false);
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
		memory.expectedUsermodeFlags(), false, true);

	std::span<uint8_t> view {(uint8_t*) &page[offset], size};
	src += size;
	len -= size;

	while (len != 0)
	{
		const size_t offset = src & PageMask();
		const size_t size = std::min(vMemory::PageSize() - offset, len);
		auto *page = memory.get_writable_page(src & ~PageMask(),
			memory.expectedUsermodeFlags(), false, true);

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
		const size_t offset = src & PageMask();
		const size_t max_size = std::min(vMemory::PageSize() - offset, maxlen - result.size());
		const auto* page = memory.get_userpage_at(src & ~PageMask());

		const auto* start = (const char *)&page[offset];
		const auto* end = start + max_size;

		const char* reader = start + strnlen(start, max_size);
		result.append(start, reader);

		if (reader < end)
			return result;
		src += max_size;
	}
	return result;
}

} // tinykvm
