#include "machine.hpp"

#include <cstring>
#include <sys/mman.h>
#include <sys/stat.h>
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

bool Machine::mmap_backed_area(
	int fd, int off, int prot, address_t virt_base, size_t size_bytes)
{
	static constexpr bool MANUAL_PREADV = false;
	static constexpr address_t MMAP_PHYS_BASE = 0x4000000000;
	static address_t mmap_phys_base = MMAP_PHYS_BASE;

	if (virt_base & 0xFFF) {
		throw MemoryException("Virtual base address is not page-aligned for MMAP backing", virt_base, size_bytes);
	}

	// Find the actual length of the file
	struct stat st;
	if (fstat(fd, &st) < 0) {
		throw MemoryException("Failed to fstat for mmap", virt_base, size_bytes);
	}
	const size_t file_size = st.st_size;
	if (off < 0 || off >= file_size) {
		return false;
	}
	size_bytes = std::min(size_bytes, file_size - off);

	// Linux doesn't support 2MB pages for files anyway, so let's just do the right thing
	// and split everything into 4k. First, calculate the number of 4k pages needed for the entire segment
	const size_t num_4k_pages = (size_bytes + 0xFFFLL) >> 12;
	// from this we can use the regular guest mmap to allocate these entries
	// each entry is of course a 64-bit address
	const size_t free_size_needed = (num_4k_pages * sizeof(uint64_t) + 0xFFF) & ~0xFFFLL;
	void* free_addr = mmap(nullptr, free_size_needed, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (free_addr == MAP_FAILED) {
		if constexpr (VERBOSE_FILE_BACKED_MMAP) {
			printf("mmap: error: failed to mmap %zu bytes at 0x%lX\n",
				size_bytes, virt_base);
		}
		return false;
	}

	// Insert the new free pages
	const int free_region = memory.banks.allocate_region_idx();
	const address_t free_phys = mmap_phys_base;
	address_t current_free_phys = free_phys;
	this->install_memory(free_region, VirtualMem(free_phys, (char*)free_addr, free_size_needed), false);
	this->memory.mmap_ranges.emplace_back(free_phys, (char*)free_addr, free_size_needed);
	mmap_phys_base += free_size_needed;

	if constexpr (VERBOSE_FILE_BACKED_MMAP) {
		printf("mmap: allocated free pages from 0x%lX -> 0x%lX\n",
			free_phys, free_phys + free_size_needed);
	}

	const address_t size_memory = size_bytes & ~0xFFFLL; // Align *DOWN* to 4kb

	// mmap the entire file into a void*
	void* real_addr = nullptr;
	if constexpr (!MANUAL_PREADV) {
		real_addr = mmap(nullptr, size_memory, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, off);
	} else {
		real_addr = mmap(nullptr, size_memory, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	}
	if (real_addr == MAP_FAILED) {
		if constexpr (VERBOSE_FILE_BACKED_MMAP) {
			printf("mmap: error: failed to mmap %zu bytes at 0x%lX\n",
				size_bytes, virt_base);
		}
		return false;
	}

	// insert the file into guest physical
	const int region_idx = memory.banks.allocate_region_idx();
	this->install_memory(region_idx, VirtualMem(mmap_phys_base, (char*)real_addr, size_memory), false);
	this->memory.mmap_ranges.emplace_back(mmap_phys_base, (char*)real_addr, virt_base, size_memory);

	// fill all the entries now that we have the physical
	for (address_t i = 0; i < size_memory; )
	{
		static constexpr uint64_t PDE64_ADDR_MASK = ~0x8000000000000FFF;
		static constexpr address_t PDE64_PRESENT = (1UL << 0);
		static constexpr address_t PDE64_RW   = (1UL << 1);
		static constexpr address_t PDE64_USER = (1UL << 2);
		static constexpr address_t PDE64_DIRTY = (1UL << 6);
		static constexpr address_t PDE64_PS   = (1UL << 7);
		static constexpr address_t PDE64_G    = (1UL << 8);
		const address_t phys = mmap_phys_base + i;
		const address_t virt = virt_base + i;
		WritablePage writable_page = writable_page_at(memory, virt, PDE64_USER | PDE64_PRESENT, false);
		// 2MB pages need to be split into 4k pages
		if (writable_page.size != vMemory::PageSize()) {
			if ((writable_page.entry & PDE64_PS) == 0) {
				throw MemoryException("Failed to split page for mmap (not a leaf page)", virt, vMemory::PageSize());
			}
			if (writable_page.size > 512*vMemory::PageSize()) {
				throw MemoryException("Failed to split page for mmap (found gigapage)", virt, vMemory::PageSize());
			}
			// Split the page using one of the free pages
			const address_t free_page_phys = current_free_phys;
			current_free_phys += vMemory::PageSize();

			const address_t free_phys_offset = free_page_phys - free_phys;
			uint64_t* free_phys_ptr = (uint64_t *)((char*)free_addr + free_phys_offset);

			// these are real pagetable entries, so they need sane values
			const address_t current_phys = writable_page.entry & PDE64_ADDR_MASK;
			const address_t current_flags = (writable_page.entry & ~PDE64_ADDR_MASK) & ~PDE64_PS;
			for (address_t j = 0; j < 512; j ++) {
				free_phys_ptr[j] = current_flags | (current_phys + j * vMemory::PageSize());
			}

			// The free page is a pagetable page now, so remove its user and read/write permissions
			const address_t old_entry = writable_page.entry;
			writable_page.entry = free_page_phys;
			writable_page.entry |= PDE64_PRESENT | PDE64_USER | PDE64_RW;
			if constexpr (VERBOSE_FILE_BACKED_MMAP) {
				printf("mmap: split 2MB page at 0x%lX -> 0x%lX, entry 0x%lX old_entry 0x%lX\n",
					virt, virt + 512 * vMemory::PageSize(), writable_page.entry, old_entry);
			}

			const unsigned idx = (virt >> 12) & 511;
			WritablePage this_page {
				.page = nullptr,
				.entry = free_phys_ptr[idx],
				.size = vMemory::PageSize()
			};
			this_page.set_address(phys);
			this_page.set_flags(PDE64_USER | PDE64_PRESENT | PDE64_G | PDE64_DIRTY);
			this_page.set_protections(prot | PROT_WRITE);
			i += vMemory::PageSize();
			continue;
		}

		writable_page.entry &= ~PDE64_ADDR_MASK; // Clear the address bits
		writable_page.entry |= (phys & PDE64_ADDR_MASK); // Set the new physical
		writable_page.set_protections(prot | PROT_WRITE);
		writable_page.set_dirty(); // Mark the page as dirty
		if constexpr (false && VERBOSE_FILE_BACKED_MMAP) {
			printf("mmap: allocating page at 0x%lX -> 0x%lX, phys 0x%lX size %zu entry 0x%lX prot 0x%X\n",
				virt, virt + writable_page.size, phys, writable_page.size, writable_page.entry, prot);
		}
		i += vMemory::PageSize();
	}
	mmap_phys_base += (size_bytes + 0xFFF) & ~0xFFFLL;

	if (current_free_phys > free_phys + free_size_needed) {
		throw MemoryException("Failed to mmap file (not enough free pages)", free_phys, free_size_needed);
	}

	if constexpr (MANUAL_PREADV)
	{
		std::vector<WrBuffer> buffers;
		// Gather buffers for the preadv call
		const size_t count = this->writable_buffers_from_range(buffers, virt_base, size_bytes);
		// preadv() the entire area
		const int result = preadv64(fd, (const iovec *)buffers.data(), count, off);
		if (result < 0) {
			throw MemoryException("Failed to preadv for mmap", virt_base, size_bytes);
		}
	}
	else if (size_bytes > size_memory)
	{
		const size_t remaining = size_bytes - size_memory;
		std::vector<WrBuffer> buffers;
		const size_t cnt =
			this->writable_buffers_from_range(buffers, virt_base + size_memory, remaining);
		// preadv() the remaining bytes
		const int result =
			preadv64(fd, (const iovec *)buffers.data(), cnt, off + size_memory);
		if (result < 0) {
			throw MemoryException("Failed to preadv for mmap", virt_base + size_memory, remaining);
		}
	}

	if constexpr (VERBOSE_FILE_BACKED_MMAP) {
		printf("mmap: allocated %zu/%zu bytes at 0x%lX, phys 0x%lX prot 0x%X\n",
			size_memory, size_bytes, virt_base, mmap_phys_base, prot);
	}
	return true;
}
bool Machine::has_mmap_backed_area(int fd, int off, address_t addr, size_t size) const
{
	(void) fd; (void) off;
	for (const auto& range : memory.mmap_ranges) {
		if (range.overlaps(addr, size)) {
			//if (range.fd == fd && range.off == off)
			return true;
		}
	}
	return false;
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
