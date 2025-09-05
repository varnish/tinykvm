#pragma once

#include <cstdint>
#include <ctime>
#include <cstring>
#include <stdexcept>
#include <vector>
#include "../common.hpp"

namespace tinykvm {

template <MachineProfiling::Location Which>
struct ScopedProfiler {
	ScopedProfiler(MachineProfiling* profiling) {
		if (profiling) {
			m_storage = &profiling->times.at(Which);
			this->m_start_time = get_time_ns();
		}
	}

	~ScopedProfiler() {
		if (m_storage) {
			const uint64_t end_time = get_time_ns();
			m_storage->push_back(end_time - m_start_time);
		}
	}
private:
	static uint64_t get_time_ns() {
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		return uint64_t(ts.tv_sec) * 1'000'000'000ULL + uint64_t(ts.tv_nsec);
	}

	std::vector<uint64_t>* m_storage = nullptr;
	uint64_t m_start_time = 0;
};

} // namespace tinykvm
