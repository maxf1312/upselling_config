#pragma once

#include <chrono>

namespace ProLoyalty {
	namespace ClockUtils {
		using clock_t = std::chrono::high_resolution_clock;
		using time_point_t = clock_t::time_point;
		using microseconds_t = std::chrono::microseconds;
		using milliseconds_t = std::chrono::milliseconds;

		inline microseconds_t   duration_us(time_point_t t0, time_point_t t1) { return std::chrono::duration_cast<microseconds_t>(t1 - t0); }
		inline milliseconds_t   duration_ms(time_point_t t0, time_point_t t1) { return std::chrono::duration_cast<milliseconds_t>(t1 - t0); }
		
		class ElapsedTimeCounter 
		{
		public:
			ElapsedTimeCounter() : m_t0{clock_t::now()} {  }

			ElapsedTimeCounter& reset() { m_t0 = clock_t::now(); return *this; }

			microseconds_t  DurationUs() { return ClockUtils::duration_us(m_t0, clock_t::now()); }
			milliseconds_t  DurationMs() { return ClockUtils::duration_ms(m_t0, clock_t::now()); }

		private:
			time_point_t  m_t0;
		};

	} //namespace ClockUtils
} //namespace ProLoyalty

