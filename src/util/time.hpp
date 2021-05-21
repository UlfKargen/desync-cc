#ifndef DESYNC_UTIL_TIME_H
#define DESYNC_UTIL_TIME_H

#include <cstddef> // std::size_t
#include <ctime>   // std::time, std::tm, std::strftime, localtime_s
#include <string>  // std::string
#ifndef _WIN32
#include <time.h> // localtime_r // NOLINT(modernize-deprecated-headers)
#endif

namespace desync {
namespace util {

[[nodiscard]] inline auto local_time_string(const char* format) -> std::string {
	const auto t = std::time(nullptr);

	auto local_time = std::tm{};
#ifdef _WIN32
	localtime_s(&local_time, &t);
#else
	localtime_r(&t, &local_time);
#endif

	static constexpr auto max_size = std::size_t{128};
	auto result = std::string(max_size, '\0');
	if (const auto count = std::strftime(result.data(), result.size(), format, &local_time)) {
		result.erase(count, std::string::npos);
	} else {
		result.clear();
	}
	return result;
}

} // namespace util
} // namespace desync

#endif
