#ifndef DESYNC_UTIL_STRING_H
#define DESYNC_UTIL_STRING_H

#include <sstream> // std::ostringstream
#include <string>  // std::string

namespace desync {
namespace util {

[[nodiscard]] inline auto concat(const auto&... args) -> std::string {
	auto stream = std::ostringstream{};
	(stream << ... << args);
	return stream.str();
}

} // namespace util
} // namespace desync

#endif
