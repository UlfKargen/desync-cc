#ifndef DESYNC_UTIL_STRING_H
#define DESYNC_UTIL_STRING_H

#include <sstream>     // std::ostringstream
#include <string>      // std::string
#include <string_view> // std::string_view

namespace desync {
namespace util {

[[nodiscard]] inline auto concat(const auto&... args) -> std::string {
	auto stream = std::ostringstream{};
	(stream << ... << args);
	return stream.str();
}

[[nodiscard]] inline auto left_align(std::string_view text, std::size_t maximum_padding, char padding = ' ') -> std::string {
	auto result = std::string{};
	for (const auto ch : text) {
		if (ch == '\t') {
			result.push_back(padding);
			result.push_back(padding);
			result.push_back(padding);
			result.push_back(padding);
		} else {
			result.push_back(ch);
		}
	}
	for (auto column = result.size(); column < maximum_padding; ++column) {
		result.push_back(padding);
	}
	return result;
}

} // namespace util
} // namespace desync

#endif
