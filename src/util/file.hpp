#ifndef DESYNC_UTIL_FILE_H
#define DESYNC_UTIL_FILE_H

#include <fstream>     // std::ifstream, std::ofstream
#include <optional>    // std::optional, std::nullopt
#include <sstream>     // std::ostringstream
#include <string>      // std::string
#include <string_view> // std::string_view

namespace desync {
namespace util {

[[nodiscard]] inline auto read_file(const char* filename) -> std::optional<std::string> {
	if (auto file = std::ifstream{filename}) {
		if (auto stream = std::ostringstream{}; stream << file.rdbuf()) {
			return stream.str();
		}
	}
	return std::nullopt;
}

[[nodiscard]] inline auto write_file(const char* filename, std::string_view file_contents) -> bool {
	if (auto file = std::ofstream{filename, std::ofstream::out | std::ofstream::trunc}) {
		if (file << file_contents) {
			return true;
		}
	}
	return false;
}

} // namespace util
} // namespace desync

#endif
