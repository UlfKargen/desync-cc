#ifndef DESYNC_UTIL_PRINT_H
#define DESYNC_UTIL_PRINT_H

#include <iostream> // std::cerr

namespace desync {
namespace util {

inline auto print(const auto&... args) -> void {
	(std::cerr << ... << args);
}

inline auto println(const auto&... args) -> void {
	print(args..., '\n');
}

} // namespace util
} // namespace desync

#endif
