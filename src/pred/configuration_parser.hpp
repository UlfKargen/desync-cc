#ifndef DESYNC_CONFIGURATION_PARSER_H
#define DESYNC_CONFIGURATION_PARSER_H

#include <cstddef>     // std::size_t
#include <string_view> // std::string_view
#include <vector>      // std::vector

namespace desync {

class configuration_parser final {
public:
	struct command final {
		std::string_view name{};
		std::string_view value{};
	};

	[[nodiscard]] static auto parse_commands(std::string_view config_string) -> std::vector<command> {
		auto result = std::vector<command>{};
		auto line_begin = std::size_t{0};
		while (line_begin < config_string.size()) {
			const auto line_end = config_string.find_first_of(",\n", line_begin);
			const auto line = config_string.substr(line_begin, line_end - line_begin);
			if (const auto command_begin = line.find_first_not_of(" \t"); command_begin != std::string_view::npos) {
				result.push_back(parse_command(line.substr(command_begin)));
			}
			if (line_end == std::string_view::npos) {
				break;
			}
			line_begin = line_end + 1;
		}
		return result;
	}

private:
	[[nodiscard]] static auto parse_command(std::string_view line) -> command {
		const auto name = line.substr(0, line.find_first_of(" \t"));
		const auto value_begin = line.find_first_not_of(" \t", name.size());
		const auto value_last = line.find_last_not_of(" \t");
		const auto value_end = (value_last == std::string_view::npos) ? line.size() : value_last + 1;
		const auto value = (value_begin == std::string_view::npos || value_begin >= value_end) ? std::string_view{} : line.substr(value_begin, value_end - value_begin);
		return command{name, value};
	}
};

} // namespace desync

#endif
