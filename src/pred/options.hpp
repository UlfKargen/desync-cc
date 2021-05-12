#ifndef DESYNC_OPTIONS_H
#define DESYNC_OPTIONS_H

#include <stdexcept>       // std::runtime_error
#include <string_view>     // std::string_view
#include <util/string.hpp> // desync::util::concat
#include <vector>          // std::vector

namespace desync {

struct options final {
	struct error final : std::runtime_error {
		[[nodiscard]] explicit error(const auto&... args)
			: std::runtime_error(util::concat(args...)) {}
	};

	[[nodiscard]] static constexpr auto usage() noexcept -> std::string_view {
		return R"(Options:\n
  -h --help                 Display this information.
  -V --version              Display version information.
  -v --verbose              Print more information while running.
  -d --dry-run				Don't write any file changes.
  -c --config-string <arg>  Specify configuration string to use.
  -f --config-file <arg>    Specify configuration file to read and use.
  -l --log-file <arg>		Specify log file to write to.)";
	}

	[[nodiscard]] static auto from_command_line(int argc, char* argv[]) -> options {
		auto opts = options{};
		opts.parse_command_line(argc, argv);
		return opts;
	}

	std::vector<std::string_view> arguments{};
	bool help = false;
	bool version = false;
	bool verbose = false;
	bool dry_run = false;
	std::string_view config_string{};
	std::string_view config_file{};
	std::string_view log_file{};

	auto parse_command_line(int argc, char* argv[]) -> void {
		auto i = 1;

		const auto read_required_argument = [&i, argc, argv](std::string_view option_name) -> std::string_view {
			++i;
			if (i >= argc) {
				throw error{"Option \"", option_name, "\" requires an argument."};
			}
			return argv[i];
		};

		for (; i < argc; ++i) {
			const auto argument = std::string_view{argv[i]};
			if (argument.size() > 1 && argument[0] == '-') {
				if (argument.size() > 2 && argument[1] == '-') {
					const auto long_name = argument.substr(2);
					if (long_name == "help") {
						help = true;
					} else if (long_name == "version") {
						version = true;
					} else if (long_name == "verbose") {
						verbose = true;
					} else if (long_name == "dry-run") {
						dry_run = true;
					} else if (long_name == "config-string") {
						config_string = read_required_argument("config-string");
					} else if (long_name == "config-file") {
						config_file = read_required_argument("config-file");
					} else if (long_name == "log-file") {
						log_file = read_required_argument("log-file");
					} else {
						throw error{"Unknown option --", long_name};
					}
				} else {
					for (const auto name : argument.substr(1)) {
						switch (name) {
							case 'h':
								help = true;
								break;
							case 'V':
								version = true;
								break;
							case 'v':
								verbose = true;
								break;
							case 'd':
								dry_run = true;
								break;
							case 'c':
								break;
							case 'f':
								break;
							case 'l':
								break;
							default:
								throw error{"Unknown option -", name};
						}
					}
					switch (argument.back()) {
						case 'c':
							config_string = read_required_argument("config-string");
							break;
						case 'f':
							config_file = read_required_argument("config-file");
							break;
						case 'l':
							log_file = read_required_argument("log-file");
							break;
						default:
							break;
					}
				}
			} else {
				arguments.push_back(argument);
			}
		}
	}
};

} // namespace desync

#endif
