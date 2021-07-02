#ifndef DESYNC_CONFIGURATION_H
#define DESYNC_CONFIGURATION_H

#include <cstddef>                       // std::size_t
#include <cstdint>                       // std::uint8_t
#include <optional>                      // std::optional
#include <pred/configuration_parser.hpp> // desync::configuration_parser
#include <stdexcept>                     // std::runtime_error
#include <string>                        // std::string, std::stoul, std::stod
#include <string_view>                   // std::string_view
#include <unordered_map>                 // std::unordered_map
#include <util/string.hpp>               // desync::util::concat
#include <vector>                        // std::vector

namespace desync {

struct configuration final {
	struct error final : std::runtime_error {
		[[nodiscard]] explicit error(const auto&... args)
			: std::runtime_error(util::concat(args...)) {}
	};

	enum class junk_length_distribution_type : std::uint8_t {
		constant,
		uniform,
		normal,
	};

	enum class interval_distribution_type : std::uint8_t {
		constant,
		uniform,
		normal,
	};

	enum class predicate_distribution_type : std::uint8_t {
		uniform,
		discrete,
	};

	static constexpr auto default_junk_length = std::size_t{2};
	static constexpr auto default_interval = std::size_t{10};

	junk_length_distribution_type junk_length_distribution = junk_length_distribution_type::constant;
	interval_distribution_type interval_distribution = interval_distribution_type::constant;
	predicate_distribution_type predicate_distribution = predicate_distribution_type::uniform;
	std::size_t junk_length_constant = default_junk_length;
	std::size_t interval_constant = default_interval;
	std::size_t junk_length_uniform_min = default_junk_length;
	std::size_t junk_length_uniform_max = default_junk_length;
	std::size_t interval_uniform_min = default_interval;
	std::size_t interval_uniform_max = default_interval;
	double junk_length_normal_mean = static_cast<double>(default_junk_length);
	double junk_length_normal_stddev = 0.0;
	double interval_normal_mean = static_cast<double>(default_interval);
	double interval_normal_stddev = 0.0;
	std::string instruction_pattern = ".*";
	std::string predicate_pattern = ".*";
	std::vector<std::string> predicate_files{};
	std::unordered_map<std::string, std::size_t> predicate_weights{};
	std::optional<std::size_t> seed{};
	std::string log_file{};
	std::string base_dir{"./"};
	bool verbose = false;
	bool print_config = false;
	bool print_assembly = false;
	bool print_cfg = false;
	bool print_result = false;
	bool print_stats = false;
	bool dry_run = false;

	auto parse_string(std::string_view config_string) -> void {
		for (const auto [name, value] : configuration_parser::parse_commands(config_string)) {
			const auto& handlers = command_handlers();
			if (const auto handler_it = handlers.find(name); handler_it != handlers.end()) {
				handler_it->second(*this, value);
			} else {
				throw error{"Unknown configuration command \"", name, "\""};
			}
		}
	}

private:
	using command_handler = void (*)(configuration& config, std::string_view value);

	[[nodiscard]] static auto command_handlers() -> const std::unordered_map<std::string_view, command_handler>& {
		static auto table = std::unordered_map<std::string_view, command_handler>{
			{"log_file",
				[](configuration& config, std::string_view value) -> void {
					config.log_file = std::string{value};
				}},
			{"verbose",
				[](configuration& config, std::string_view value) -> void {
					if (value == "true") {
						config.verbose = true;
					} else if (value == "false") {
						config.verbose = false;
					} else {
						throw error{"Invalid verbosity setting \"", value, "\""};
					}
				}},
			{"print_config",
				[](configuration& config, std::string_view value) -> void {
					if (value == "true") {
						config.print_config = true;
					} else if (value == "false") {
						config.print_config = false;
					} else {
						throw error{"Invalid print config setting \"", value, "\""};
					}
				}},
			{"print_assembly",
				[](configuration& config, std::string_view value) -> void {
					if (value == "true") {
						config.print_assembly = true;
					} else if (value == "false") {
						config.print_assembly = false;
					} else {
						throw error{"Invalid print assembly setting \"", value, "\""};
					}
				}},
			{"print_cfg",
				[](configuration& config, std::string_view value) -> void {
					if (value == "true") {
						config.print_cfg = true;
					} else if (value == "false") {
						config.print_cfg = false;
					} else {
						throw error{"Invalid print cfg setting \"", value, "\""};
					}
				}},
			{"print_result",
				[](configuration& config, std::string_view value) -> void {
					if (value == "true") {
						config.print_result = true;
					} else if (value == "false") {
						config.print_result = false;
					} else {
						throw error{"Invalid print result setting \"", value, "\""};
					}
				}},
			{"print_stats",
				[](configuration& config, std::string_view value) -> void {
					if (value == "true") {
						config.print_stats = true;
					} else if (value == "false") {
						config.print_stats = false;
					} else {
						throw error{"Invalid print stats setting \"", value, "\""};
					}
				}},
			{"dry_run",
				[](configuration& config, std::string_view value) -> void {
					if (value == "true") {
						config.dry_run = true;
					} else if (value == "false") {
						config.dry_run = false;
					} else {
						throw error{"Invalid dry run setting \"", value, "\""};
					}
				}},
			{"seed",
				[](configuration& config, std::string_view value) -> void {
					if (value == "random") {
						config.seed.reset();
					} else {
						config.seed.emplace(std::stoul(std::string{value}));
					}
				}},
			{"junk_length_distribution",
				[](configuration& config, std::string_view value) -> void {
					if (value == "constant") {
						config.junk_length_distribution = junk_length_distribution_type::constant;
					} else if (value == "uniform") {
						config.junk_length_distribution = junk_length_distribution_type::uniform;
					} else if (value == "normal") {
						config.junk_length_distribution = junk_length_distribution_type::normal;
					} else {
						throw error{"Invalid junk length distribution \"", value, "\". Valid distributions are: constant, uniform, normal"};
					}
				}},
			{"junk_length",
				[](configuration& config, std::string_view value) -> void {
					config.junk_length_constant = std::stoul(std::string{value});
				}},
			{"junk_length_min",
				[](configuration& config, std::string_view value) -> void {
					config.junk_length_uniform_min = std::stoul(std::string{value});
				}},
			{"junk_length_max",
				[](configuration& config, std::string_view value) -> void {
					config.junk_length_uniform_max = std::stoul(std::string{value});
				}},
			{"junk_length_mean",
				[](configuration& config, std::string_view value) -> void {
					config.junk_length_normal_mean = std::stod(std::string{value});
				}},
			{"junk_length_stddev",
				[](configuration& config, std::string_view value) -> void {
					config.junk_length_normal_stddev = std::stod(std::string{value});
				}},
			{"interval_distribution",
				[](configuration& config, std::string_view value) -> void {
					if (value == "constant") {
						config.interval_distribution = interval_distribution_type::constant;
					} else if (value == "uniform") {
						config.interval_distribution = interval_distribution_type::uniform;
					} else if (value == "normal") {
						config.interval_distribution = interval_distribution_type::normal;
					} else {
						throw error{"Invalid interval distribution \"", value, "\". Valid distributions are: constant, uniform, normal"};
					}
				}},
			{"interval",
				[](configuration& config, std::string_view value) -> void {
					config.interval_constant = std::stoul(std::string{value});
				}},
			{"interval_min",
				[](configuration& config, std::string_view value) -> void {
					config.interval_uniform_min = std::stoul(std::string{value});
				}},
			{"interval_max",
				[](configuration& config, std::string_view value) -> void {
					config.interval_uniform_max = std::stoul(std::string{value});
				}},
			{"interval_mean",
				[](configuration& config, std::string_view value) -> void {
					config.interval_normal_mean = std::stod(std::string{value});
				}},
			{"interval_stddev",
				[](configuration& config, std::string_view value) -> void {
					config.interval_normal_stddev = std::stod(std::string{value});
				}},
			{"instruction_pattern",
				[](configuration& config, std::string_view value) -> void {
					config.instruction_pattern = std::string{value};
				}},
			{"predicate_file",
				[](configuration& config, std::string_view value) -> void {
					config.predicate_files.push_back(std::string{value});
				}},
			{"predicate_pattern",
				[](configuration& config, std::string_view value) -> void {
					config.predicate_pattern = std::string{value};
				}},
			{"predicate_distribution",
				[](configuration& config, std::string_view value) -> void {
					if (value == "uniform") {
						config.predicate_distribution = predicate_distribution_type::uniform;
					} else if (value == "discrete") {
						config.predicate_distribution = predicate_distribution_type::discrete;
					} else {
						throw error{"Invalid predicate distribution \"", value, "\". Valid distributions are: uniform, discrete"};
					}
				}},
			{"predicate_weight",
				[](configuration& config, std::string_view value) -> void {
					const auto predicate_name = value.substr(0, value.find_first_of(" \t"));
					if (predicate_name.empty()) {
						throw error{"Empty predicate name in predicate weight command"};
					}
					const auto predicate_weight_begin = value.find_first_not_of(" \t", predicate_name.size());
					const auto predicate_weight = (predicate_weight_begin == std::string_view::npos) ? std::string_view{} : value.substr(predicate_weight_begin);
					config.predicate_weights[std::string{predicate_name}] = std::stoul(std::string{predicate_weight});
				}},
		};
		return table;
	}
};

} // namespace desync

#endif
