#ifndef DESYNC_DESYNCHRONIZER_H
#define DESYNC_DESYNCHRONIZER_H

#include <cassert>                     // assert
#include <cstddef>                     // std::size_t
#include <cstdint>                     // std::uint8_t
#include <limits>                      // std::numeric_limits
#include <memory>                      // std::unique_ptr, std::make_unique
#include <ostream>                     // std::ostream
#include <pred/configuration.hpp>      // desync::configuration
#include <pred/control_flow_graph.hpp> // desync::control_flow_graph
#include <pred/predicate_parser.hpp>   // desync::predicate_parser
#include <random>                      // std::mt19937, std::random_device, std::..._distribution
#include <regex>                       // std::regex, std::regex_match
#include <sstream>                     // std::ostringstream
#include <stdexcept>                   // std::runtime_error
#include <string>                      // std::string
#include <string_view>                 // std::string_view
#include <unordered_map>               // std::unordered_map
#include <util/file.hpp>               // desync::util::read_file
#include <util/print.hpp>              // desync::util::println
#include <util/string.hpp>             // desync::util::concat
#include <utility>                     // std::move
#include <vector>                      // std::vector

namespace desync {

class desynchronizer final {
public:
	struct error final : std::runtime_error {
		[[nodiscard]] explicit error(const auto&... args)
			: std::runtime_error(util::concat(args...)) {}
	};

	auto configure(const configuration& config) -> void {
		m_verbose = config.verbose;
		m_instruction_pattern.assign(std::string{config.instruction_pattern});
		const auto seed = configure_seed(config);
		configure_junk_length_distribution(config);
		configure_interval_distribution(config);
		configure_predicates(config);
		if (m_verbose) {
			print_configuration(config, seed);
		}
	}

	[[nodiscard]] auto apply_predicates(std::string_view assembly) -> std::string {
		if (m_predicates.empty()) {
			if (m_verbose) {
				util::println("No predicates to apply.");
			}
			return std::string{assembly};
		}

		const auto cfg = control_flow_graph::liveness_analyzed(assembly);
		if (m_verbose) {
			print_control_flow_graph(assembly, cfg);
		}

		// TODO: Find and choose predicate applications in the cfg.
		// TODO: Sort predicate applications by their assembly index
		//       (assembly index is instruction.string.data() - assembly.data()).
		auto stream = std::ostringstream{};
		// TODO: Output assembly with predicates, junk bytes and symbols interleaved.
		stream << assembly;
		return stream.str();
	}

private:
	static constexpr auto desync_label_name = std::string_view{"DESYNC"};
	static constexpr auto desync_label_replacement_index = std::numeric_limits<std::size_t>::max();

	class predicate final {
	public:
		enum class parameter_type : std::uint8_t {
			r32,
			r64,
		};

		predicate(std::string name, const predicate_parser::predicate& parsed_predicate, std::string_view filename) {
			m_name = std::move(name);
			m_body = std::make_unique<char[]>(parsed_predicate.body.size());
			parsed_predicate.body.copy(m_body.get(), parsed_predicate.body.size());
			const auto body = std::string_view{m_body.get(), parsed_predicate.body.size()};

			m_parameters.reserve(parsed_predicate.parameters.size());
			for (const auto& parameter : parsed_predicate.parameters) {
				if (parameter.type == "r32") {
					m_parameters.push_back(parameter_type::r32);
				} else if (parameter.type == "r64") {
					m_parameters.push_back(parameter_type::r64);
				} else {
					throw error{filename, ": Unknown parameter type \"", parameter.type, "\""};
				}
			}

			auto piece_begin = std::size_t{0};
			for (auto i = std::size_t{0}; i < body.size(); ++i) {
				if (body.compare(i, desync_label_name.size(), desync_label_name) == 0) {
					m_replacement_indices.push_back(desync_label_replacement_index);
					m_pieces.push_back(body.substr(piece_begin, i - piece_begin));
					i += desync_label_name.size();
					piece_begin = i;
					--i;
				} else {
					for (auto parameter_index = std::size_t{0}; parameter_index < parsed_predicate.parameters.size(); ++parameter_index) {
						const auto& parameter = parsed_predicate.parameters[parameter_index];
						if (body.compare(i, parameter.name.size(), parameter.name) == 0) {
							m_replacement_indices.push_back(parameter_index);
							m_pieces.push_back(body.substr(piece_begin, i - piece_begin));
							i += parameter.name.size();
							piece_begin = i;
							--i;
							break;
						}
					}
				}
			}
			m_pieces.push_back(body.substr(piece_begin));
		}

		auto apply(std::ostream& out, std::string_view label, std::span<const std::string_view> arguments) const -> void {
			assert(arguments.size() == m_parameters.size());
			assert(m_pieces.size() == m_replacement_indices.size() + 1);
			for (auto i = std::size_t{0}; i < m_replacement_indices.size(); ++i) {
				const auto& piece = m_pieces[i];
				const auto& replacement_index = m_replacement_indices[i];
				out << piece;
				if (replacement_index == desync_label_replacement_index) {
					out << label;
				} else {
					assert(desync_label_replacement_index < arguments.size());
					out << arguments[desync_label_replacement_index];
				}
			}
			out << m_pieces.back();
		}

		[[nodiscard]] auto name() const noexcept -> std::string_view {
			return m_name;
		}

		[[nodiscard]] auto parameters() const noexcept -> std::span<const parameter_type> {
			return std::span{m_parameters};
		}

	private:
		std::string m_name{};
		std::unique_ptr<char[]> m_body{};
		std::vector<std::string_view> m_pieces{};
		std::vector<std::size_t> m_replacement_indices{};
		std::vector<parameter_type> m_parameters{};
	};

	static auto print_control_flow_graph(std::string_view assembly, const control_flow_graph& cfg) -> void {
		util::println(
			"===================================================================\n"
			"ASSEMBLY\n"
			"===================================================================\n",
			assembly,
			"\n"
			"===================================================================\n"
			"CONTROL FLOW GRAPH\n"
			"===================================================================\n",
			cfg);
	}

	auto configure_seed(const configuration& config) -> std::mt19937::result_type {
		auto seed = std::mt19937::result_type{};
		if (config.seed) {
			if (*config.seed > std::numeric_limits<decltype(seed)>::max()) {
				throw error{"Seed value out of range."};
			}
			seed = static_cast<decltype(seed)>(*config.seed);
		} else {
			seed = static_cast<decltype(seed)>(std::random_device{}());
		}
		m_random_number_generator.seed(seed);
		return seed;
	}

	auto configure_junk_length_distribution(const configuration& config) -> void {
		m_junk_length_distribution = config.junk_length_distribution;
		m_junk_length_constant = config.junk_length_constant;
		m_junk_length_uniform = decltype(m_junk_length_uniform){
			config.junk_length_uniform_min,
			config.junk_length_uniform_max,
		};
		m_junk_length_normal = decltype(m_junk_length_normal){
			config.junk_length_normal_mean,
			config.junk_length_normal_stddev,
		};
	}

	auto configure_interval_distribution(const configuration& config) -> void {
		m_interval_distribution = config.interval_distribution;
		m_interval_constant = config.interval_constant;
		m_interval_uniform = decltype(m_interval_uniform){
			config.interval_uniform_min,
			config.interval_uniform_max,
		};
		m_interval_normal = decltype(m_interval_normal){
			config.interval_normal_mean,
			config.interval_normal_stddev,
		};
	}

	auto configure_predicates(const configuration& config) -> void {
		const auto pattern = std::regex{std::string{config.predicate_pattern}};
		auto weights = std::vector<double>{};
		auto soruce_files = std::unordered_map<std::string_view, std::string_view>{};
		for (const auto& predicate_file : config.predicate_files) {
			if (const auto code = util::read_file(std::string{predicate_file}.c_str())) {
				const auto parsed_predicates = predicate_parser::parse_predicates(predicate_file, *code);
				for (const auto& parsed_predicate : parsed_predicates) {
					if (const auto [source_file_it, inserted] = soruce_files.emplace(parsed_predicate.name, predicate_file); !inserted) {
						throw error{predicate_file, ": Predicate name \"", parsed_predicate.name, "\" already defined in ", source_file_it->second};
					}

					auto name = std::string{parsed_predicate.name};
					if (!std::regex_match(name, pattern)) {
						continue;
					}

					auto& weight = weights.emplace_back(1.0);
					if (const auto weight_it = config.predicate_weights.find(parsed_predicate.name); weight_it != config.predicate_weights.end()) {
						weight = weight_it->second;
					}

					m_predicates.emplace_back(std::move(name), parsed_predicate, predicate_file);
				}
			} else {
				throw error{"Failed to open predicate file \"", predicate_file, "\" for reading."};
			}
		}

		m_predicate_distribution = config.predicate_distribution;
		m_predicate_uniform = decltype(m_predicate_uniform){
			0,
			(m_predicates.empty()) ? 0 : m_predicates.size() - 1,
		};
		m_predicate_discrete = decltype(m_predicate_discrete){
			weights.begin(),
			weights.end(),
		};
	}

	auto print_configuration(const configuration& config, std::mt19937::result_type seed) const -> void {
		// clang-format off
		util::println(
			"===================================================================\n"
			"CONFIGURATION\n"
			"===================================================================\n"
			"seed ", seed, "\n"
			"instruction_pattern ", config.instruction_pattern);
		switch (m_junk_length_distribution) {
			case configuration::junk_length_distribution_type::constant:
				util::println(
					"junk_length_distribution constant\n"
					"junk_length ", m_junk_length_constant);
				break;
			case configuration::junk_length_distribution_type::uniform:
				util::println(
					"junk_length_distribution uniform\n"
					"junk_length_min ", m_junk_length_uniform.a(), "\n"
					"junk_length_max ", m_junk_length_uniform.b());
				break;
			case configuration::junk_length_distribution_type::normal:
				util::println(
					"junk_length_distribution normal\n"
					"junk_length_mean ", m_junk_length_normal.mean(), "\n"
					"junk_length_stddev ", m_junk_length_normal.stddev());
				break;
		}
		switch (m_interval_distribution) {
			case configuration::interval_distribution_type::constant:
				util::println(
					"interval_distribution constant\n"
					"interval ", m_interval_constant);
				break;
			case configuration::interval_distribution_type::uniform:
				util::println(
					"interval_distribution uniform\n"
					"interval_min ", m_interval_uniform.a(), "\n"
					"interval_max ", m_interval_uniform.b());
				break;
			case configuration::interval_distribution_type::normal:
				util::println(
					"interval_distribution normal\n"
					"interval_mean ", m_interval_normal.mean(), "\n"
					"interval_stddev ", m_interval_normal.stddev());
				break;
		}
		for (const auto& predicate_file : config.predicate_files) {
			util::println("predicate_file ", predicate_file);
		}
		util::println("predicate_pattern ", config.predicate_pattern);
		switch (m_predicate_distribution) {
			case configuration::predicate_distribution_type::uniform:
				util::println("predicate_distribution uniform");
				break;
			case configuration::predicate_distribution_type::discrete:
				util::println("predicate_distribution discrete");
				break;
		}
		for (const auto& [name, weight] : config.predicate_weights) {
			util::println("predicate_weight ", name, " ", weight);
		}
		util::println(
			"===================================================================\n"
			"PREDICATES\n"
			"===================================================================");
		for (const auto& predicate : m_predicates) {
			util::println("predicate ", predicate.name());
		}
		// clang-format on
	}

	std::mt19937 m_random_number_generator{};
	std::regex m_instruction_pattern{};
	configuration::junk_length_distribution_type m_junk_length_distribution{};
	configuration::interval_distribution_type m_interval_distribution{};
	configuration::predicate_distribution_type m_predicate_distribution{};
	std::size_t m_junk_length_constant{};
	std::size_t m_interval_constant{};
	std::uniform_int_distribution<std::size_t> m_junk_length_uniform{};
	std::uniform_int_distribution<std::size_t> m_interval_uniform{};
	std::uniform_int_distribution<std::size_t> m_predicate_uniform{};
	std::normal_distribution<double> m_junk_length_normal{};
	std::normal_distribution<double> m_interval_normal{};
	std::discrete_distribution<std::size_t> m_predicate_discrete{};
	std::vector<predicate> m_predicates{};
	bool m_verbose = false;
};

} // namespace desync

#endif
