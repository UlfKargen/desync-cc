#ifndef DESYNC_DESYNCHRONIZER_H
#define DESYNC_DESYNCHRONIZER_H

#include <algorithm>                   // std::max
#include <bitset>                      // std::bitset
#include <cassert>                     // assert
#include <cmath>                       // std::round
#include <cstddef>                     // std::size_t
#include <cstdint>                     // std::uint8_t
#include <limits>                      // std::numeric_limits
#include <memory>                      // std::unique_ptr, std::make_unique
#include <optional>                    // std::optional
#include <ostream>                     // std::ostream
#include <pred/assembler.hpp>          // desync::assembler
#include <pred/configuration.hpp>      // desync::configuration
#include <pred/control_flow_graph.hpp> // desync::control_flow_graph
#include <pred/disassembler.hpp>       // desync::disassembler
#include <pred/predicate_parser.hpp>   // desync::predicate_parser
#include <random>                      // std::mt19937, std::random_device, std::..._distribution
#include <regex>                       // std::regex, std::regex_match
#include <span>                        // std::span
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
		auto result = std::string{};
		if (m_predicates.empty()) {
			if (m_verbose) {
				util::println("No predicates to apply.");
			}
			result = assembly;
		} else {
			const auto cfg = control_flow_graph::liveness_analyzed(assembly, m_assembler, m_disassembler);
			if (m_verbose) {
				print_control_flow_graph(assembly, cfg);
			}

			auto stream = std::ostringstream{};
			auto assembly_rest = std::size_t{0};
			auto next = std::size_t{0};
			auto predicate_count = std::size_t{0};
			const auto& instructions = cfg.instructions();
			for (auto i = std::size_t{0}; i < instructions.size(); i = next) {
				const auto& predicate = m_predicates[generate_predicate()];
				while (i < instructions.size()) {
					if (std::regex_match(std::string{instructions[i].string}, m_instruction_pattern)) {
						if (const auto arguments = predicate.find_arguments(~instructions[i].live_registers, ~instructions[i].live_flags, m_disassembler)) {
							const auto assembly_index = instructions[i].string.data() - assembly.data();
							stream << assembly.substr(assembly_rest, assembly_index - assembly_rest) << '\n';
							assembly_rest = assembly_index;
							const auto junk_length = generate_junk_length();
							const auto junk_label = util::concat("desyncpoint", predicate_count, '_', junk_length);
							const auto jump_label = util::concat(".Ldesyncjump", predicate_count);
							++predicate_count;
							predicate.apply(stream, jump_label, std::span{*arguments});
							stream << '\n' << junk_label << ":\n";
							for (auto n = std::size_t{0}; n < junk_length; ++n) {
								stream << "nop\n";
							}
							stream << jump_label << ":\n";
							break;
						}
					}
					++i;
				}
				if (i >= instructions.size()) {
					break;
				}
				next += generate_interval();
				next = std::max(i, next);
			}
			stream << assembly.substr(assembly_rest);
			result = stream.str();
			if (m_verbose) {
				print_result(result, predicate_count);
			}
		}
		return result;
	}

private:
	static constexpr auto desync_label_name = std::string_view{"DESYNC"};
	static constexpr auto desync_label_replacement_index = std::numeric_limits<std::size_t>::max();

	class predicate final {
	public:
		enum class parameter_type : std::uint8_t {
			r8,
			r16,
			r32,
			r64,
		};

		[[nodiscard]] static auto applicable_registers(parameter_type parameter) -> std::bitset<disassembler::register_count> {
			switch (parameter) {
				case parameter_type::r8:
					return disassembler::registers_8bit();
				case parameter_type::r16:
					return disassembler::registers_16bit();
				case parameter_type::r32:
					return disassembler::registers_32bit();
				case parameter_type::r64:
					return disassembler::registers_64bit();
			}
			return {};
		}

		predicate(std::string name, const predicate_parser::predicate& parsed_predicate, std::string_view filename, const assembler& assembler, const disassembler& disassembler) {
			m_name = std::move(name);
			m_body = std::make_unique<char[]>(parsed_predicate.body.size());
			parsed_predicate.body.copy(m_body.get(), parsed_predicate.body.size());
			const auto body = std::string_view{m_body.get(), parsed_predicate.body.size()};

			m_parameters.reserve(parsed_predicate.parameters.size());
			for (const auto& parameter : parsed_predicate.parameters) {
				if (parameter.type == "r8") {
					m_parameters.push_back(parameter_type::r8);
				} else if (parameter.type == "r16") {
					m_parameters.push_back(parameter_type::r16);
				} else if (parameter.type == "r32") {
					m_parameters.push_back(parameter_type::r32);
				} else if (parameter.type == "r64") {
					m_parameters.push_back(parameter_type::r64);
				} else {
					throw error{filename, ": Predicate \"", m_name, "\": Unknown parameter type \"", parameter.type, "\""};
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

			check_assembly(filename, assembler, disassembler);
		}

		[[nodiscard]] auto find_arguments(std::bitset<disassembler::register_count> free_registers, std::bitset<disassembler::flag_count> free_flags,
			const disassembler& disassembler) const -> std::optional<std::vector<std::string>> {
			auto result = std::optional<std::vector<std::string>>{};
			if ((free_flags & m_required_flags) == m_required_flags && free_registers.count() >= m_parameters.size()) {
				auto& arguments = result.emplace();
				for (const auto& parameter : m_parameters) {
					auto found = false;
					for (auto i = std::size_t{0}; i < free_registers.size(); ++i) {
						if (free_registers[i] && applicable_registers(parameter)[i]) {
							arguments.emplace_back(disassembler.register_name(i));
							free_registers &= ~disassembler::related_registers(i);
							found = true;
							break;
						}
					}
					if (!found) {
						result.reset();
						break;
					}
				}
			}
			return result;
		}

		auto apply(std::ostream& out, std::string_view label, std::span<const std::string> arguments) const -> void {
			assert(arguments.size() == m_parameters.size());
			assert(m_pieces.size() == m_replacement_indices.size() + 1);

			for (auto i = std::size_t{0}; i < m_replacement_indices.size(); ++i) {
				const auto& piece = m_pieces[i];
				const auto& replacement_index = m_replacement_indices[i];
				out << piece;
				if (replacement_index == desync_label_replacement_index) {
					out << label;
				} else {
					assert(replacement_index < arguments.size());
					out << arguments[replacement_index];
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
		auto check_assembly(std::string_view filename, const assembler& assembler, const disassembler& disassembler) -> void {
			auto free_registers = std::bitset<disassembler::register_count>{};
			free_registers.set();
			auto free_flags = std::bitset<disassembler::flag_count>{};
			free_flags.set();
			const auto arguments = find_arguments(free_registers, free_flags, disassembler);
			if (!arguments) {
				throw error{filename, ": Predicate \"", m_name, "\": Failed to find suitable registers for parameters."};
			}
			auto stream = std::ostringstream{};
			apply(stream, "dummy_label", std::span{*arguments});
			const auto assembly = stream.str();
			try {
				const auto assemble_result = assembler.assemble(assembly);
				const auto disassemble_result = disassembler.disassemble(assemble_result.encoding);
				for (const auto& instruction : std::span{disassemble_result.instructions.data(), disassemble_result.instructions.size()}) {
					const auto access = disassembler.access(instruction);
					m_required_flags |= access.flags_written;
				}
			} catch (const assembler::error& e) {
				throw error{filename, ": Predicate \"", m_name, "\": Assembler error: ", e.what()};
			} catch (const disassembler::error& e) {
				throw error{filename, ": Predicate \"", m_name, "\": Disassembler error: ", e.what()};
			}
		}

		std::string m_name{};
		std::unique_ptr<char[]> m_body{};
		std::vector<std::string_view> m_pieces{};
		std::vector<std::size_t> m_replacement_indices{};
		std::vector<parameter_type> m_parameters{};
		std::bitset<disassembler::flag_count> m_required_flags{};
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

	static auto print_result(std::string_view assembly, std::size_t predicate_count) -> void {
		util::println(
			"===================================================================\n"
			"RESULT\n"
			"===================================================================\n"
			"Predicates inserted: ",
			predicate_count,
			"\n",
			assembly);
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
		if (config.junk_length_uniform_min > config.junk_length_uniform_max) {
			throw error{"Configuration error: junk length minimum value cannot be greater than the maximum value."};
		}
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
		if (config.interval_constant < 1) {
			throw error{"Configuration error: interval constant value must be at least 1."};
		}
		m_interval_constant = config.interval_constant;
		if (config.interval_uniform_min > config.interval_uniform_max) {
			throw error{"Configuration error: interval minimum value cannot be greater than the maximum value."};
		}
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
		auto source_files = std::unordered_map<std::string_view, std::string_view>{};
		for (const auto& predicate_file : config.predicate_files) {
			auto filepath = config.base_dir;
			filepath.append(predicate_file);
			if (const auto code = util::read_file(filepath.c_str())) {
				const auto parsed_predicates = predicate_parser::parse_predicates(predicate_file, *code);
				for (const auto& parsed_predicate : parsed_predicates) {
					if (const auto [source_file_it, inserted] = source_files.emplace(parsed_predicate.name, predicate_file); !inserted) {
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

					m_predicates.emplace_back(std::move(name), parsed_predicate, predicate_file, m_assembler, m_disassembler);
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

	[[nodiscard]] auto generate_junk_length() -> std::size_t {
		switch (m_junk_length_distribution) {
			case configuration::junk_length_distribution_type::constant:
				return m_junk_length_constant;
			case configuration::junk_length_distribution_type::uniform:
				return m_junk_length_uniform(m_random_number_generator);
			case configuration::junk_length_distribution_type::normal:
				return static_cast<std::size_t>(std::round(std::max(m_junk_length_normal(m_random_number_generator), 0.0)));
		}
		return std::size_t{};
	}

	[[nodiscard]] auto generate_interval() -> std::size_t {
		switch (m_interval_distribution) {
			case configuration::interval_distribution_type::constant:
				return m_interval_constant;
			case configuration::interval_distribution_type::uniform:
				return std::max(m_interval_uniform(m_random_number_generator), std::size_t{1});
			case configuration::interval_distribution_type::normal:
				return static_cast<std::size_t>(std::round(std::max(m_interval_normal(m_random_number_generator), 1.0)));
		}
		return std::size_t{};
	}

	[[nodiscard]] auto generate_predicate() -> std::size_t {
		switch (m_predicate_distribution) {
			case configuration::predicate_distribution_type::uniform:
				return m_predicate_uniform(m_random_number_generator);
			case configuration::predicate_distribution_type::discrete:
				return m_predicate_discrete(m_random_number_generator);
		}
		return std::size_t{};
	}

	desync::assembler m_assembler{};
	desync::disassembler m_disassembler{};
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
