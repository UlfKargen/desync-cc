#ifndef DESYNC_DESYNCHRONIZER_H
#define DESYNC_DESYNCHRONIZER_H

#include <algorithm>                   // std::max, std::shuffle
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
#include <pred/logger.hpp>             // desync::logger
#include <pred/predicate_parser.hpp>   // desync::predicate_parser
#include <random>                      // std::mt19937, std::random_device, std::..._distribution
#include <regex>                       // std::regex, std::regex_match
#include <ranges>                      // std::views
#include <span>                        // std::span
#include <sstream>                     // std::ostringstream
#include <stdexcept>                   // std::runtime_error
#include <string>                      // std::string
#include <string_view>                 // std::string_view
#include <unordered_map>               // std::unordered_map
#include <util/file.hpp>               // desync::util::read_file
#include <util/string.hpp>             // desync::util::concat
#include <utility>                     // std::move
#include <vector>    
#include <set>

namespace desync {

class desynchronizer final {
public:
	struct error final : std::runtime_error {
		[[nodiscard]] explicit error(const auto&... args)
			: std::runtime_error(util::concat(args...)) {}
	};

	auto configure(const configuration& config) -> void {
		if (!config.log_file.empty()) {
			m_logger.open(config.log_file);
		}
		m_verbose = config.verbose;
		m_print_config = config.print_config;
		m_print_assembly = config.print_assembly;
		m_print_cfg = config.print_cfg;
		m_print_result = config.print_result;
		m_print_stats = config.print_stats;
		m_instruction_pattern.assign(config.instruction_pattern);
		m_debug_cfg = config.debug_cfg;
		m_use_spilling = config.use_spilling;
		m_always_taken_fraction = config.always_taken_fraction;
		const auto seed = configure_seed(config);
		configure_junk_length_distribution(config);
		configure_interval_distribution(config);
		configure_predicates(config);
		if (m_print_config || m_verbose) {
			print_configuration(config, seed);
		}
	}

	[[nodiscard]] auto apply_predicates(std::string_view filename, std::string_view assembly, std::string_view filehash) -> std::string {
		auto result = std::string{};
		if (m_predicates_always.empty() && m_predicates_never.empty()) {
			m_logger.writeln("Warning: No predicates to apply.");
			result = assembly;
		} else {
			if (m_print_assembly || m_verbose) {
				print_assembly(filename, assembly);
			}
			const auto cfg = control_flow_graph::liveness_analyzed(assembly, m_assembler, m_disassembler);
			if (m_print_cfg || m_verbose) {
				print_control_flow_graph(filename, cfg);
			}
			const auto& instructions = cfg.instructions();
			if (m_debug_cfg){
				result = apply_debug_predicate(assembly, instructions);
			}
			else{
				result = apply_predicates_inner(assembly, instructions, filehash);
			}
			if (m_print_result || m_verbose) {
				print_result(filename, result);
			}
			if (m_print_stats || m_verbose) {
				print_stats(filename, instructions.size(), m_predicate_count);
			}
		}
		return result;
	}

private:
	static constexpr auto desync_label_replacement_index = std::numeric_limits<std::size_t>::max();
	static constexpr auto desync_restore_point_index = desync_label_replacement_index - 1;

	[[nodiscard]] static auto get_instruction_start(std::string_view assembly, const control_flow_graph::instruction& instruction) -> std::size_t {
		if (instruction.prefix.empty()){
			return instruction.string.data() - assembly.data();
		}
		else{
			return instruction.prefix.data() - assembly.data(); 
		}
	}

	[[nodiscard]] auto apply_predicates_inner(std::string_view assembly, const std::span<const control_flow_graph::instruction>& instructions, 
			std::string_view filehash) -> std::string {
		auto stream = std::ostringstream{};
		auto assembly_rest = std::size_t{0};
		auto next = std::size_t{0};
		m_predicate_count = std::size_t{0};
		for (auto i = std::size_t{0}; i < instructions.size(); i = next) {
			double r = static_cast<double>(m_random_number_generator() -  m_random_number_generator.min()) / static_cast<double>(m_random_number_generator.max());
			bool is_taken_branch = (r < m_always_taken_fraction && m_predicates_always.size() > 0) || m_predicates_never.size() == 0;
			const auto& predicate = generate_predicate(is_taken_branch);

			while (i < instructions.size()) {
				if (std::regex_match(std::string{instructions[i].string}, m_instruction_pattern)) {
					if (const auto arguments = predicate.find_arguments(~instructions[i].live_registers, ~instructions[i].live_flags, m_random_number_generator)) {
						auto missing_arg_count = predicate.parameters().size() - arguments->size();
						auto used_live_regs = instructions[i].live_registers & predicate.used_registers();
						if((missing_arg_count == 0 && used_live_regs.none()) || m_use_spilling) {
							auto to_spill = std::optional<std::vector<std::string>>{};
							auto argument_names = std::vector<std::string>{};
							for(auto idx : *arguments) {
								argument_names.emplace_back(m_disassembler.register_name(idx));
							}
							// if we use register spilling, allocate additional registers as spilled ones
							if(missing_arg_count || used_live_regs.any()) {
								auto already_allocated = std::bitset<disassembler::register_count>{};
								for(auto idx : *arguments) {
									already_allocated.set(idx);
								}
								auto& parent_registers = to_spill.emplace();
								auto allocated_regs = predicate.pick_registers(
									predicate.parameters().last(missing_arg_count), ~already_allocated, m_random_number_generator);
								if(allocated_regs.size() < missing_arg_count) {
									// failed to find suitable registers to spill
									++i;
									continue;
								}
								for(auto idx : allocated_regs) {
									argument_names.emplace_back(m_disassembler.register_name(idx));
									parent_registers.emplace_back(m_disassembler.register_name(disassembler::parent_register(idx)));
								}
								// also spill any registers implicitly used in predicate
								std::set<unsigned> live_parents{};
								for(size_t i = 0; i < used_live_regs.size(); ++i) {
									if(used_live_regs[i]) {
										//std::cout << "IMPLICIT: " << m_disassembler.register_name(disassembler::parent_register(i)) << std::endl;
										live_parents.insert(disassembler::parent_register(i));
									}
								}
								for(auto i : live_parents) {
									parent_registers.emplace_back(m_disassembler.register_name(i));
								}
							}
							const auto assembly_index = get_instruction_start(assembly, instructions[i]);
							// original assembly is used since some non-instruction assembly is skipped during parsing
							stream << assembly.substr(assembly_rest, assembly_index - assembly_rest) << '\n';
							assembly_rest = assembly_index;
							const auto junk_length = is_taken_branch ? generate_junk_length() : 0;
							const auto junk_label = util::concat("desyncpoint", filehash, '_', m_predicate_count, '_', junk_length);
							const auto jump_label = util::concat(".Ldesyncjump", filehash, m_predicate_count);
							++m_predicate_count;
							// spill registers to stack if needed
							if(to_spill) {
								for(const auto& r : *to_spill) {
									stream << "push %" << r << std::endl;
								}
							}
							predicate.apply(stream, jump_label, std::span{argument_names}, to_spill);
							stream << '\n' << junk_label << ":\n";
							for (auto n = std::size_t{0}; n < junk_length; ++n) {
								stream << "nop\n";
							}
							stream << jump_label << ":\n";
							break;
						}
					}
				}
				++i;
			}
			if (i >= instructions.size()) {
				break;
			}
			next = i + generate_interval();
			next = std::max(i, next);
		}
		stream << assembly.substr(assembly_rest);
		return stream.str();
	}

	[[nodiscard]] auto apply_debug_predicate(std::string_view assembly, const std::span<const control_flow_graph::instruction>& instructions) -> std::string {
		auto stream = std::ostringstream{};
		m_predicate_count = std::size_t{0};
		auto assembly_rest = std::size_t{0};
		auto regs_8bit = disassembler::general_registers_8bit();
		auto regs_16bit = disassembler::general_registers_16bit();
		auto regs_32bit = disassembler::general_registers_32bit();
		auto regs_64bit = disassembler::general_registers_64bit();
		for (auto i = std::size_t{0}; i < instructions.size(); ++i) {
			const auto assembly_index = get_instruction_start(assembly, instructions[i]);
			stream << assembly.substr(assembly_rest, assembly_index - assembly_rest);
			assembly_rest = assembly_index;
			bool inserted = false;
			for (auto reg = std::size_t{0}; reg < disassembler::register_count; reg++){
				if (instructions[i].live_registers.test(reg)) 
					continue; // register is live, don't use
				auto reg_name = m_disassembler.register_name(reg);
				if (regs_8bit.test(reg)){
					stream << "movb\t$-1, %" << reg_name << "\n\t";
					inserted = true;
				}
				else if (regs_16bit.test(reg)){
					stream << "movw\t$-1, %" << reg_name << "\n\t";
					inserted = true;
				}
				else if (regs_32bit.test(reg)){
					stream << "movl\t$-1, %" << reg_name << "\n\t";
					inserted = true;
				}
				else if (regs_64bit.test(reg)){
					stream << "movq\t$-1, %" << reg_name << "\n\t";
					inserted = true;
				}
				else{
					continue; //not one of the general registers
				}
			}
			if (inserted)
				++m_predicate_count;
		}
		stream << assembly.substr(assembly_rest);
		return stream.str();
	}

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
					return disassembler::general_registers_8bit();
				case parameter_type::r16:
					return disassembler::general_registers_16bit();
				case parameter_type::r32:
					return disassembler::general_registers_32bit();
				case parameter_type::r64:
					return disassembler::general_registers_64bit();
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
				if(i == parsed_predicate.restore_point_ofs) {
					m_replacement_indices.push_back(desync_restore_point_index);
					m_pieces.push_back(body.substr(piece_begin, i - piece_begin));
					piece_begin = i;
				} else if (body.compare(i, predicate_parser::desync_label_name.size(), predicate_parser::desync_label_name) == 0) {
					m_replacement_indices.push_back(desync_label_replacement_index);
					m_pieces.push_back(body.substr(piece_begin, i - piece_begin));
					i += predicate_parser::desync_label_name.size();
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

		[[nodiscard]] static auto index_list(){
			static const auto result = []{
				auto order = std::array<std::size_t, disassembler::register_count>{};
				for (auto i = std::size_t{0}; i < disassembler::register_count; ++i) {
					order[i] = i;
				}
				return order;
			}();
			return result;
		}

		[[nodiscard]] auto find_arguments(std::bitset<disassembler::register_count> free_registers, std::bitset<disassembler::flag_count> free_flags, std::mt19937& g) const -> std::optional<std::vector<std::size_t>> {
			auto result = std::optional<std::vector<std::size_t>>{};

			if ((free_flags & m_required_flags) != m_required_flags){
				return result; // flags needed by predicate are not free
			}
			// if ((free_registers & m_used_registers) != m_used_registers){
			// 	return result; // registers needed by predicate are not free
			// }
			// if (free_registers.count() < m_parameters.size()){
			// 	return result; // not enough free registers
			// }
			result.emplace(pick_registers(std::span{m_parameters}, free_registers, g));

			return result;
		}

		/**
		 * @brief Randomly choose one register per argument. Stops at first non-assignable argument and returns partial result.
		 */
		[[nodiscard]] auto pick_registers(std::span<const parameter_type> params, std::bitset<disassembler::register_count> free_registers, std::mt19937& g) const -> std::vector<std::size_t> {
			std::vector<std::size_t> result{};
			for (const auto& parameter : params) {
				auto found = false;
				// randomize order of registers
				auto order = predicate::index_list();
				shuffle (order.begin(), order.end(), g);
				// search list of registers
				for (auto it = order.begin(); it != order.end(); it++) {
					if (m_used_registers.test(*it)){
						continue; // register is reserved for predicate, don't use
					}
					if (free_registers.test(*it) && applicable_registers(parameter).test(*it)) {
						auto related_regs = disassembler::related_registers(*it);
						if ((m_used_registers & related_regs).count() > 0){
							continue; // register would affect a register needed by predicate, don't use
						}
						// register is fine to use, add to result
						result.push_back(*it);
						free_registers &= ~related_regs;
						found = true;
						break;
					}
				}
				if (!found) {
					// return partial result
					break;
				}
			}
			return result;
		}

		auto apply(std::ostream& out, 
		           std::string_view label, 
				   std::span<const std::string> arguments, 
				   const std::optional<std::vector<std::string>>& to_restore = std::nullopt) const -> void {
			assert(arguments.size() == m_parameters.size());
			assert(m_pieces.size() == m_replacement_indices.size() + 1);

			for (auto i = std::size_t{0}; i < m_replacement_indices.size(); ++i) {
				const auto& piece = m_pieces[i];
				const auto& replacement_index = m_replacement_indices[i];
				out << piece;
				if (replacement_index == desync_label_replacement_index) {
					out << label;
				} else if (replacement_index == desync_restore_point_index) {
					if (to_restore) {
						for(const auto& r : *to_restore | std::views::reverse) {
							out << "pop %" << r << std::endl;
						}
					}
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

		[[nodiscard]] auto used_registers() const noexcept -> std::bitset<disassembler::register_count> {
			return m_used_registers;
		}

	private:
		/**
		* @brief Gives a list of register names of appropriate size for each parameter.
		*/
		[[nodiscard]] auto get_general_registers(const disassembler& disassembler) -> std::vector<std::string> {
			auto arguments = std::vector<std::string>{};
			auto i = std::size_t{0};
			for (const auto& parameter : m_parameters) {
				std::string arg;
				switch (parameter) {
					case parameter_type::r8:
						arg = disassembler.register_name(disassembler::register_index(X86_REG_R8B + i));
						break;
					case parameter_type::r16:
						arg = disassembler.register_name(disassembler::register_index(X86_REG_R8W + i));
						break;
					case parameter_type::r32:
						arg = disassembler.register_name(disassembler::register_index(X86_REG_R8D + i));
						break;
					case parameter_type::r64:
						arg = disassembler.register_name(disassembler::register_index(X86_REG_R8 + i));
						break;
				}
				arguments.emplace_back(arg);
				++i;
			}
			return arguments;
		}

		/**
		 * @brief Run the predicate through keystone/capstone to ses what registers and flags are needed.
		 */
		auto check_assembly(std::string_view filename, const assembler& assembler, const disassembler& disassembler) -> void {
			auto ignore_registers = disassembler.all_registers_r64();// ignore registers R8-R15 since they are used in the test
			ignore_registers.flip(disassembler.register_index(X86_REG_EFLAGS)); // and eflags since it is covered by m_required_flags
			const auto arguments = get_general_registers(disassembler);
			auto stream = std::ostringstream{};
			apply(stream, "dummy_label", std::span{arguments});
			const auto assembly = stream.str();
			try {
				const auto assemble_result = assembler.assemble(assembly);
				const auto disassemble_result = disassembler.disassemble(assemble_result.encoding);
				for (const auto& instruction : std::span{disassemble_result.instructions.data(), disassemble_result.instructions.size()}) {
					const auto access = disassembler.access(instruction);
					m_required_flags |= access.flags_written;
					m_used_registers |= (access.registers_written & ~ignore_registers); 
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
		std::bitset<disassembler::register_count> m_used_registers{};
		std::bitset<disassembler::flag_count> m_required_flags{};
	};

	auto print_assembly(std::string_view filename, std::string_view assembly) const -> void {
		// clang-format off
		m_logger.writeln(
			"===================================================================\n"
			"ASSEMBLY for ", filename, "\n"
			"===================================================================\n",
			assembly);
		// clang-format on
	}

	auto print_control_flow_graph(std::string_view filename, const control_flow_graph& cfg) const -> void {
		// clang-format off
		m_logger.writeln(
			"===================================================================\n"
			"CONTROL FLOW GRAPH for ", filename, "\n"
			"===================================================================\n",
			cfg);
		// clang-format on
	}

	auto print_result(std::string_view filename, std::string_view assembly) const -> void {
		// clang-format off
		m_logger.writeln(
			"===================================================================\n"
			"RESULT for ", filename, "\n"
			"===================================================================\n",
			assembly);
		// clang-format on
	}

	auto print_stats(std::string_view filename, std::size_t instruction_count, std::size_t predicate_count) const -> void {
		// clang-format off
		m_logger.writeln(
			"===================================================================\n"
			"STATS for ", filename, "\n"
			"===================================================================\n"
			"Instructions: ", instruction_count, "\n"
			"Predicates inserted: ", predicate_count);
		// clang-format on
	}

	auto print_configuration(const configuration& config, std::mt19937::result_type seed) const -> void {
		// clang-format off
		m_logger.writeln(
			"===================================================================\n"
			"CONFIGURATION\n"
			"===================================================================\n"
			"seed ", seed, "\n"
			"instruction_pattern ", config.instruction_pattern,
			"use_spilling ", config.use_spilling ? "true\n" : "false\n",
			"always_taken_fraction ", config.always_taken_fraction, "\n");
		switch (m_junk_length_distribution) {
			case configuration::junk_length_distribution_type::constant:
				m_logger.writeln(
					"junk_length_distribution constant\n"
					"junk_length ", m_junk_length_constant);
				break;
			case configuration::junk_length_distribution_type::uniform:
				m_logger.writeln(
					"junk_length_distribution uniform\n"
					"junk_length_min ", m_junk_length_uniform.a(), "\n"
					"junk_length_max ", m_junk_length_uniform.b());
				break;
			case configuration::junk_length_distribution_type::normal:
				m_logger.writeln(
					"junk_length_distribution normal\n"
					"junk_length_mean ", m_junk_length_normal.mean(), "\n"
					"junk_length_stddev ", m_junk_length_normal.stddev());
				break;
		}
		switch (m_interval_distribution) {
			case configuration::interval_distribution_type::constant:
				m_logger.writeln(
					"interval_distribution constant\n"
					"interval ", m_interval_constant);
				break;
			case configuration::interval_distribution_type::uniform:
				m_logger.writeln(
					"interval_distribution uniform\n"
					"interval_min ", m_interval_uniform.a(), "\n"
					"interval_max ", m_interval_uniform.b());
				break;
			case configuration::interval_distribution_type::normal:
				m_logger.writeln(
					"interval_distribution normal\n"
					"interval_mean ", m_interval_normal.mean(), "\n"
					"interval_stddev ", m_interval_normal.stddev());
				break;
		}
		for (const auto& predicate_file : config.predicate_files) {
			m_logger.writeln("predicate_file ", predicate_file);
		}
		m_logger.writeln("predicate_pattern ", config.predicate_pattern);
		switch (m_predicate_distribution) {
			case configuration::predicate_distribution_type::uniform:
				m_logger.writeln("predicate_distribution uniform");
				break;
			case configuration::predicate_distribution_type::discrete:
				m_logger.writeln("predicate_distribution discrete");
				break;
		}
		for (const auto& [name, weight] : config.predicate_weights) {
			m_logger.writeln("predicate_weight ", name, " ", weight);
		}
		m_logger.writeln(
			"===================================================================\n"
			"PREDICATES\n"
			"===================================================================");
		m_logger.writeln("=== ALWAYS TAKEN ===\n");
		for (const auto& predicate : m_predicates_always) {
			m_logger.writeln("predicate ", predicate.name());
		}
		m_logger.writeln("=== NEVER TAKEN ===\n");
		for (const auto& predicate : m_predicates_never) {
			m_logger.writeln("predicate ", predicate.name());
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
		const auto pattern = std::regex{config.predicate_pattern};
		auto weights_always = std::vector<double>{};
		auto weights_never = std::vector<double>{};
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

					bool is_type_always{};
					auto pred = predicate(std::move(name), parsed_predicate, predicate_file, m_assembler, m_disassembler);
					if (parsed_predicate.type == "always") {
						m_predicates_always.emplace_back(std::move(pred));
						is_type_always = true;
					} else if (parsed_predicate.type == "never") {
						m_predicates_never.emplace_back(std::move(pred));
						is_type_always = false;
					} else {
						throw error{predicate_file, ": Predicate \"",  parsed_predicate.name, "\": Invalid predicate type \"", parsed_predicate.type, "\""};
					}

					auto& weight = is_type_always ? weights_always.emplace_back(1.0) : weights_never.emplace_back(1.0);
					if (const auto weight_it = config.predicate_weights.find(std::string{parsed_predicate.name}); weight_it != config.predicate_weights.end()) {
						weight = weight_it->second;
					}
				}
			} else {
				throw error{"Failed to open predicate file \"", predicate_file, "\" for reading."};
			}
		}

		m_predicate_distribution = config.predicate_distribution;
		m_predicate_always_uniform = decltype(m_predicate_always_uniform){
			0,
			(m_predicates_always.empty()) ? 0 : m_predicates_always.size() - 1,
		};
		m_predicate_never_uniform = decltype(m_predicate_never_uniform){
			0,
			(m_predicates_never.empty()) ? 0 : m_predicates_never.size() - 1,
		};
		m_predicate_always_discrete = decltype(m_predicate_always_discrete){
			weights_always.begin(),
			weights_always.end(),
		};
		m_predicate_never_discrete = decltype(m_predicate_never_discrete){
			weights_never.begin(),
			weights_never.end(),
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

	[[nodiscard]] auto generate_predicate(bool is_taken_branch) -> const predicate& {
		switch (m_predicate_distribution) {
			case configuration::predicate_distribution_type::uniform:
				if (is_taken_branch) {
					return m_predicates_always[m_predicate_always_uniform(m_random_number_generator)];
				} else {
					return m_predicates_never[m_predicate_never_uniform(m_random_number_generator)];
				}
			case configuration::predicate_distribution_type::discrete:
				if (is_taken_branch) {
					return m_predicates_always[m_predicate_always_discrete(m_random_number_generator)];
				} else {
					return m_predicates_never[m_predicate_never_discrete(m_random_number_generator)];
				}
			default:
				if (is_taken_branch) {
					return m_predicates_always[0];
				} else {
					return m_predicates_never[0];
				}
		}
	}

	desync::logger m_logger{};
	desync::assembler m_assembler{};
	desync::disassembler m_disassembler{};
	std::mt19937 m_random_number_generator{};
	std::regex m_instruction_pattern{};
	configuration::junk_length_distribution_type m_junk_length_distribution{};
	configuration::interval_distribution_type m_interval_distribution{};
	configuration::predicate_distribution_type m_predicate_distribution{};
	std::size_t m_junk_length_constant{};
	std::size_t m_interval_constant{};
	double m_always_taken_fraction{};
	std::uniform_int_distribution<std::size_t> m_junk_length_uniform{};
	std::uniform_int_distribution<std::size_t> m_interval_uniform{};
	std::uniform_int_distribution<std::size_t> m_predicate_always_uniform{};
	std::uniform_int_distribution<std::size_t> m_predicate_never_uniform{};
	std::normal_distribution<double> m_junk_length_normal{};
	std::normal_distribution<double> m_interval_normal{};
	std::discrete_distribution<std::size_t> m_predicate_always_discrete{};
	std::discrete_distribution<std::size_t> m_predicate_never_discrete{};
	std::vector<predicate> m_predicates_always{};
	std::vector<predicate> m_predicates_never{};
	bool m_verbose = false;
	bool m_print_config = false;
	bool m_print_assembly = false;
	bool m_print_cfg = false;
	bool m_print_result = false;
	bool m_print_stats = false;
	bool m_debug_cfg = false;
	bool m_use_spilling = false;
	std::size_t m_predicate_count;

};

} // namespace desync

#endif
