#ifndef DESYNC_CONTROL_FLOW_GRAPH_H
#define DESYNC_CONTROL_FLOW_GRAPH_H

#include <bitset>                   // std::bitset
#include <cassert>                  // assert
#include <memory>                   // std::unique_ptr, std::make_unique
#include <ostream>                  // std::ostream
#include <pred/assembler.hpp>       // desync::assembler
#include <pred/assembly_parser.hpp> // desync::assembly_parser
#include <pred/disassembler.hpp>    // desync::disassembler
#include <queue>                    // std::queue
#include <span>                     // std::span
#include <stdexcept>                // std::runtime_error
#include <string>                   // std::string
#include <string_view>              // std::string_view
#include <unordered_map>            // std::unordered_map
#include <util/string.hpp>          // desync::util::concat, desync::util::left_align
#include <utility>                  // std::move
#include <vector>                   // std::vector

namespace desync {

class control_flow_graph final {
public:
	struct error final : std::runtime_error {
		[[nodiscard]] explicit error(const auto&... args)
			: std::runtime_error(util::concat(args...)) {}
	};

	struct instruction final {
		std::string_view string{};                                  // Assembly substring that the instruction originated from.
		std::string_view prefix = std::string_view{};				// Assembly substring for any prefix instuctions immediately before it
		disassembler::disassemble_result disassembled{};            // Info about the machine code of the instruction.
		std::bitset<disassembler::register_count> live_registers{}; // Set of registers which are live at this instruction.
		std::bitset<disassembler::flag_count> live_flags{};         // Set of flags which are live at this instruction.
	};

	struct basic_block final {
		std::string_view label{};                                   // Label of this block, or empty if the block was created from a branch.
		std::size_t begin{};                                        // First instruction index in the block.
		std::size_t end{};                                          // End of the instructions in this block.
		std::vector<basic_block*> predecessors{};                   // Blocks that are known to potentially jump to the beginning of this block.
		std::vector<basic_block*> successors{};                     // Blocks that are known to be potentially reachable from this block.
		std::unique_ptr<basic_block> next{};                        // Next block in the order of declaration in the file. Not necessarily a successor of this block.
		std::bitset<disassembler::register_count> live_registers{}; // Set of registers which are live at the beginning of this block.
		std::bitset<disassembler::flag_count> live_flags{};         // Set of flags which are live at the beginning of this block.
	};

	[[nodiscard]] static auto liveness_analyzed(std::string_view assembly, const assembler& assembler, const disassembler& disassembler) -> control_flow_graph {
		auto cfg = control_flow_graph{assembly, assembler, disassembler};
		cfg.analyze_liveness();
		return cfg;
	}

	control_flow_graph(std::string_view assembly, const assembler& assembler, const disassembler& disassembler)
		: m_assembler(&assembler)
		, m_disassembler(&disassembler) {
		split_blocks(assembly);
	}

	auto analyze_liveness() -> void {
		auto work = std::queue<basic_block*>{};
		for (auto* block = m_head.get(); block; block = block->next.get()) {
			analyze_liveness(*block, work);
		}
		while (!work.empty()) {
			auto* const block = work.front();
			work.pop();
			assert(block);
			analyze_liveness(*block, work);
		}
	}

	[[nodiscard]] auto instructions() const noexcept -> std::span<const instruction> {
		return std::span{m_instructions};
	}

	[[nodiscard]] auto symbols() const noexcept -> std::span<basic_block* const> {
		return std::span{m_symbols};
	}

	[[nodiscard]] auto symbol(std::string_view label) const -> const basic_block* {
		if (const auto it = m_symbol_table.find(label); it != m_symbol_table.end()) {
			return it->second;
		}
		return nullptr;
	}

	[[nodiscard]] auto head() const noexcept -> const basic_block& {
		assert(m_head);
		return *m_head;
	}

private:

	/** 
	 * @brief Split the assebly into basic blocks
	 * */
	auto split_blocks(std::string_view assembly) -> void {
		first_pass(assembly);
		second_pass();
	}

	/** 
	 * @brief First pass: Consider only whole instructions and labels.
	 * */
	auto first_pass(std::string_view assembly) -> void {
		const auto statements = assembly_parser::parse_statements(assembly);
		// Allocate first basic block.
		m_head = std::make_unique<basic_block>();
		auto* block = m_head.get();
		for (auto it = statements.begin(); it != statements.end(); ++it) {
			auto statement = *it;
			if (statement.type == assembly_parser::statement_type::instruction) {
				// Add an instruction.
				auto& instruction = m_instructions.emplace_back();
				instruction.string = statement.string;
			} else if (statement.type == assembly_parser::statement_type::label) {
				// Start a new basic block.
				block->end = m_instructions.size();
				block->next = std::make_unique<basic_block>();
				block->next->label = statement.string;
				block->next->begin = block->end;
				block->next->predecessors.push_back(block);
				block->successors.push_back(block->next.get());
				block = block->next.get();

				// Define symbol.
				m_symbol_table.emplace(block->label, block);
				m_symbols.push_back(block);
			} else if (statement.type == assembly_parser::statement_type::prefix) {
				assembly_parser::statement next_statment;
				do{
					if (++it == statements.end())
						throw error{"Assembler error: prefix instruction at end of file"};
					next_statment = *it;
					if (next_statment.type == assembly_parser::statement_type::label ||
						next_statment.type == assembly_parser::statement_type::prefix)
						throw error{"Assembler error: prefix was not followed by instruction"};
				} while (next_statment.type != assembly_parser::statement_type::instruction);
				// Add instruction with prefix
				auto& instruction = m_instructions.emplace_back();
				instruction.string = next_statment.string;
				instruction.prefix = statement.string;
			}
		}
		block->end = m_instructions.size();
	}

	/** 
	 * @brief Second pass: Consider branch instructions now that we know all symbols. 
	 * */
	auto second_pass() -> void {
		for (auto* block = m_head.get(); block; block = block->next.get()) {
			// Iterate all instructions in each block.
			for (auto instruction_index = block->begin; instruction_index != block->end; ++instruction_index) {
				auto& instruction = m_instructions[instruction_index];

				// Assemble and disassemble the instruction to get info about the instruction type.
				// To make sure large constants don't cause problems when assembling, set all constants to 0.
				auto modified_instruction_string = assembly_parser::zero_out_constant_operands(instruction.string);
				auto modified_instruction_string_with_prefix = std::string{instruction.prefix} + ' ' + std::string{modified_instruction_string};
				try {
					assert(m_assembler);
					const auto assemble_result = m_assembler->assemble(modified_instruction_string_with_prefix);
					if (assemble_result.statement_count == 0) {
						throw error{"Assembler error @", instruction_index, ": No statements assembled: ", modified_instruction_string_with_prefix, " (original: ", instruction.string, ")"};
					}
					assert(m_disassembler);
					instruction.disassembled = m_disassembler->disassemble(assemble_result.encoding);
					if (instruction.disassembled.instructions.size() == 0) {
						throw error{
							"Disassembler error @", instruction_index, ": No instructions disassembled: ", modified_instruction_string_with_prefix, " (original: ", instruction.string, ")"};
					}
				} catch (const assembler::error& e) {
					throw error{"Assembler error @", instruction_index, ": ", e.what(), ": ", modified_instruction_string_with_prefix, " (original: ", instruction.string, ")"};
				} catch (const disassembler::error& e) {
					throw error{"Disassembler error @", instruction_index, ": ", e.what(), ": ", modified_instruction_string_with_prefix, " (original: ", instruction.string, ")"};
				}
				assert(instruction.disassembled.instructions.size() != 0);
				const auto& info = *instruction.disassembled.instructions.data();

				// Check if it is a branch instruction.
				if (disassembler::is_branch(info)) {
					const auto new_block_begin = instruction_index + 1;
					if (block->end == new_block_begin) {
						if (disassembler::is_unconditional_jump(info)) {
							// Remove edge to next block.
							if (block->next) {
								for (auto it = block->next->predecessors.begin(); it != block->next->predecessors.end();) {
									if (*it == block) {
										it = block->next->predecessors.erase(it);
									} else {
										++it;
									}
								}
							}
							block->successors.clear();
						}
					} else {
						// Start a new basic block.
						auto new_block = std::make_unique<basic_block>();
						new_block->begin = new_block_begin;
						new_block->end = block->end;
						new_block->next = std::move(block->next);
						new_block->successors = std::move(block->successors);
						// Update the end of the old block.
						block->end = new_block_begin;
						// Update successors' predecessor pointers.
						for (auto* const successor : new_block->successors) {
							if (successor) {
								for (auto& predecessor : successor->predecessors) {
									if (predecessor == block) {
										predecessor = new_block.get();
									}
								}
							}
						}
						// Update the old block's successor pointers.
						block->successors.clear();
						if (!disassembler::is_unconditional_jump(info)) {
							new_block->predecessors.push_back(block);
							block->successors.push_back(new_block.get());
						}
						// Insert the new basic block.
						block->next = std::move(new_block);
					}
					// Add the branch target as a successor.
					if (disassembler::has_operand(info)){
						// calling convention check relies on the target successor being added last so do not change order.
						if (disassembler::has_immediate_operand(info)) {
							// Search for matching symbols.
							const auto arguments = assembly_parser::parse_arguments(instruction.string);
							if (arguments.size() == 2) {
								if (const auto it = m_symbol_table.find(arguments[1].string); it != m_symbol_table.end()) {
									auto* const symbol = it->second;
									symbol->predecessors.push_back(block);
									block->successors.push_back(symbol);
								} else {
									block->successors.push_back(nullptr); // Unknown branch target (e.g. library function).
								}
							} else {
								throw error{"Unknown branch instruction format"};
							}
						}
						else{
							// The instruction is using some other addressing mode. Assume the target is unknown.
							block->successors.push_back(nullptr);
						}
					}					
					break;
				}
			}
		}
	}

	auto analyze_liveness(basic_block& block, std::queue<basic_block*>& work) -> void {
		const auto old_live_registers = block.live_registers;
		const auto old_live_flags = block.live_flags;
		if (block.successors.empty()) {
			block.live_registers.set();
			block.live_flags.set();
		} else {
			block.live_registers.reset();
			block.live_flags.reset();
			for (auto* const successor : block.successors) {
				if (successor) {
					if (successor == &block){
						block.live_registers |= old_live_registers;
						block.live_flags |= old_live_flags;
					}
					else{
						block.live_registers |= successor->live_registers;
						block.live_flags |= successor->live_flags;
					}
				} else {
					// successor is an unknown target, assume everything is live
					block.live_registers.set();
					block.live_flags.set();
					break;
				}
			}
		}
		for (auto instruction_index = block.end; instruction_index-- != block.begin;) {
			assert(instruction_index < m_instructions.size());
			auto& instruction = m_instructions[instruction_index];
			assert(instruction.disassembled.instructions.size() != 0);
			const auto& info = *instruction.disassembled.instructions.data();
			assert(m_disassembler);
			const auto access = m_disassembler->access(info);
			block.live_registers &= ~access.registers_written; // registers that are overwritten are not live
			if (m_disassembler->is_call(info)) {
				block.live_registers &= ~call_convention(block); // add registers freed by calling convention as "not live"
				block.live_flags.reset(); // flags are not live across function calls
			} else if (m_disassembler->is_ret(info)) {
				block.live_flags.reset(); // flags are not live across function calls
			} 
			block.live_registers |= disassembler::related_registers(access.registers_read); // registers that are read are live
			block.live_flags &= ~access.flags_written; // flags that are overwritten are not live
			block.live_flags |= access.flags_read; // flags that are read are live
			instruction.live_registers = block.live_registers;
			instruction.live_flags = block.live_flags;
		}
		if (block.live_registers != old_live_registers || block.live_flags != old_live_flags) {
			// the liveness was updated so update predecessors
			for (auto* const predecessor : block.predecessors) {
				assert(predecessor);
				work.push(predecessor);
			}
		}
	}

	/**
	 * @brief Get the registers that are freed when call is performed
	 * */
	auto call_convention(const basic_block& block) -> std::bitset<disassembler::register_count> {
		const auto* const target_block = block.successors.back(); // relies on target being added last
		if (!target_block){
			return guess_call_convention();
		}
		return ~(target_block->live_registers); // use registers that are free in call
	}

	/**
	 * @brief The called function is not known so used registers has to be inferred
	 * */
	auto guess_call_convention() -> std::bitset<disassembler::register_count> {
		// use standard call registers
		return disassembler:: disassembler::scratch_registers();
	}

	friend auto operator<<(std::ostream& out, const control_flow_graph& cfg) -> std::ostream&;

	const assembler* m_assembler = nullptr;
	const disassembler* m_disassembler = nullptr;
	std::vector<instruction> m_instructions{};
	std::vector<basic_block*> m_symbols{};
	std::unordered_map<std::string_view, basic_block*> m_symbol_table{};
	std::unique_ptr<basic_block> m_head{};
};

inline auto operator<<(std::ostream& out, const control_flow_graph::basic_block& block) -> std::ostream& {
	if (block.label.empty()) {
		out << '@' << block.begin;
	} else {
		out << block.label;
	}
	return out;
}

inline auto operator<<(std::ostream& out, const control_flow_graph::instruction& instruction) -> std::ostream& {
	static constexpr auto instruction_width = std::size_t{32};
	static constexpr auto disassembled_width = std::size_t{36};
	out << util::left_align(instruction.string, instruction_width) << " #";
	auto disassembled_text = std::string{};
	const auto* const begin = instruction.disassembled.instructions.data();
	const auto* const end = begin + instruction.disassembled.instructions.size();
	for (const auto* info = begin; info != end; ++info) {
		disassembled_text.push_back(' ');
		disassembled_text.append(info->mnemonic);
		if (info->op_str[0] != '\0') {
			disassembled_text.push_back(' ');
			disassembled_text.append(info->op_str);
		}
		disassembled_text.push_back(';');
	}
	out << util::left_align(disassembled_text, disassembled_width);
	return out;
}

inline auto operator<<(std::ostream& out, const control_flow_graph& cfg) -> std::ostream& {
	for (const auto* block = &cfg.head(); block; block = block->next.get()) {
		out << *block
			<< " {\n"
			   "    predecessors {\n";
		for (const auto* const predecessor : block->predecessors) {
			out << "        " << *predecessor << '\n';
		}
		out << "    }\n"
			   "    successors {\n";
		for (const auto* const successor : block->successors) {
			if (successor) {
				out << "        " << *successor << '\n';
			} else {
				out << "        ???\n";
			}
		}
		out << "    }\n"
			   "    instructions {\n";
		for (auto instruction_index = block->begin; instruction_index != block->end; ++instruction_index) {
			assert(instruction_index < cfg.m_instructions.size());
			const auto& instruction = cfg.m_instructions[instruction_index];
			out << "        ";
			// Right-align instruction index with a maximum padding of 3 columns.
			const auto padding = (instruction_index < 1000) + (instruction_index < 100) + (instruction_index < 10);
			for (auto i = 0; i < padding; ++i) {
				out << ' ';
			}
			assert(cfg.m_disassembler);
			out << instruction_index << ": " << instruction << " (free registers: {" << cfg.m_disassembler->registers_string(~instruction.live_registers) << "}; free flags: {"
				<< cfg.m_disassembler->flags_string(~instruction.live_flags) << "})\n";
		}
		out << "    }\n"
			   "}\n";
	}
	return out;
}

} // namespace desync

#endif
