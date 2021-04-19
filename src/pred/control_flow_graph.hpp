#ifndef DESYNC_CONTROL_FLOW_GRAPH_H
#define DESYNC_CONTROL_FLOW_GRAPH_H

#include <memory>                   // std::unique_ptr, std::make_unique
#include <ostream>                  // std::ostream
#include <pred/assembler.hpp>       // desync::assembler
#include <pred/assembly_parser.hpp> // desync::assembly_parser
#include <pred/disassembler.hpp>    // desync::disassembler
#include <span>                     // std::span
#include <stdexcept>                // std::runtime_error
#include <string_view>              // std::string_view
#include <unordered_map>            // std::unordered_map
#include <util/string.hpp>          // desync::util::concat
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
		std::string_view string{};                       // Assembly substring that the instruction originated from.
		disassembler::disassemble_result disassembled{}; // Info about the machine code of the instruction.
	};

	struct basic_block final {
		std::string_view label{};                 // Label of this block, or empty if the block was created from a branch.
		std::size_t begin{};                      // First instruction index in the block.
		std::size_t end{};                        // End of the instructions in this block.
		std::vector<basic_block*> predecessors{}; // Blocks that are known to potentially jump to the beginning of this block.
		std::vector<basic_block*> successors{};   // Blocks that are known to be potentially reachable from this block.
		std::unique_ptr<basic_block> next{};      // Next block in the order of declaration in the file. Not necessarily a successor of this block.
	};

	control_flow_graph(assembler& assembler, disassembler& disassembler, std::string_view assembly) {
		// Parse assembly statements.
		const auto statements = assembly_parser::parse_statements(assembly);

		// First pass: Consider only whole instructions and labels.
		{
			auto* block = &m_head;
			for (const auto& statement : statements) {
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
				}
			}
			block->end = m_instructions.size();
		}

		// Second pass: Consider branch instructions now that we know all symbols.
		for (auto* block = &m_head; block; block = block->next.get()) {
			// Iterate all instructions in each block.
			for (auto instruction_index = block->begin; instruction_index != block->end; ++instruction_index) {
				auto& instruction = m_instructions[instruction_index];

				// Assemble and disassemble the instruction to get info about the instruction type.
				// To make sure large constants don't cause problems when assembling, set all constants to 0.
				auto modified_instruction_string = assembly_parser::zero_out_constant_operands(instruction.string);
				try {
					const auto assembler_result = assembler.assemble(modified_instruction_string);
					if (assembler_result.statement_count == 0) {
						throw error{"Assembler error @", instruction_index, ": No statements assembled: ", modified_instruction_string, " (original: ", instruction.string, ")"};
					}
					instruction.disassembled = disassembler.disassemble(assembler_result.encoding);
					if (instruction.disassembled.instructions.size() == 0) {
						throw error{
							"Disassembler error @", instruction_index, ": No instructions disassembled: ", modified_instruction_string, " (original: ", instruction.string, ")"};
					}
				} catch (const assembler::error& e) {
					throw error{"Assembler error @", instruction_index, ": ", e.what(), ": ", modified_instruction_string, " (original: ", instruction.string, ")"};
				} catch (const disassembler::error& e) {
					throw error{"Disassembler error @", instruction_index, ": ", e.what(), ": ", modified_instruction_string, " (original: ", instruction.string, ")"};
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
								block->next->predecessors.clear();
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
							for (auto& predecessor : successor->predecessors) {
								if (predecessor == block) {
									predecessor = new_block.get();
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
					if (disassembler::has_immediate_operand(info)) {
						// Search for matching symbols.
						for (auto* const symbol : m_symbols) {
							if (instruction.string.find(symbol->label) != std::string_view::npos) {
								symbol->predecessors.push_back(block);
								block->successors.push_back(symbol);
								break;
							}
						}
					}
					break;
				}
			}
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
		return m_head;
	}

private:
	std::vector<instruction> m_instructions{};
	std::vector<basic_block*> m_symbols{};
	std::unordered_map<std::string_view, basic_block*> m_symbol_table{};
	basic_block m_head{};
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
	// Left-align instruction string with a maximum padding of instruction_width columns.
	static constexpr auto instruction_width = std::size_t{32};
	auto column = std::size_t{0};
	for (const auto ch : instruction.string) {
		if (ch == '\t') {
			out << "    ";
			column += 4;
		} else {
			out << ch;
			++column;
		}
	}
	for (; column < instruction_width; ++column) {
		out << ' ';
	}
	// Append the disassembled instruction text as a comment.
	out << " #";
	const auto* const begin = instruction.disassembled.instructions.data();
	const auto* const end = begin + instruction.disassembled.instructions.size();
	for (const auto* info = begin; info != end; ++info) {
		out << ' ' << info->mnemonic << ' ' << info->op_str << ';';
	}
	return out;
}

inline auto operator<<(std::ostream& out, const control_flow_graph& cfg) -> std::ostream& {
	for (const auto* block = &cfg.head(); block; block = block->next.get()) {
		out << *block
			<< " {\n"
			   "    predecessors {\n";
		for (const auto& predecessor : block->predecessors) {
			out << "        " << *predecessor << '\n';
		}
		out << "    }\n"
			   "    successors {\n";
		for (const auto& successor : block->successors) {
			out << "        " << *successor << '\n';
		}
		out << "    }\n"
			   "    instructions {\n";
		for (auto instruction_index = block->begin; instruction_index != block->end; ++instruction_index) {
			out << "        ";
			// Right-align instruction index with a maximum padding of 3 columns.
			const auto padding = (instruction_index < 1000) + (instruction_index < 100) + (instruction_index < 10);
			for (auto i = 0; i < padding; ++i) {
				out << ' ';
			}
			out << instruction_index << ": " << cfg.instructions()[instruction_index];
			out << '\n';
		}
		out << "    }\n"
			   "}\n";
	}
	return out;
}

} // namespace desync

#endif
