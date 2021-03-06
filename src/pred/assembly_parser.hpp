#ifndef DESYNC_ASSEMBLY_PARSER_H
#define DESYNC_ASSEMBLY_PARSER_H

#include <cassert>     // assert
#include <cstddef>     // std::size_t, std::ptrdiff_t
#include <cstdint>     // std::uint8_t
#include <span>        // std::span
#include <string>      // std::string
#include <string_view> // std::string_view
#include <vector>      // std::vector
#include <stdexcept>   // std::runtime_error

namespace desync {

class assembly_parser final {
public:
	struct unsafe_branch_error final : std::runtime_error {
		[[nodiscard]] explicit unsafe_branch_error(const auto&... args)
			: std::runtime_error(util::concat(args...)) {}
	};

	enum class statement_type : std::uint8_t {
		instruction,
		label,
		directive,
		prefix,
	};

	struct statement final {
		std::string_view string{}; // Assembly substring containing the full statement.
		statement_type type{};     // Statement type.
	};

	struct argument final {
		std::string_view string{}; // Assembly substring containing the argument.
	};

	[[nodiscard]] static auto parse_statements(std::string_view code) -> std::vector<statement> {
		return assembly_parser{code}.read_statements();
	}

	[[nodiscard]] static auto parse_arguments(std::string_view string) -> std::vector<argument> {
		return assembly_parser{string}.read_arguments();
	}

	[[nodiscard]] static auto zero_out_constant_operands(std::string_view instruction_string) -> std::string {
		auto result = std::string{};
		const auto arguments = parse_arguments(instruction_string);
		if (!arguments.empty()) {
			result = arguments.front().string;
			if (arguments.size() >= 2) {
				result.push_back(' ');
				
				// Deal with branches with hardcoded offsets, which cannot be handled safely by desync-cc
				if(arguments.front().string[0] == 'j' && 
				   arguments.size() == 2 &&
					!arguments[1].string.empty() && arguments[1].string[0] >= '0' && arguments[1].string[0] <= '9') 
				{
					throw unsafe_branch_error{instruction_string};
				}
				
				result.append(zero_out_constant_operand(arguments[1].string));
				for (const auto& argument : std::span{arguments}.subspan(2)) {
					result.append(", ");
					result.append(zero_out_constant_operand(argument.string));
				}
			}
		}
		return result;
	}

	[[nodiscard]] static auto zero_out_constant_operand(std::string_view argument_string) -> std::string_view {
		if (!argument_string.empty() && argument_string.front() == '$') {
			return std::string_view{"$0"};
		}
		return argument_string;
	}

	[[nodiscard]] static constexpr auto is_whitespace(char ch) noexcept -> bool {
		return ch == ' ' || ch == '\t' || ch == '\n';
	}

	[[nodiscard]] static auto is_prefix(std::string_view argument_string) -> bool {
		if (argument_string.empty())
			return false;
		auto begin = argument_string.find_first_not_of(" \t");
		auto end = argument_string.find_last_not_of(" \t\n");
		auto no_whitespace = argument_string.substr(begin, end - begin + 1);
		const std::array<std::string_view, 13> prefix_inst = { "cs", "ds" , "ss", "es", "fs", "gs", "data16", "addr16", "lock", "wait", "rep", "repe", "repne"};
		for(const auto& s: prefix_inst){
			if (no_whitespace.compare(s) == 0){
				return true;
			}
		}
		return false;
	}

private:
	explicit assembly_parser(std::string_view code)
		: m_code(code)
		, m_it(code.begin())
		, m_end(code.end()) {}



	[[nodiscard]] auto read_statements() -> std::vector<statement> {
		auto result = std::vector<statement>{};
		while (!at_end()) {
			if (is_whitespace(peek())) {
				advance();
			} else if (peek() == ';') {
				advance();
			} else if (peek() == '#') {
				advance();
				skip_line();
			} else if (peek(2) == "/*") {
				skip_comment();
			} else {
				result.push_back(read_statement());
			}
		}
		return result;
	}

	[[nodiscard]] auto read_statement() -> statement {
		assert(!at_end());
		const auto begin = current_position();
		auto type = (peek() == '.') ? statement_type::directive : statement_type::instruction;
		do {
			if (peek() == ':') {
				const auto str = peek(2);
				if (str.size() == 2 && (str[1] == ';' || is_whitespace(str[1]))) {
					type = statement_type::label;
					break;
				}
				advance();
			} else if (peek() == '"') {
				skip_quote();
			} else {
				advance();
			}
		} while (!at_end() && peek() != '\n' && peek() != ';');
		const auto end = current_position();
		if (!at_end()) {
			advance();
		}
		auto result = m_code.substr(begin, end - begin);
		if (type != statement_type::label && is_prefix(result)){
			type = statement_type::prefix;
		}
		return statement{result, type};
	}

	[[nodiscard]] auto read_arguments() -> std::vector<argument> {
		auto result = std::vector<argument>{};
		while (!at_end() && is_whitespace(peek())) {
			advance();
		}
		if (!at_end()) {
			result.push_back(read_mnemonic());
			while (!at_end()) {
				if (is_whitespace(peek())) {
					advance();
				} else if (peek() == '#') {
					skip_line();
				} else if (peek(2) == "/*") {
					skip_comment();
				} else {
					result.push_back(read_operand());
				}
			}
		}
		return result;
	}

	[[nodiscard]] auto read_mnemonic() -> argument {
		assert(!at_end());
		const auto begin = current_position();
		do {
			advance();
		} while (!at_end() && !is_whitespace(peek()));
		const auto end = current_position();
		return argument{m_code.substr(begin, end - begin)};
	}

	[[nodiscard]] auto read_operand() -> argument {
		assert(!at_end());
		const auto begin = current_position();
		do {
			if (peek() == '"') {
				skip_quote();
				break;
			}
			advance();
		} while (!at_end() && peek() != ',');
		const auto end = current_position();
		if (!at_end() && peek() == ',') {
			advance();
		}
		return argument{m_code.substr(begin, end - begin)};
	}

	[[nodiscard]] auto current_position() const -> std::size_t {
		return static_cast<std::size_t>(m_it - m_code.begin());
	}

	[[nodiscard]] auto at_end() const -> bool {
		return m_it == m_end;
	}

	[[nodiscard]] auto peek() const -> char {
		assert(m_it - m_code.begin() < m_end - m_code.begin());
		return *m_it;
	}

	[[nodiscard]] auto peek(std::size_t n) const -> std::string_view {
		return m_code.substr(current_position(), n);
	}

	auto advance() -> void {
		assert(m_it - m_code.begin() < m_end - m_code.begin());
		++m_it;
	}

	auto advance(std::ptrdiff_t n) -> void {
		assert(m_it + n - m_code.begin() < m_end - m_code.begin());
		m_it += n;
	}

	auto skip_line() -> void {
		while (!at_end()) {
			if (peek() == '\n') {
				advance();
				break;
			}
			advance();
		}
	}

	auto skip_comment() -> void {
		assert(peek(2) == "/*");
		advance(2);
		while (!at_end()) {
			if (peek(2) == "*/") {
				advance(2);
				break;
			}
			advance();
		}
	}

	auto skip_quote() -> void {
		assert(peek() == '"');
		advance();
		while (!at_end()) {
			if (peek() == '"') {
				advance();
				break;
			}
			if (peek() == '\\') {
				advance();
				if (!at_end()) {
					advance();
				}
			} else {
				advance();
			}
		}
	}

	std::string_view m_code;
	std::string_view::iterator m_it;
	std::string_view::iterator m_end;
};

} // namespace desync

#endif
