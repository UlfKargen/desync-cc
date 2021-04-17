#ifndef DESYNC_ASSEMBLY_PARSER_H
#define DESYNC_ASSEMBLY_PARSER_H

#include <cassert>     // assert
#include <cstddef>     // std::size_t, std::ptrdiff_t
#include <cstdint>     // std::uint8_t
#include <string_view> // std::string_view
#include <vector>      // std::vector

namespace desync {

class assembly_parser final {
public:
	enum class statement_type : std::uint8_t {
		instruction,
		label,
		directive,
	};

	struct statement final {
		std::string_view string{}; // Assembly substring containing the full statement.
		statement_type type{};     // Statement type.
	};

	[[nodiscard]] static auto parse(std::string_view code) -> std::vector<statement> {
		return assembly_parser{code}.read_statements();
	}

	[[nodiscard]] static constexpr auto is_whitespace(char ch) noexcept -> bool {
		return ch == ' ' || ch == '\t' || ch == '\n';
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
			} else if (peek() == '#') {
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
			if (peek() == '\n' || peek() == ';') {
				break;
			}
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
		} while (!at_end());
		const auto end = current_position();
		if (!at_end()) {
			advance();
		}
		return statement{m_code.substr(begin, end - begin), type};
	}

	[[nodiscard]] auto current_position() const -> std::size_t {
		return static_cast<std::size_t>(m_it - m_code.begin());
	}

	[[nodiscard]] auto at_end() const -> bool {
		return m_it == m_end;
	}

	[[nodiscard]] auto peek() const -> char {
		return *m_it;
	}

	[[nodiscard]] auto peek(std::size_t n) const -> std::string_view {
		return m_code.substr(current_position(), n);
	}

	auto advance() -> void {
		++m_it;
	}

	auto advance(std::ptrdiff_t n) -> void {
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
