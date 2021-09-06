#ifndef DESYNC_PREDICATE_PARSER_H
#define DESYNC_PREDICATE_PARSER_H

#include <cassert>         // assert
#include <cstddef>         // std::size_t, std::ptrdiff_t
#include <cstdint>         // std::uint8_t
#include <span>            // std::span
#include <stdexcept>       // std::runtime_error
#include <string>          // std::string
#include <string_view>     // std::string_view
#include <util/string.hpp> // desync::util::concat
#include <vector>          // std::vector

namespace desync {

class predicate_parser final {
public:
	static constexpr auto desync_label_name = std::string_view{"DESYNC"};

	struct error final : std::runtime_error {
		[[nodiscard]] explicit error(std::string_view filename, std::size_t line, std::size_t column, const auto&... args)
			: std::runtime_error(util::concat(filename, ':', line, ':', column, ": ", args...)) {}
	};

	struct parameter final {
		std::string_view name{};
		std::string_view type{};
	};

	struct predicate_body final {
		std::string_view code{};
		std::size_t restore_point_ofs{};
	};

	struct predicate final {
		std::string_view name{};
		std::string_view body{};
		// Point for inserting register restoration instructions, if register spilling is used
		std::size_t restore_point_ofs{};
		std::vector<parameter> parameters{};
	};

	[[nodiscard]] static auto parse_predicates(std::string_view filename, std::string_view code) -> std::vector<predicate> {
		return predicate_parser{filename, code}.read_predicates();
	}

	[[nodiscard]] static constexpr auto is_identifier_character(char ch) noexcept -> bool {
		return ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9');
	}

private:
	predicate_parser(std::string_view filename, std::string_view code)
		: m_filename(filename)
		, m_code(code)
		, m_it(code.begin())
		, m_end(code.end())
		, m_line_begin(0) {}

	[[nodiscard]] auto read_predicates() -> std::vector<predicate> {
		auto result = std::vector<predicate>{};
		while (true) {
			skip_whitespace();
			if (at_end()) {
				break;
			}
			const auto statement = read_identifier();
			if (statement == "predicate") {
				result.push_back(read_predicate());
			} else {
				throw make_error("Invalid statement: \"", statement, "\"");
			}
		}
		return result;
	}

	[[nodiscard]] auto read_predicate() -> predicate {
		auto result = predicate{};
		result.name = read_identifier();
		result.parameters = read_parameters();
		auto body = read_predicate_body();
		result.body = body.code;
		result.restore_point_ofs = body.restore_point_ofs;
		return result;
	}

	[[nodiscard]] auto read_identifier() -> std::string_view {
		skip_whitespace();
		const auto begin = current_position();
		while (!at_end() && is_identifier_character(peek())) {
			advance();
		}
		const auto end = current_position();
		if (begin == end) {
			throw make_error("Expected an identifier.");
		}
		return m_code.substr(begin, end - begin);
	}

	[[nodiscard]] auto read_parameters() -> std::vector<parameter> {
		auto result = std::vector<parameter>{};
		skip_whitespace();
		if (at_end() || peek() != '(') {
			throw make_error("Expected a parameter list.");
		}
		advance();
		skip_whitespace();
		while (true) {
			if (at_end()) {
				throw make_error("Expected end of parameter list ')'");
			}
			if (peek() == ')') {
				advance();
				break;
			}
			result.push_back(read_parameter());
			skip_whitespace();
			if (at_end() || (peek() != ',' && peek() != ')')) {
				throw make_error("Expected parameter separator ',' or ')'");
			}
			if (peek() == ',') {
				advance();
				skip_whitespace();
			}
		}
		return result;
	}

	[[nodiscard]] auto read_parameter() -> parameter {
		const auto name = read_identifier();
		skip_whitespace();
		if (at_end() || peek() != ':') {
			throw make_error("Expected a parameter type specifier ':'");
		}
		advance();
		const auto type = read_identifier();
		return parameter{name, type};
	}

	[[nodiscard]] auto read_predicate_body() -> predicate_body {
		skip_whitespace();
		if (at_end() || peek() != '{') {
			throw make_error("Expected a predicate body.");
		}
		advance();
		const auto begin = current_position();
		std::size_t restore_point_ofs{std::string::npos};
		while (true) {
			if (at_end()) {
				throw make_error("Expected end of predicate body '}'");
			}
			if (peek() == '}') {
				break;
			}
			if (peek() == '\n') {
				if(check_if_jump()) {
					if(restore_point_ofs != std::string::npos) {
						throw make_error("Malfromed predicate body (multiple " + std::string{desync_label_name} + " labels)");
					}
					restore_point_ofs = m_line_begin - begin;
				}
				advance_line();
			} else {
				advance();
			}
		}
		const auto end = current_position();
		advance();
		if(restore_point_ofs == std::string::npos) {
			throw make_error("Malfromed predicate body (no " + std::string{desync_label_name} + " label present)");
		}
		return {m_code.substr(begin, end - begin), restore_point_ofs};
	}

	[[nodiscard]] auto check_if_jump() -> bool {
		return m_code.substr(m_line_begin, current_position() - m_line_begin).find(desync_label_name) != std::string::npos;
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

	auto advance_line() -> void {
		assert(peek() == '\n');
		advance();
		++m_line;
		m_line_begin = current_position();
	}

	auto skip_whitespace() -> void {
		while (!at_end()) {
			if (peek() == ' ' || peek() == '\t') {
				advance();
			} else if (peek() == '\n') {
				advance_line();
			} else if (peek(2) == "//") {
				advance(2);
				skip_line();
			} else if (peek(2) == "/*") {
				skip_comment();
			} else {
				break;
			}
		}
	}

	auto skip_line() -> void {
		while (!at_end()) {
			if (peek() == '\n') {
				advance_line();
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
			if (peek() == '\n') {
				advance_line();
			} else {
				advance();
			}
		}
	}

	[[nodiscard]] auto make_error(const auto&... args) const -> error {
		return error{m_filename, m_line, current_position() - m_line_begin, args...};
	}

	std::string_view m_filename;
	std::string_view m_code;
	std::string_view::iterator m_it;
	std::string_view::iterator m_end;
	std::size_t m_line = 1;
	std::size_t m_line_begin = 0;
};

} // namespace desync

#endif
