#ifndef DESYNC_ASSEMBLER_H
#define DESYNC_ASSEMBLER_H

#include <cstddef>             // std::size_t
#include <cstdint>             // std::uint64_t
#include <keystone/keystone.h> // ks_..., KS_...
#include <stdexcept>           // std::runtime_error
#include <string>              // std::string
#include <string_view>         // std::string_view, std::basic_string_view

namespace desync {

class assembler final {
private:
	static auto symbol_resolver(const char* /*symbol*/, std::uint64_t* value) -> bool {
		// TODO: Fix "Literal value out of range for directive (KS_ERR_ASM_DIRECTIVE_VALUE_RANGE)"
		// (probably caused by huge offsets in relative jumps due to all symbols being treated as 0 here).
		*value = 0;
		return true;
	}

public:
	struct error final : std::runtime_error {
		[[nodiscard]] explicit error(const char* message)
			: std::runtime_error(message) {}
	};

	class encoding_string final {
	public:
		using pointer = unsigned char*;
		using size_type = std::size_t;

		encoding_string() noexcept = default;

		encoding_string(pointer data, size_type size) noexcept
			: m_data(data)
			, m_size(size) {}

		~encoding_string() {
			ks_free(m_data);
		}

		encoding_string(encoding_string&& other) noexcept
			: m_data(other.m_data)
			, m_size(other.m_size) {
			other.m_data = nullptr;
			other.m_size = 0;
		}

		auto operator=(encoding_string&& other) noexcept -> encoding_string& {
			ks_free(m_data);
			m_data = other.m_data;
			m_size = other.m_size;
			other.m_data = nullptr;
			other.m_size = 0;
			return *this;
		}

		// Disallow copying.
		encoding_string(const encoding_string&) = delete;
		auto operator=(const encoding_string&) -> encoding_string& = delete;

		operator std::basic_string_view<unsigned char>() const noexcept {
			return {m_data, m_size};
		}

		[[nodiscard]] auto data() const noexcept -> pointer {
			return m_data;
		}

		[[nodiscard]] auto size() const noexcept -> size_type {
			return m_size;
		}

	private:
		pointer m_data = nullptr;
		size_type m_size = 0;
	};

	assembler() {
		if (const auto err = ks_open(KS_ARCH_X86, KS_MODE_64, &m_ks); err != KS_ERR_OK) {
			throw error{ks_strerror(err)};
		}
		if (const auto err = ks_option(m_ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_GAS); err != KS_ERR_OK) {
			throw error{ks_strerror(err)};
		}
		if (const auto err = ks_option(m_ks, KS_OPT_SYM_RESOLVER, reinterpret_cast<std::size_t>(ks_sym_resolver{&symbol_resolver})); err != KS_ERR_OK) {
			throw error{ks_strerror(err)};
		}
	}

	~assembler() {
		ks_close(m_ks);
	}

	// Disallow copying and moving.
	assembler(const assembler&) = delete;
	assembler(assembler&&) = delete;
	auto operator=(const assembler&) -> assembler& = delete;
	auto operator=(assembler &&) -> assembler& = delete;

	struct assemble_result final {
		encoding_string encoding{};
		std::size_t statement_count = 0;
	};

	[[nodiscard]] auto assemble(std::string_view string, std::uint64_t address = 0) -> assemble_result {
		unsigned char* encoding = nullptr;
		auto encoding_size = std::size_t{};
		auto stat_count = std::size_t{};
		if (ks_asm(m_ks, std::string{string}.c_str(), address, &encoding, &encoding_size, &stat_count) != 0) {
			throw error{ks_strerror(ks_errno(m_ks))};
		}
		return assemble_result{encoding_string{encoding, encoding_size}, stat_count};
	}

private:
	ks_engine* m_ks = nullptr;
};

} // namespace desync

#endif
