#ifndef DESYNC_DISASSEMBLER_H
#define DESYNC_DISASSEMBLER_H

#include <capstone/capstone.h> // csh, cs_..., CS_..., X86_...
#include <cstdint>             // std::uint8_t, std::uint64_t
#include <span>                // std::span
#include <stdexcept>           // std::runtime_error
#include <string_view>         // std::basic_string_view

namespace desync {

class disassembler final {
public:
	struct error final : std::runtime_error {
		[[nodiscard]] explicit error(const char* message)
			: std::runtime_error(message) {}
	};

	class instruction_list final {
	public:
		using pointer = cs_insn*;
		using size_type = std::size_t;

		instruction_list() noexcept = default;

		instruction_list(pointer data, size_type size) noexcept
			: m_data(data)
			, m_size(size) {}

		~instruction_list() {
			cs_free(m_data, m_size);
		}

		instruction_list(instruction_list&& other) noexcept
			: m_data(other.m_data)
			, m_size(other.m_size) {
			other.m_data = nullptr;
			other.m_size = 0;
		}

		auto operator=(instruction_list&& other) noexcept -> instruction_list& {
			cs_free(m_data, m_size);
			m_data = other.m_data;
			m_size = other.m_size;
			other.m_data = nullptr;
			other.m_size = 0;
			return *this;
		}

		// Disallow copying.
		instruction_list(const instruction_list&) = delete;
		auto operator=(const instruction_list&) -> instruction_list& = delete;

		operator std::span<cs_insn>() const noexcept {
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

	[[nodiscard]] static auto is_branch(const cs_insn& info) -> bool {
		for (auto group_index = std::uint8_t{0}; group_index < info.detail->groups_count; ++group_index) {
			const auto& group = info.detail->groups[group_index];
			if (group == CS_GRP_JUMP || group == CS_GRP_CALL || group == CS_GRP_RET || group == CS_GRP_IRET || group == CS_GRP_BRANCH_RELATIVE) {
				return true;
			}
		}
		return false;
	}

	[[nodiscard]] static auto is_unconditional_jump(const cs_insn& info) -> bool {
		return info.id == X86_INS_JMP || info.id == X86_INS_LJMP || info.id == X86_INS_CALL || info.id == X86_INS_LCALL || info.id == X86_INS_RET || info.id == X86_INS_RETF ||
			info.id == X86_INS_RETFQ;
	}

	[[nodiscard]] static auto has_immediate_operand(const cs_insn& info) -> bool {
		for (auto op_index = std::uint8_t{0}; op_index < info.detail->x86.op_count; ++op_index) {
			const auto& op = info.detail->x86.operands[op_index];
			if (op.type == X86_OP_IMM) {
				return true;
			}
		}
		return false;
	}

	disassembler() {
		if (const auto err = cs_open(CS_ARCH_X86, CS_MODE_64, &m_cs); err != CS_ERR_OK) {
			throw error{cs_strerror(err)};
		}
		if (const auto err = cs_option(m_cs, CS_OPT_DETAIL, CS_OPT_ON); err != CS_ERR_OK) {
			throw error{cs_strerror(err)};
		}
	}

	~disassembler() {
		cs_close(&m_cs);
	}

	// Disallow copying and moving.
	disassembler(const disassembler&) = delete;
	disassembler(disassembler&&) = delete;
	auto operator=(const disassembler&) -> disassembler& = delete;
	auto operator=(disassembler &&) -> disassembler& = delete;

	struct disassemble_result final {
		instruction_list instructions{};
	};

	[[nodiscard]] auto disassemble(std::basic_string_view<unsigned char> code, std::uint64_t address = 0, std::size_t count = 0) const -> disassemble_result {
		cs_insn* insn = nullptr;
		const auto size = cs_disasm(m_cs, code.data(), code.size(), address, count, &insn);
		if (size < count) {
			throw error{cs_strerror(cs_errno(m_cs))};
		}
		return disassemble_result{instruction_list{insn, size}};
	}

private:
	csh m_cs{};
};

} // namespace desync

#endif
