#ifndef DESYNC_DISASSEMBLER_H
#define DESYNC_DISASSEMBLER_H

#include <array>               // std::array
#include <bitset>              // std::bitset
#include <capstone/capstone.h> // csh, cs_..., CS_..., X86_...
#include <cassert>             // assert
#include <cstddef>             // std::size_t
#include <cstdint>             // std::uint8_t, std::uint64_t
#include <span>                // std::span
#include <stdexcept>           // std::runtime_error
#include <string>              // std::string, std::to_string
#include <string_view>         // std::basic_string_view

namespace desync {

class disassembler final {
public:
	static constexpr auto register_count = std::size_t{X86_REG_ENDING - 1};
	static constexpr auto flag_count = std::size_t{32 + 4};

	enum class flag : std::size_t {
		CF = 0,
		PF = 2,
		AF = 4,
		ZF = 6,
		SF = 7,
		TF = 8,
		IF = 9,
		DF = 10,
		OF = 11,
		NT = 14,
		RF = 16,
		C0 = 32,
		C1 = 33,
		C2 = 34,
		C3 = 35,
	};

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
		assert(info.detail);
		for (auto op_index = std::uint8_t{0}; op_index < info.detail->x86.op_count; ++op_index) {
			const auto& op = info.detail->x86.operands[op_index];
			if (op.type == X86_OP_IMM) {
				return true;
			}
		}
		return false;
	}

	[[nodiscard]] static auto registers_8bit() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[static_cast<std::size_t>(X86_REG_AH - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_AL - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_BH - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_BL - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_CH - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_CL - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_DH - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_DL - 1)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_16bit() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[static_cast<std::size_t>(X86_REG_AX - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_BX - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_CX - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_DX - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_SI - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_DI - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_BP - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_SP - 1)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_32bit() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[static_cast<std::size_t>(X86_REG_EAX - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_EBX - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_ECX - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_EDX - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_ESI - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_EDI - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_EBP - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_ESP - 1)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_64bit() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[static_cast<std::size_t>(X86_REG_RAX - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_RBX - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_RCX - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_RDX - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_RSI - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_RDI - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_RBP - 1)] = true;
			result[static_cast<std::size_t>(X86_REG_RSP - 1)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] auto registers_string(const std::bitset<register_count>& registers) const -> std::string {
		assert(m_cs);
		auto result = std::string{};
		for (auto i = std::size_t{0}; i < registers.size(); ++i) {
			if (registers[i]) {
				const auto reg_id = static_cast<unsigned>(i + 1);
				if (const auto* const name = cs_reg_name(m_cs, reg_id)) {
					result.append(name);
					result.append(", ");
				} else {
					result.append("???, ");
				}
			}
		}
		if (!result.empty()) {
			// Remove the ", " at the end.
			result.pop_back();
			result.pop_back();
		}
		return result;
	}

	[[nodiscard]] auto flags_string(const std::bitset<flag_count>& flags) const -> std::string { // NOLINT(readability-convert-member-functions-to-static)
		auto result = std::string{};
		for (auto i = std::size_t{0}; i < flags.size(); ++i) {
			if (flags[i]) {
				// clang-format off
				switch (i) {
					case static_cast<std::size_t>(flag::CF): result.append("CF, "); break;
					case static_cast<std::size_t>(flag::PF): result.append("PF, "); break;
					case static_cast<std::size_t>(flag::AF): result.append("AF, "); break;
					case static_cast<std::size_t>(flag::ZF): result.append("ZF, "); break;
					case static_cast<std::size_t>(flag::SF): result.append("SF, "); break;
					case static_cast<std::size_t>(flag::TF): result.append("TF, "); break;
					case static_cast<std::size_t>(flag::IF): result.append("IF, "); break;
					case static_cast<std::size_t>(flag::DF): result.append("DF, "); break;
					case static_cast<std::size_t>(flag::OF): result.append("OF, "); break;
					case static_cast<std::size_t>(flag::NT): result.append("NT, "); break;
					case static_cast<std::size_t>(flag::RF): result.append("RF, "); break;
					case static_cast<std::size_t>(flag::C0): result.append("C0, "); break;
					case static_cast<std::size_t>(flag::C1): result.append("C1, "); break;
					case static_cast<std::size_t>(flag::C2): result.append("C2, "); break;
					case static_cast<std::size_t>(flag::C3): result.append("C3, "); break;
					default:
						result.append(std::to_string(i));
						result.append(", ");
						break;
				}
				// clang-format on
			}
		}
		if (!result.empty()) {
			// Remove the ", " at the end.
			result.pop_back();
			result.pop_back();
		}
		return result;
	}

	struct access_result final {
		std::bitset<register_count> registers_read{};
		std::bitset<register_count> registers_written{};
		std::bitset<flag_count> flags_read{};
		std::bitset<flag_count> flags_written{};
	};

	[[nodiscard]] auto access(const cs_insn& info) const -> access_result {
		auto result = access_result{};
		assert(m_cs);
		assert(info.detail);

		auto regs_read = std::array<std::uint16_t, sizeof(cs_regs) / sizeof(std::uint16_t)>{};
		auto regs_write = std::array<std::uint16_t, sizeof(cs_regs) / sizeof(std::uint16_t)>{};
		auto read_count = std::uint8_t{};
		auto write_count = std::uint8_t{};
		if (const auto err = cs_regs_access(m_cs, &info, regs_read.data(), &read_count, regs_write.data(), &write_count); err != CS_ERR_OK) {
			throw error{cs_strerror(err)};
		}

		for (auto i = std::size_t{0}; i < read_count; ++i) {
			assert(regs_read[i] >= 1);
			assert(static_cast<std::size_t>(regs_read[i] - 1) < result.registers_read.size());
			result.registers_read[static_cast<std::size_t>(regs_read[i] - 1)] = true;
		}

		for (auto i = std::size_t{0}; i < write_count; ++i) {
			assert(regs_write[i] >= 1);
			assert(static_cast<std::size_t>(regs_write[i] - 1) < result.registers_written.size());
			result.registers_written[static_cast<std::size_t>(regs_write[i] - 1)] = true;
		}

		result.flags_read[static_cast<std::size_t>(flag::CF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_TEST_CF);
		result.flags_read[static_cast<std::size_t>(flag::PF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_TEST_PF);
		result.flags_read[static_cast<std::size_t>(flag::AF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_TEST_AF);
		result.flags_read[static_cast<std::size_t>(flag::ZF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_TEST_ZF);
		result.flags_read[static_cast<std::size_t>(flag::SF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_TEST_SF);
		result.flags_read[static_cast<std::size_t>(flag::TF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_TEST_TF);
		result.flags_read[static_cast<std::size_t>(flag::IF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_TEST_IF);
		result.flags_read[static_cast<std::size_t>(flag::DF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_TEST_DF);
		result.flags_read[static_cast<std::size_t>(flag::OF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_TEST_OF);
		result.flags_read[static_cast<std::size_t>(flag::NT)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_TEST_NT);
		result.flags_read[static_cast<std::size_t>(flag::RF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_TEST_RF);

		result.flags_read[static_cast<std::size_t>(flag::C0)] = static_cast<bool>(info.detail->x86.eflags & X86_FPU_FLAGS_TEST_C0);
		result.flags_read[static_cast<std::size_t>(flag::C1)] = static_cast<bool>(info.detail->x86.eflags & X86_FPU_FLAGS_TEST_C1);
		result.flags_read[static_cast<std::size_t>(flag::C2)] = static_cast<bool>(info.detail->x86.eflags & X86_FPU_FLAGS_TEST_C2);
		result.flags_read[static_cast<std::size_t>(flag::C3)] = static_cast<bool>(info.detail->x86.eflags & X86_FPU_FLAGS_TEST_C3);

		result.flags_written[static_cast<std::size_t>(flag::CF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_MODIFY_CF);
		result.flags_written[static_cast<std::size_t>(flag::PF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_MODIFY_PF);
		result.flags_written[static_cast<std::size_t>(flag::AF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_MODIFY_AF);
		result.flags_written[static_cast<std::size_t>(flag::ZF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_MODIFY_ZF);
		result.flags_written[static_cast<std::size_t>(flag::SF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_MODIFY_SF);
		result.flags_written[static_cast<std::size_t>(flag::TF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_MODIFY_TF);
		result.flags_written[static_cast<std::size_t>(flag::IF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_MODIFY_IF);
		result.flags_written[static_cast<std::size_t>(flag::DF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_MODIFY_DF);
		result.flags_written[static_cast<std::size_t>(flag::OF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_MODIFY_OF);
		result.flags_written[static_cast<std::size_t>(flag::NT)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_MODIFY_NT);
		result.flags_written[static_cast<std::size_t>(flag::RF)] = static_cast<bool>(info.detail->x86.eflags & X86_EFLAGS_MODIFY_RF);

		result.flags_written[static_cast<std::size_t>(flag::C0)] = static_cast<bool>(info.detail->x86.eflags & X86_FPU_FLAGS_MODIFY_C0);
		result.flags_written[static_cast<std::size_t>(flag::C1)] = static_cast<bool>(info.detail->x86.eflags & X86_FPU_FLAGS_MODIFY_C1);
		result.flags_written[static_cast<std::size_t>(flag::C2)] = static_cast<bool>(info.detail->x86.eflags & X86_FPU_FLAGS_MODIFY_C2);
		result.flags_written[static_cast<std::size_t>(flag::C3)] = static_cast<bool>(info.detail->x86.eflags & X86_FPU_FLAGS_MODIFY_C3);
		return result;
	}

	[[nodiscard]] auto register_name(std::size_t index) const -> std::string_view {
		const auto reg_id = static_cast<unsigned>(index + 1);
		return cs_reg_name(m_cs, reg_id);
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

	disassembler(disassembler&& other) noexcept
		: m_cs(other.m_cs) {
		other.m_cs = csh{};
	}

	auto operator=(disassembler&& other) noexcept -> disassembler& {
		cs_close(&m_cs);
		m_cs = other.m_cs;
		other.m_cs = csh{};
		return *this;
	}

	// Disallow copying.
	disassembler(const disassembler&) = delete;
	auto operator=(const disassembler&) -> disassembler& = delete;

	struct disassemble_result final {
		instruction_list instructions{};
	};

	[[nodiscard]] auto disassemble(std::basic_string_view<unsigned char> code, std::uint64_t address = 0, std::size_t count = 0) const -> disassemble_result {
		assert(m_cs);
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
