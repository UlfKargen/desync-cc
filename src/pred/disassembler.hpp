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
	static constexpr auto num_extra_64_registers = std::size_t{X86_REG_R15 - X86_REG_R8 + 1};

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

	[[nodiscard]] static constexpr auto register_index(unsigned id) noexcept -> std::size_t {
		return static_cast<std::size_t>(id - 1);
	}

	[[nodiscard]] static constexpr auto register_id(std::size_t index) noexcept -> unsigned {
		return static_cast<unsigned>(index + 1);
	}

	[[nodiscard]] static constexpr auto flag_index(flag f) noexcept -> std::size_t {
		return static_cast<std::size_t>(f);
	}

	[[nodiscard]] static auto is_branch(const cs_insn& info) -> bool {
		for (auto group_index = std::uint8_t{0}; group_index < info.detail->groups_count; ++group_index) {
			const auto& group = info.detail->groups[group_index];
			if (group == CS_GRP_JUMP || group == CS_GRP_CALL || group == CS_GRP_RET || group == CS_GRP_IRET || group == CS_GRP_BRANCH_RELATIVE) {
				return true;
			}
		}
		return false;
	}

	[[nodiscard]] static auto is_call(const cs_insn& info) -> bool {
		for (auto group_index = std::uint8_t{0}; group_index < info.detail->groups_count; ++group_index) {
			const auto& group = info.detail->groups[group_index];
			if (group == CS_GRP_CALL){
				return true;
			}
		}
		return false;
	}
	

	[[nodiscard]] static auto is_unconditional_jump(const cs_insn& info) -> bool {
		return info.id == X86_INS_JMP || info.id == X86_INS_LJMP || info.id == X86_INS_RET || info.id == X86_INS_RETF || info.id == X86_INS_RETFQ;
	}

	[[nodiscard]] static auto has_operand(const cs_insn& info) -> bool {
		assert(info.detail);
		return info.detail->x86.op_count > 0;
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

	[[nodiscard]] static auto general_registers_8bit() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[register_index(X86_REG_AH)] = true;
			result[register_index(X86_REG_AL)] = true;
			result[register_index(X86_REG_BH)] = true;
			result[register_index(X86_REG_BL)] = true;
			result[register_index(X86_REG_CH)] = true;
			result[register_index(X86_REG_CL)] = true;
			result[register_index(X86_REG_DH)] = true;
			result[register_index(X86_REG_DL)] = true;
			for (auto i = std::size_t{0}; i < num_extra_64_registers; ++i){
				result[register_index(X86_REG_R8B) + i] = true;
			}
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto general_registers_16bit() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[register_index(X86_REG_AX)] = true;
			result[register_index(X86_REG_BX)] = true;
			result[register_index(X86_REG_CX)] = true;
			result[register_index(X86_REG_DX)] = true;
			for (auto i = std::size_t{0}; i < num_extra_64_registers; ++i){
				result[register_index(X86_REG_R8W) + i] = true;
			}
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto general_registers_32bit() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[register_index(X86_REG_EAX)] = true;
			result[register_index(X86_REG_EBX)] = true;
			result[register_index(X86_REG_ECX)] = true;
			result[register_index(X86_REG_EDX)] = true;
			for (auto i = std::size_t{0}; i < num_extra_64_registers; ++i){
				result[register_index(X86_REG_R8D) + i] = true;
			}
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto general_registers_64bit() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[register_index(X86_REG_RAX)] = true;
			result[register_index(X86_REG_RBX)] = true;
			result[register_index(X86_REG_RCX)] = true;
			result[register_index(X86_REG_RDX)] = true;
			for (auto i = std::size_t{0}; i < num_extra_64_registers; ++i){
				result[register_index(X86_REG_R8) + i] = true;
			}
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_8bit() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result |= general_registers_8bit();
			result[register_index(X86_REG_SIL)] = true;
			result[register_index(X86_REG_DIL)] = true;
			result[register_index(X86_REG_BPL)] = true;
			result[register_index(X86_REG_SPL)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_16bit() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result |= general_registers_16bit();
			result[register_index(X86_REG_SI)] = true;
			result[register_index(X86_REG_DI)] = true;
			result[register_index(X86_REG_BP)] = true;
			result[register_index(X86_REG_SP)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_32bit() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result |= general_registers_32bit();
			result[register_index(X86_REG_ESI)] = true;
			result[register_index(X86_REG_EDI)] = true;
			result[register_index(X86_REG_EBP)] = true;
			result[register_index(X86_REG_ESP)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_64bit() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result |= general_registers_64bit();
			result[register_index(X86_REG_RSI)] = true;
			result[register_index(X86_REG_RDI)] = true;
			result[register_index(X86_REG_RBP)] = true;
			result[register_index(X86_REG_RSP)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_ax() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[register_index(X86_REG_AH)] = true;
			result[register_index(X86_REG_AL)] = true;
			result[register_index(X86_REG_AX)] = true;
			result[register_index(X86_REG_EAX)] = true;
			result[register_index(X86_REG_RAX)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_bx() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[register_index(X86_REG_BH)] = true;
			result[register_index(X86_REG_BL)] = true;
			result[register_index(X86_REG_BX)] = true;
			result[register_index(X86_REG_EBX)] = true;
			result[register_index(X86_REG_RBX)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_cx() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[register_index(X86_REG_CH)] = true;
			result[register_index(X86_REG_CL)] = true;
			result[register_index(X86_REG_CX)] = true;
			result[register_index(X86_REG_ECX)] = true;
			result[register_index(X86_REG_RCX)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_dx() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[register_index(X86_REG_DH)] = true;
			result[register_index(X86_REG_DL)] = true;
			result[register_index(X86_REG_DX)] = true;
			result[register_index(X86_REG_EDX)] = true;
			result[register_index(X86_REG_RDX)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_si() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[register_index(X86_REG_SIL)] = true;
			result[register_index(X86_REG_SI)] = true;
			result[register_index(X86_REG_ESI)] = true;
			result[register_index(X86_REG_RSI)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_di() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[register_index(X86_REG_DIL)] = true;
			result[register_index(X86_REG_DI)] = true;
			result[register_index(X86_REG_EDI)] = true;
			result[register_index(X86_REG_RDI)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_bp() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[register_index(X86_REG_BPL)] = true;
			result[register_index(X86_REG_BP)] = true;
			result[register_index(X86_REG_EBP)] = true;
			result[register_index(X86_REG_RBP)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_sp() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result[register_index(X86_REG_SPL)] = true;
			result[register_index(X86_REG_SP)] = true;
			result[register_index(X86_REG_ESP)] = true;
			result[register_index(X86_REG_RSP)] = true;
			return result;
		}();
		return bits;
	}

	[[nodiscard]] static auto registers_r64(std::size_t i) -> std::bitset<register_count> {
		assert (i < num_extra_64_registers);
		auto result = std::bitset<register_count>{};
		result[register_index(X86_REG_R8 + i)] = true;
		result[register_index(X86_REG_R8D + i)] = true;
		result[register_index(X86_REG_R8W + i)] = true;
		result[register_index(X86_REG_R8B + i)] = true;
		return result;
	}

	[[nodiscard]] static auto all_registers_r64() -> std::bitset<register_count> {
		auto result = std::bitset<register_count>{};
		for (auto i = std::size_t{0}; i < num_extra_64_registers; ++i){
			result[register_index(X86_REG_R8 + i)] = true;
			result[register_index(X86_REG_R8D + i)] = true;
			result[register_index(X86_REG_R8W + i)] = true;
			result[register_index(X86_REG_R8B + i)] = true;
		}
		return result;
	}

	/**
	 * @brief Registers that are potentially overwritten during a function call.
	 */
	[[nodiscard]] static auto scratch_registers() -> std::bitset<register_count> {
		static const auto bits = [] {
			auto result = std::bitset<register_count>{};
			result |= registers_ax();
			//result |= registers_di(); // these registers are used to pass parameters
			//result |= registers_si(); // they could be used when function takes less than four arguments
			//result |= registers_dx();
			//result |= registers_cx();
			//result |= registers_r64(X86_REG_R8 - X86_REG_R8);
			//result |= registers_r64(X86_REG_R9 - X86_REG_R8);
			result |= registers_r64(X86_REG_R10 - X86_REG_R8);
			result |= registers_r64(X86_REG_R11 - X86_REG_R8);
			return result;
		}();
		return bits;
	}

	/**
	 * @brief Return a set of all registers related to the register in the given set of registers.
	 */
	[[nodiscard]] static auto related_registers(std::size_t i) -> std::bitset<register_count> {
		// clang-format off
		switch (i) {
			case register_index(X86_REG_AH): [[fallthrough]];
			case register_index(X86_REG_AL): [[fallthrough]];
			case register_index(X86_REG_AX): [[fallthrough]];
			case register_index(X86_REG_EAX): [[fallthrough]];
			case register_index(X86_REG_RAX):
				return registers_ax();
			case register_index(X86_REG_BH): [[fallthrough]];
			case register_index(X86_REG_BL): [[fallthrough]];
			case register_index(X86_REG_BX): [[fallthrough]];
			case register_index(X86_REG_EBX): [[fallthrough]];
			case register_index(X86_REG_RBX):
				return registers_bx();
			case register_index(X86_REG_CH): [[fallthrough]];
			case register_index(X86_REG_CL): [[fallthrough]];
			case register_index(X86_REG_CX): [[fallthrough]];
			case register_index(X86_REG_ECX): [[fallthrough]];
			case register_index(X86_REG_RCX):
				return registers_cx();
			case register_index(X86_REG_DH): [[fallthrough]];
			case register_index(X86_REG_DL): [[fallthrough]];
			case register_index(X86_REG_DX): [[fallthrough]];
			case register_index(X86_REG_EDX): [[fallthrough]];
			case register_index(X86_REG_RDX):
				return registers_dx();
			case register_index(X86_REG_SIL): [[fallthrough]];
			case register_index(X86_REG_SI): [[fallthrough]];
			case register_index(X86_REG_ESI): [[fallthrough]];
			case register_index(X86_REG_RSI):
				return registers_si();
			case register_index(X86_REG_DIL): [[fallthrough]];
			case register_index(X86_REG_DI): [[fallthrough]];
			case register_index(X86_REG_EDI): [[fallthrough]];
			case register_index(X86_REG_RDI):
				return registers_di();
			case register_index(X86_REG_BPL): [[fallthrough]];
			case register_index(X86_REG_BP): [[fallthrough]];
			case register_index(X86_REG_EBP): [[fallthrough]];
			case register_index(X86_REG_RBP):
				return registers_bp();
			case register_index(X86_REG_SPL): [[fallthrough]];
			case register_index(X86_REG_SP): [[fallthrough]];
			case register_index(X86_REG_ESP): [[fallthrough]];
			case register_index(X86_REG_RSP):
				return registers_sp();
		}
		// clang-format on
		if (register_index(X86_REG_R8) <= i && i <= register_index(X86_REG_R15)){
			return registers_r64(register_id(i) - X86_REG_R8);	
		}
		if (register_index(X86_REG_R8D) <= i && i <= register_index(X86_REG_R15D)){
			return registers_r64(register_id(i) - X86_REG_R8D);	
		}
		if (register_index(X86_REG_R8W) <= i && i <= register_index(X86_REG_R15W)){
			return registers_r64(register_id(i) - X86_REG_R8W);	
		}
		if (register_index(X86_REG_R8B) <= i && i <= register_index(X86_REG_R15B)){
			return registers_r64(register_id(i) - X86_REG_R8B);	
		}
		auto result = std::bitset<register_count>{};
		result[i] = true;
		return result;
	}

	/**
	 * @brief Return a set of all registers overwritten by writes to the given register.
	 * 
	 * For example AX is always overwitten when EAX is written to, while RAX could still keep values in the high bits.
	 */
	[[nodiscard]] static auto registers_affected_by(std::size_t i) -> std::bitset<register_count> {
		auto result = std::bitset<register_count>{};
		// clang-format off
		switch (i) {
			//AX
			case register_index(X86_REG_RAX): 
				result[register_index(X86_REG_RAX)] = true; [[fallthrough]];
			case register_index(X86_REG_EAX):
				result[register_index(X86_REG_EAX)] = true; [[fallthrough]];
			case register_index(X86_REG_AX):
				result[register_index(X86_REG_AX)] = true;
				result[register_index(X86_REG_AH)] = true;
				result[register_index(X86_REG_AL)] = true;
				return result;			
			case register_index(X86_REG_AH):
				result[register_index(X86_REG_AH)] = true;
				return result;
			case register_index(X86_REG_AL):
				result[register_index(X86_REG_AL)] = true;
				return result;
			//BX
			case register_index(X86_REG_RBX):
				result[register_index(X86_REG_RBX)] = true; [[fallthrough]];
			case register_index(X86_REG_EBX):
				result[register_index(X86_REG_EBX)] = true; [[fallthrough]];
			case register_index(X86_REG_BX):
				result[register_index(X86_REG_BX)] = true;
				result[register_index(X86_REG_BH)] = true;
				result[register_index(X86_REG_BL)] = true;
				return result;			
			case register_index(X86_REG_BH):
				result[register_index(X86_REG_BH)] = true;
				return result;
			case register_index(X86_REG_BL):
				result[register_index(X86_REG_BL)] = true;
				return result;
			//CX
			case register_index(X86_REG_RCX):
				result[register_index(X86_REG_RCX)] = true; [[fallthrough]];
			case register_index(X86_REG_ECX):
				result[register_index(X86_REG_ECX)] = true; [[fallthrough]];
			case register_index(X86_REG_CX):
				result[register_index(X86_REG_CX)] = true;
				result[register_index(X86_REG_CH)] = true;
				result[register_index(X86_REG_CL)] = true;
				return result;			
			case register_index(X86_REG_CH):
				result[register_index(X86_REG_CH)] = true;
				return result;
			case register_index(X86_REG_CL):
				result[register_index(X86_REG_CL)] = true;
				return result;
			//DX
			case register_index(X86_REG_RDX):
				result[register_index(X86_REG_RDX)] = true; [[fallthrough]];
			case register_index(X86_REG_EDX):
				result[register_index(X86_REG_EDX)] = true; [[fallthrough]];
			case register_index(X86_REG_DX):
				result[register_index(X86_REG_DX)] = true;
				result[register_index(X86_REG_DH)] = true;
				result[register_index(X86_REG_DL)] = true;
				return result;			
			case register_index(X86_REG_DH):
				result[register_index(X86_REG_DH)] = true;
				return result;
			case register_index(X86_REG_DL):
				result[register_index(X86_REG_DL)] = true;
				return result;
			//SI
			case register_index(X86_REG_RSI):
				result[register_index(X86_REG_RSI)] = true; [[fallthrough]];
			case register_index(X86_REG_ESI): 
				result[register_index(X86_REG_ESI)] = true; [[fallthrough]];
			case register_index(X86_REG_SI): 
				result[register_index(X86_REG_SI)] = true; [[fallthrough]];
			case register_index(X86_REG_SIL):
				result[register_index(X86_REG_SIL)] = true;
				return result;
			//DI
			case register_index(X86_REG_RDI):
				result[register_index(X86_REG_RDI)] = true; [[fallthrough]];
			case register_index(X86_REG_EDI):
				result[register_index(X86_REG_EDI)] = true; [[fallthrough]];
			case register_index(X86_REG_DI): 
				result[register_index(X86_REG_DI)] = true; [[fallthrough]];	
			case register_index(X86_REG_DIL):
				result[register_index(X86_REG_DIL)] = true;
				return result;
			//BP
			case register_index(X86_REG_RBP):
				result[register_index(X86_REG_RBP)] = true; [[fallthrough]];
			case register_index(X86_REG_EBP):
				result[register_index(X86_REG_EBP)] = true; [[fallthrough]];
			case register_index(X86_REG_BP):
				result[register_index(X86_REG_BP)] = true; [[fallthrough]];	
			case register_index(X86_REG_BPL):
				result[register_index(X86_REG_BPL)] = true;
				return result;
			//SP
			case register_index(X86_REG_RSP):
				result[register_index(X86_REG_RSP)] = true; [[fallthrough]];
			case register_index(X86_REG_ESP):
				result[register_index(X86_REG_ESP)] = true; [[fallthrough]];
			case register_index(X86_REG_SP):
				result[register_index(X86_REG_SP)] = true; [[fallthrough]];	
			case register_index(X86_REG_SPL):
				result[register_index(X86_REG_SPL)] = true;
				return result;
		}
		// clang-format on
		// R8-R15
		if (register_index(X86_REG_R8) <= i && i <= register_index(X86_REG_R15)){
			result[i] = true;
			result[i + X86_REG_R8D - X86_REG_R8] = true;
			result[i + X86_REG_R8W - X86_REG_R8] = true;
			result[i + X86_REG_R8B - X86_REG_R8] = true;
			return result;
		}
		if (register_index(X86_REG_R8D) <= i && i <= register_index(X86_REG_R15D)){
			result[i] = true;
			result[i + X86_REG_R8W - X86_REG_R8D] = true;
			result[i + X86_REG_R8B - X86_REG_R8D] = true;
			return result;
		}
		if (register_index(X86_REG_R8W) <= i && i <= register_index(X86_REG_R15W)){
			result[i] = true;
			result[i + X86_REG_R8B - X86_REG_R8W] = true;
			return result;
		}
		if (register_index(X86_REG_R8B) <= i && i <= register_index(X86_REG_R15B)){
			result[i] = true;
			return result;
		}
		result[i] = true;
		return result;
	}

	/**
	 * @brief Return a set of all registers related to any register in the given set of registers.
	 * Same as calling related_registers(std::size_t i) for each register
	 */
	[[nodiscard]] static auto related_registers(std::bitset<register_count> registers) -> std::bitset<register_count> {
		auto result = registers;
		// clang-format off
		if (registers[register_index(X86_REG_AH)] ||
			registers[register_index(X86_REG_AL)] ||
			registers[register_index(X86_REG_AX)] ||
			registers[register_index(X86_REG_EAX)] ||
			registers[register_index(X86_REG_RAX)]) {
			result |= registers_ax();
		}
		if (registers[register_index(X86_REG_BH)] ||
			registers[register_index(X86_REG_BL)] ||
			registers[register_index(X86_REG_BX)] ||
			registers[register_index(X86_REG_EBX)] ||
			registers[register_index(X86_REG_RBX)]) {
			result |= registers_bx();
		}
		if (registers[register_index(X86_REG_CH)] ||
			registers[register_index(X86_REG_CL)] ||
			registers[register_index(X86_REG_CX)] ||
			registers[register_index(X86_REG_ECX)] ||
			registers[register_index(X86_REG_RCX)]) {
			result |= registers_cx();
		}
		if (registers[register_index(X86_REG_DH)] ||
			registers[register_index(X86_REG_DL)] ||
			registers[register_index(X86_REG_DX)] ||
			registers[register_index(X86_REG_EDX)] ||
			registers[register_index(X86_REG_RDX)]) {
			result |= registers_dx();
		}
		if (registers[register_index(X86_REG_SIL)] ||
			registers[register_index(X86_REG_SI)] ||
			registers[register_index(X86_REG_ESI)] ||
			registers[register_index(X86_REG_RSI)]) {
			result |= registers_si();
		}
		if (registers[register_index(X86_REG_DIL)] ||
			registers[register_index(X86_REG_DI)] ||
			registers[register_index(X86_REG_EDI)] ||
			registers[register_index(X86_REG_RDI)]) {
			result |= registers_di();
		}
		if (registers[register_index(X86_REG_BPL)] ||
			registers[register_index(X86_REG_BP)] ||
			registers[register_index(X86_REG_EBP)] ||
			registers[register_index(X86_REG_RBP)]) {
			result |= registers_bp();
		}
		if (registers[register_index(X86_REG_SPL)] ||
			registers[register_index(X86_REG_SP)] ||
			registers[register_index(X86_REG_ESP)] ||
			registers[register_index(X86_REG_RSP)]) {
			result |= registers_sp();
		}
		for (auto i = std::size_t{0}; i < num_extra_64_registers; ++i){
			if (registers[register_index(X86_REG_R8) + i] ||
				registers[register_index(X86_REG_R8D) + i] ||
				registers[register_index(X86_REG_R8W) + i] ||
				registers[register_index(X86_REG_R8B) + i]) {
				result |= registers_r64(i);
			}
		}
		// clang-format on
		return result;
	}

	[[nodiscard]] auto registers_string(const std::bitset<register_count>& registers) const -> std::string {
		assert(m_cs);
		auto result = std::string{};
		for (auto i = std::size_t{0}; i < registers.size(); ++i) {
			if (registers[i]) {
				if (const auto* const name = cs_reg_name(m_cs, register_id(i))) {
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
					case flag_index(flag::CF): result.append("CF, "); break;
					case flag_index(flag::PF): result.append("PF, "); break;
					case flag_index(flag::AF): result.append("AF, "); break;
					case flag_index(flag::ZF): result.append("ZF, "); break;
					case flag_index(flag::SF): result.append("SF, "); break;
					case flag_index(flag::TF): result.append("TF, "); break;
					case flag_index(flag::IF): result.append("IF, "); break;
					case flag_index(flag::DF): result.append("DF, "); break;
					case flag_index(flag::OF): result.append("OF, "); break;
					case flag_index(flag::NT): result.append("NT, "); break;
					case flag_index(flag::RF): result.append("RF, "); break;
					case flag_index(flag::C0): result.append("C0, "); break;
					case flag_index(flag::C1): result.append("C1, "); break;
					case flag_index(flag::C2): result.append("C2, "); break;
					case flag_index(flag::C3): result.append("C3, "); break;
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

	/**
	 * @brief Return information about the registers and flags affected by the given instruction.
	 */
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

		//registers
		if (info.id == X86_INS_XOR && read_count < 2 && info.detail->x86.operands[0].type == X86_OP_REG && info.detail->x86.operands[1].type == X86_OP_REG){
			// special case for 'xor %r, %r' since it is so common to clear registers: the value is never used so don't treat as read
			assert(read_count == 1);
			assert(info.detail->x86.operands[0].reg == info.detail->x86.operands[1].reg);
		}
		else{
			for (auto i = std::size_t{0}; i < read_count; ++i) {
				assert(regs_read[i] >= 1);
				assert(register_index(regs_read[i]) < result.registers_read.size());
				result.registers_read[register_index(regs_read[i])] = true;
			}
		}

		for (auto i = std::size_t{0}; i < write_count; ++i) {
			assert(regs_write[i] >= 1);
			assert(register_index(regs_write[i]) < result.registers_written.size());
			result.registers_written |= registers_affected_by(register_index(regs_write[i]));
			//old method: result.registers_written[register_index(regs_write[i])] = true;
		}

		//eflags
		if (result.registers_read.test(register_index(X86_REG_EFLAGS))){
			// some instructions read from eflags register instead of giving 'test' flags
			result.flags_read.set();
		}
		else{
			result.flags_read[flag_index(flag::CF)] = (info.detail->x86.eflags & (X86_EFLAGS_TEST_CF | X86_EFLAGS_UNDEFINED_CF)) != 0;
			result.flags_read[flag_index(flag::PF)] = (info.detail->x86.eflags & (X86_EFLAGS_TEST_PF | X86_EFLAGS_UNDEFINED_PF)) != 0;
			result.flags_read[flag_index(flag::AF)] = (info.detail->x86.eflags & (X86_EFLAGS_TEST_AF | X86_EFLAGS_UNDEFINED_AF)) != 0;
			result.flags_read[flag_index(flag::ZF)] = (info.detail->x86.eflags & (X86_EFLAGS_TEST_ZF | X86_EFLAGS_UNDEFINED_ZF)) != 0;
			result.flags_read[flag_index(flag::SF)] = (info.detail->x86.eflags & (X86_EFLAGS_TEST_SF | X86_EFLAGS_UNDEFINED_SF)) != 0;
			result.flags_read[flag_index(flag::TF)] = (info.detail->x86.eflags & (X86_EFLAGS_TEST_TF)) != 0;
			result.flags_read[flag_index(flag::IF)] = (info.detail->x86.eflags & (X86_EFLAGS_TEST_IF)) != 0;
			result.flags_read[flag_index(flag::DF)] = (info.detail->x86.eflags & (X86_EFLAGS_TEST_DF)) != 0;
			result.flags_read[flag_index(flag::OF)] = (info.detail->x86.eflags & (X86_EFLAGS_TEST_OF | X86_EFLAGS_UNDEFINED_OF)) != 0;
			result.flags_read[flag_index(flag::NT)] = (info.detail->x86.eflags & (X86_EFLAGS_TEST_NT)) != 0;
			result.flags_read[flag_index(flag::RF)] = (info.detail->x86.eflags & (X86_EFLAGS_TEST_RF)) != 0;
		}

		// cannot use eflags register here because instructions that give 'modify' also set eflags register
		result.flags_written[flag_index(flag::CF)] = (info.detail->x86.eflags &
														(X86_EFLAGS_MODIFY_CF | X86_EFLAGS_RESET_CF | X86_EFLAGS_PRIOR_CF | X86_EFLAGS_SET_CF | X86_EFLAGS_UNDEFINED_CF)) != 0;
		result.flags_written[flag_index(flag::PF)] = (info.detail->x86.eflags &
														(X86_EFLAGS_MODIFY_PF | X86_EFLAGS_RESET_PF | X86_EFLAGS_PRIOR_PF | X86_EFLAGS_SET_PF | X86_EFLAGS_UNDEFINED_PF)) != 0;
		result.flags_written[flag_index(flag::AF)] = (info.detail->x86.eflags &
														(X86_EFLAGS_MODIFY_AF | X86_EFLAGS_RESET_AF | X86_EFLAGS_PRIOR_AF | X86_EFLAGS_SET_AF | X86_EFLAGS_UNDEFINED_AF)) != 0;
		result.flags_written[flag_index(flag::ZF)] = (info.detail->x86.eflags &
														(X86_EFLAGS_MODIFY_ZF | X86_EFLAGS_RESET_ZF | X86_EFLAGS_PRIOR_ZF | X86_EFLAGS_SET_ZF | X86_EFLAGS_UNDEFINED_ZF)) != 0;
		result.flags_written[flag_index(flag::SF)] = (info.detail->x86.eflags &
														(X86_EFLAGS_MODIFY_SF | X86_EFLAGS_RESET_SF | X86_EFLAGS_PRIOR_SF | X86_EFLAGS_SET_SF | X86_EFLAGS_UNDEFINED_SF)) != 0;
		result.flags_written[flag_index(flag::TF)] = (info.detail->x86.eflags & (X86_EFLAGS_MODIFY_TF | X86_EFLAGS_RESET_TF | X86_EFLAGS_PRIOR_TF)) != 0;
		result.flags_written[flag_index(flag::IF)] = (info.detail->x86.eflags & (X86_EFLAGS_MODIFY_IF | X86_EFLAGS_RESET_IF | X86_EFLAGS_PRIOR_IF | X86_EFLAGS_SET_IF)) != 0;
		result.flags_written[flag_index(flag::DF)] = (info.detail->x86.eflags & (X86_EFLAGS_MODIFY_DF | X86_EFLAGS_RESET_DF | X86_EFLAGS_PRIOR_DF | X86_EFLAGS_SET_DF)) != 0;
		result.flags_written[flag_index(flag::OF)] = (info.detail->x86.eflags &
														(X86_EFLAGS_MODIFY_OF | X86_EFLAGS_RESET_OF | X86_EFLAGS_PRIOR_OF | X86_EFLAGS_SET_OF | X86_EFLAGS_UNDEFINED_OF)) != 0;
		result.flags_written[flag_index(flag::NT)] = (info.detail->x86.eflags & (X86_EFLAGS_MODIFY_NT | X86_EFLAGS_RESET_NT | X86_EFLAGS_PRIOR_NT)) != 0;
		result.flags_written[flag_index(flag::RF)] = (info.detail->x86.eflags & (X86_EFLAGS_MODIFY_RF | X86_EFLAGS_RESET_RF)) != 0;
		

		//fpuflags
		result.flags_read[flag_index(flag::C0)] = (info.detail->x86.fpu_flags & (X86_FPU_FLAGS_TEST_C0 | X86_FPU_FLAGS_UNDEFINED_C0)) != 0;
		result.flags_read[flag_index(flag::C1)] = (info.detail->x86.fpu_flags & (X86_FPU_FLAGS_TEST_C1 | X86_FPU_FLAGS_UNDEFINED_C1)) != 0;
		result.flags_read[flag_index(flag::C2)] = (info.detail->x86.fpu_flags & (X86_FPU_FLAGS_TEST_C2 | X86_FPU_FLAGS_UNDEFINED_C2)) != 0;
		result.flags_read[flag_index(flag::C3)] = (info.detail->x86.fpu_flags & (X86_FPU_FLAGS_TEST_C3 | X86_FPU_FLAGS_UNDEFINED_C3)) != 0;

		result.flags_written[flag_index(flag::C0)] = (info.detail->x86.fpu_flags &
														(X86_FPU_FLAGS_MODIFY_C0 | X86_FPU_FLAGS_RESET_C0 | X86_FPU_FLAGS_SET_C0 | X86_FPU_FLAGS_UNDEFINED_C0)) != 0;
		result.flags_written[flag_index(flag::C1)] = (info.detail->x86.fpu_flags &
														(X86_FPU_FLAGS_MODIFY_C1 | X86_FPU_FLAGS_RESET_C1 | X86_FPU_FLAGS_SET_C1 | X86_FPU_FLAGS_UNDEFINED_C1)) != 0;
		result.flags_written[flag_index(flag::C2)] = (info.detail->x86.fpu_flags &
														(X86_FPU_FLAGS_MODIFY_C2 | X86_FPU_FLAGS_RESET_C2 | X86_FPU_FLAGS_SET_C2 | X86_FPU_FLAGS_UNDEFINED_C2)) != 0;
		result.flags_written[flag_index(flag::C3)] = (info.detail->x86.fpu_flags &
														(X86_FPU_FLAGS_MODIFY_C3 | X86_FPU_FLAGS_RESET_C3 | X86_FPU_FLAGS_SET_C3 | X86_FPU_FLAGS_UNDEFINED_C3)) != 0;

		return result;
	}

	[[nodiscard]] auto register_name(std::size_t index) const -> std::string_view {
		return cs_reg_name(m_cs, register_id(index));
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
