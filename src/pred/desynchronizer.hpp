#ifndef DESYNC_DESYNCHRONIZER_H
#define DESYNC_DESYNCHRONIZER_H

#include <pred/control_flow_graph.hpp> // desync::control_flow_graph
#include <stdexcept>                   // std::runtime_error
#include <string>                      // std::string
#include <string_view>                 // std::string_view
#include <util/string.hpp>             // desync::util::concat

namespace desync {

class desynchronizer final {
public:
	struct error final : std::runtime_error {
		[[nodiscard]] explicit error(const auto&... args)
			: std::runtime_error(desync::util::concat(args...)) {}
	};

	[[nodiscard]] static auto process_assembly(desync::assembler& assembler, desync::disassembler& disassembler, std::string_view assembly) -> std::string {
		// TODO: Remove [[maybe_unused]].
		[[maybe_unused]] const auto cfg = control_flow_graph{assembler, disassembler, assembly};
		// TODO: Insert predicates.
		return std::string{assembly};
	}
};

} // namespace desync

#endif
