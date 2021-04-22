#ifndef DESYNC_DESYNCHRONIZER_H
#define DESYNC_DESYNCHRONIZER_H

#include <pred/control_flow_graph.hpp> // desync::control_flow_graph
#include <stdexcept>                   // std::runtime_error
#include <string>                      // std::string
#include <string_view>                 // std::string_view
#include <util/print.hpp>              // desync::util::println
#include <util/string.hpp>             // desync::util::concat

namespace desync {

class desynchronizer final {
public:
	struct error final : std::runtime_error {
		[[nodiscard]] explicit error(const auto&... args)
			: std::runtime_error(util::concat(args...)) {}
	};

	[[nodiscard]] static auto process_assembly(std::string_view assembly) -> std::string {
		auto result = std::string{assembly};
		auto cfg = control_flow_graph{assembly};
		cfg.analyze_liveness();

		// TODO: Remove these test prints.
		util::println(
			"===================================================================\n"
			"ASSEMBLY\n"
			"===================================================================\n",
			assembly);
		util::println(
			"===================================================================\n"
			"CONTROL FLOW GRAPH\n"
			"===================================================================\n",
			cfg);

		// TODO: Remove this example code.
		const auto get_instruction = [&cfg](std::size_t i) -> const control_flow_graph::instruction& {
			if (i < cfg.instructions().size()) {
				return cfg.instructions()[i];
			}
			throw error{"No instruction at ", i, "!"};
		};

		const auto get_file_index = [&assembly](const control_flow_graph::instruction& instruction) -> std::size_t {
			return instruction.string.data() - assembly.data();
		};

		const auto* const main_block = cfg.symbol("main");
		if (main_block) {
			const auto& instruction = get_instruction(main_block->begin);
			const auto file_index = get_file_index(instruction);
			util::println("Main is at: ", file_index);
			//util::println("Assembly, starting at main: ", assembly.substr(file_index));
		}

		// TODO: Insert predicates.
		return result;
	}
};

} // namespace desync

#endif
