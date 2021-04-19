#include <cstdlib>                 // EXIT_SUCCESS, EXIT_FAILURE
#include <iostream>                // std::cerr
#include <pred/assembler.hpp>      // desync::assembler
#include <pred/desynchronizer.hpp> // desync::desynchronizer
#include <pred/disassembler.hpp>   // desync::disassembler
#include <stdexcept>               // std::exception
#include <string>                  // std::string
#include <util/file.hpp>           // desync::util::read_file, desync::util::write_file
#include <util/print.hpp>          // desync::util::println

auto main(int argc, char* argv[]) -> int {
	using desync::util::println;
	try {
		auto assembler = desync::assembler{};
		auto disassembler = desync::disassembler{};

		if (argc <= 1) {
			println("Usage: desync-pred <file(s)...>");
			return EXIT_FAILURE;
		}

		// TODO: Parse options from environment variable/config file
		// (use std::getenv("DESYNC_OPTIONS")/std::getenv("DESYNC_OPTIONS_FILE") from <cstdlib>).

		auto error = false;
		for (auto i = 1; i < argc; ++i) {
			const auto* const filename = argv[i];
			const auto assembly = desync::util::read_file(filename);
			if (!assembly) {
				println("desync: Failed to open file \"", filename, "\" for reading.");
				error = true;
				continue;
			}
			auto new_assembly = std::string{};
			try {
				// TODO: Remove these temporary test prints.
				println(
					"===================================================================\n"
					"ASSEMBLY\n"
					"===================================================================\n",
					*assembly);
				println(
					"===================================================================\n"
					"CONTROL FLOW GRAPH\n"
					"===================================================================\n",
					desync::control_flow_graph{assembler, disassembler, *assembly});

				new_assembly = desync::desynchronizer::process_assembly(assembler, disassembler, *assembly);
			} catch (const std::exception& e) {
				println("desync: ", filename, ": ", e.what());
				error = true;
				continue;
			} catch (...) {
				println("desync: Failed to process file \"", filename, "\".");
				error = true;
				continue;
			}
			if (!desync::util::write_file(filename, new_assembly)) {
				println("desync: Failed to open file \"", filename, "\" for writing.");
				error = true;
			}
		}

		if (error) {
			// Some file produced an error.
			return EXIT_FAILURE;
		}
	} catch (const std::exception& e) {
		println("desync: Fatal error: ", e.what());
		return EXIT_FAILURE;
	} catch (...) {
		println("desync: Fatal error!");
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}