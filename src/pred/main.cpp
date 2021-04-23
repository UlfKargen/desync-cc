#include <cstdlib>                 // std::getenv, EXIT_SUCCESS, EXIT_FAILURE
#include <iostream>                // std::cerr
#include <pred/configuration.hpp>  // desync::configuration
#include <pred/desynchronizer.hpp> // desync::desynchronizer
#include <pred/options.hpp>        // desync::options
#include <stdexcept>               // std::exception
#include <string>                  // std::string
#include <util/file.hpp>           // desync::util::read_file, desync::util::write_file
#include <util/print.hpp>          // desync::util::println

using desync::util::println;

namespace {

auto print_usage() -> void {
	println("Usage: desync-pred [options...] <file...>");
}

} // namespace

auto main(int argc, char* argv[]) -> int {
	try {
		const auto options = desync::options::from_command_line(argc, argv);
		if (options.help || options.version) {
			println("desync-pred version 0.0.1");
			if (options.help) {
				print_usage();
				println(desync::options::usage());
			}
			return EXIT_SUCCESS;
		}

		if (options.arguments.empty()) {
			print_usage();
			return EXIT_FAILURE;
		}

		auto desynchronizer = desync::desynchronizer{};
		if (!options.config_string.empty()) {
			auto config = desync::configuration::from_string(options.config_string);
			config.verbose = config.verbose || options.verbose;
			desynchronizer.configure(config);
		} else {
			auto config_file = options.config_file;
			if (config_file.empty()) {
				if (const auto* const value = std::getenv("DESYNC_CONFIG_FILE")) {
					config_file = value;
				}
			}
			if (config_file.empty()) {
				println("desync: Warning: No config specified. Using default configuration.");
			} else if (auto config_string = desync::util::read_file(std::string{config_file}.c_str())) {
				auto config = desync::configuration::from_string(*config_string);
				config.verbose = config.verbose || options.verbose;
				desynchronizer.configure(config);
			} else {
				println("desync: Failed to open config file \"", config_file, "\" for reading.");
				return EXIT_FAILURE;
			}
		}

		auto error = false;
		for (const auto& argument : options.arguments) {
			const auto filename = std::string{argument};
			const auto assembly = desync::util::read_file(filename.c_str());
			if (!assembly) {
				println("desync: Failed to open file \"", filename, "\" for reading.");
				error = true;
				continue;
			}
			auto new_assembly = std::string{};
			try {
				new_assembly = desynchronizer.apply_predicates(*assembly);
			} catch (const std::exception& e) {
				println("desync: ", filename, ": ", e.what());
				error = true;
				continue;
			} catch (...) {
				println("desync: Failed to process file \"", filename, "\".");
				error = true;
				continue;
			}
			if (!desync::util::write_file(filename.c_str(), new_assembly)) {
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