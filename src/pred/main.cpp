#include <cstdlib>                 // std::getenv, EXIT_SUCCESS, EXIT_FAILURE
#include <iostream>                // std::cerr
#include <pred/configuration.hpp>  // desync::configuration
#include <pred/desynchronizer.hpp> // desync::desynchronizer
#include <pred/options.hpp>        // desync::options
#include <stdexcept>               // std::exception
#include <string>                  // std::string
#include <util/file.hpp>           // desync::util::read_file, desync::util::write_file

namespace {

auto print(const auto&... args) -> void {
	(std::cerr << ... << args);
}

auto println(const auto&... args) -> void {
	print(args..., '\n');
}

auto print_version() -> void {
	println("desync-pred version 0.0.1");
}

auto print_usage() -> void {
	println("Usage: desync-pred [options...] <file...>");
}

} // namespace

auto main(int argc, char* argv[]) -> int {
	try {
		const auto options = desync::options::from_command_line(argc, argv);
		if (options.help || options.version) {
			print_version();
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
		auto config = desync::configuration{};
		config.log_file = options.log_file;
		config.verbose = options.verbose;
		config.dry_run = options.dry_run;
		if (const auto* const env_config_base_dir = std::getenv("DESYNC_CONFIG_BASE_DIR")) {
			config.base_dir = env_config_base_dir;
			if (!config.base_dir.empty() && config.base_dir.back() != '/') {
				config.base_dir.push_back('/');
			}
		}
		if (!options.config_string.empty()) {
			config.parse_string(options.config_string);
		} else {
			auto config_file = config.base_dir;
			if (options.config_file.empty()) {
				if (const auto* const env_config_file = std::getenv("DESYNC_CONFIG_FILE")) {
					config_file.append(env_config_file);
				}
			} else {
				config_file.append(options.config_file);
			}
			if (config_file.size() == config.base_dir.size()) {
				println("desync: Warning: No config specified. Using default configuration.");
			} else if (auto config_string = desync::util::read_file(config_file.c_str())) {
				config.parse_string(*config_string);
			} else {
				println("desync: Failed to open config file \"", config_file, "\" for reading.");
				return EXIT_FAILURE;
			}
		}
		desynchronizer.configure(config);

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
				new_assembly = desynchronizer.apply_predicates(filename, *assembly);
			} catch (const std::exception& e) {
				println("desync: ", filename, ": ", e.what());
				error = true;
				continue;
			} catch (...) {
				println("desync: Failed to process file \"", filename, "\".");
				error = true;
				continue;
			}
			if (!config.dry_run) {
				if (!desync::util::write_file(filename.c_str(), new_assembly)) {
					println("desync: Failed to open file \"", filename, "\" for writing.");
					error = true;
				}
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