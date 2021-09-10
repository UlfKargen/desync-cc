#ifndef DESYNC_LOGGER_H
#define DESYNC_LOGGER_H

#include <fstream>       // std::ofstream
#include <iostream>      // std::clog
#include <string>        // std::string
#include <util/time.hpp> // desync::util::local_time_string

namespace desync {

class logger final {
public:
	// Disallow copying and moving.
	logger(const logger&) = delete;
	logger(logger&&) = delete;
	auto operator=(const logger&) -> logger& = delete;
	auto operator=(logger&&) -> logger& = delete;

	logger() noexcept = default;
	~logger() = default;

	explicit logger(const std::string& filename) {
		open(filename);
	}

	auto open(const std::string& filename) -> void {
		m_file.exceptions(std::ofstream::failbit | std::ofstream::badbit);
		m_file.open(filename, std::ofstream::out | std::ofstream::app);
		m_file << "===================================================================\n"
				  "Desync log "
			   << util::local_time_string("%c") << '\n';
	}

	auto write(const auto&... args) const -> void {
		if (m_file.is_open()) {
			(m_file << ... << args);
		} else {
			(std::clog << ... << args);
		}
	}

	auto writeln(const auto&... args) const -> void {
		write(args..., '\n');
	}

private:
	mutable std::ofstream m_file{};
};

} // namespace desync

#endif
