cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project(
	"desync"
	VERSION 1.0.0
	DESCRIPTION "Automatic Disassembly Desynchronization Obfuscator"
	LANGUAGES C CXX
)

add_subdirectory("thirdparty/keystone")
add_subdirectory("thirdparty/capstone")

find_program(CLANG_TIDY NAMES clang-tidy-7 clang-tidy-6.0 clang-tidy-5.0 clang-tidy-4.0 clang-tidy REQUIRED)

add_executable(
	desync-pred
	"src/pred/assembler.hpp"
	"src/pred/assembly_parser.hpp"
	"src/pred/control_flow_graph.hpp"
	"src/pred/desynchronizer.hpp"
	"src/pred/disassembler.hpp"
	"src/pred/main.cpp"
	"src/util/file.hpp"
	"src/util/print.hpp"
	"src/util/string.hpp"
)

target_include_directories(
	desync-pred
	PRIVATE
		"src"
)

target_include_directories(
	desync-pred SYSTEM
	PRIVATE
		"thirdparty/keystone/include"
		"thirdparty/capstone/include"
)

target_compile_features(
	desync-pred
	PRIVATE
		cxx_std_20
)

target_compile_options(
	desync-pred
	PRIVATE
		$<$<CXX_COMPILER_ID:GNU>:
			-W -Wall -Wextra -Wpedantic -Werror
			$<$<CONFIG:Debug>:-g>
			$<$<NOT:$<CONFIG:Debug>>:-O3>
		>
		$<$<CXX_COMPILER_ID:Clang>:
			-W -Wall -Wextra -Wpedantic -Werror
			$<$<CONFIG:Debug>:-g>
			$<$<NOT:$<CONFIG:Debug>>:-O3>
		>
		$<$<CXX_COMPILER_ID:MSVC>:
			/W3 /WX /wd4648 /permissive- /utf-8
			$<$<CONFIG:Debug>:/Od>
			$<$<NOT:$<CONFIG:Debug>>:/Ot>
		>
)

target_link_libraries(
	desync-pred
	PRIVATE
		keystone
		capstone-static
)

set_property(
	TARGET desync-pred
	PROPERTY CXX_CLANG_TIDY "${CLANG_TIDY}" "-header-filter=src/"
)

include(GNUInstallDirs)

set_target_properties(
	desync-pred
	PROPERTIES
		ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_INSTALL_LIBDIR}"
		LIBRARY_OUTPUT_DIRECTORY "${CMAKE_INSTALL_LIBDIR}"
		RUNTIME_OUTPUT_DIRECTORY "${CMAKE_INSTALL_BINDIR}"
)

add_custom_target(
	symlink-desync-file ALL
	COMMAND ${CMAKE_COMMAND} -E create_symlink "${CMAKE_CURRENT_SOURCE_DIR}/desync/desync" "${CMAKE_INSTALL_BINDIR}/desync"
	COMMENT "Creating symlink to desync file at ${CMAKE_INSTALL_BINDIR}/desync"
	DEPENDS desync-pred
)

add_custom_target(
	symlink-desync-junk-file ALL
	COMMAND ${CMAKE_COMMAND} -E create_symlink "${CMAKE_CURRENT_SOURCE_DIR}/desync/desync-junk" "${CMAKE_INSTALL_BINDIR}/desync-junk"
	COMMENT "Creating symlink to desync-junk file at ${CMAKE_INSTALL_BINDIR}/desync-junk"
	DEPENDS desync-pred
)

install(
	TARGETS desync-pred
	ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(
	FILES
		"${CMAKE_CURRENT_SOURCE_DIR}/desync/desync"
		"${CMAKE_CURRENT_SOURCE_DIR}/desync/desync-junk"
	DESTINATION "${CMAKE_INSTALL_BINDIR}"
)