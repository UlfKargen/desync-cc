cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

set(CMAKE_INSTALL_BINDIR "desync-cc/bin")
set(CMAKE_INSTALL_DATADIR "desync-cc/share")

project(
	"desync-cc"
	VERSION 1.0.0
	DESCRIPTION "Automatic Disassembly Desynchronization Obfuscator"
	LANGUAGES C CXX
)

set(DESYNC_USE_CLANG_TIDY OFF CACHE BOOL "Enable static analysis using clang-tidy.")

add_subdirectory("thirdparty/keystone" EXCLUDE_FROM_ALL)
add_subdirectory("thirdparty/capstone" EXCLUDE_FROM_ALL)
remove_definitions(-Werror)
add_subdirectory("thirdparty/smhasher/src" EXCLUDE_FROM_ALL)
add_definitions(-Werror)

add_executable(
	desync-pred
	"src/pred/assembler.hpp"
	"src/pred/assembly_parser.hpp"
	"src/pred/configuration_parser.hpp"
	"src/pred/configuration.hpp"
	"src/pred/control_flow_graph.hpp"
	"src/pred/desynchronizer.hpp"
	"src/pred/disassembler.hpp"
	"src/pred/logger.hpp"
	"src/pred/main.cpp"
	"src/pred/options.hpp"
	"src/pred/predicate_parser.hpp"
	"src/util/file.hpp"
	"src/util/string.hpp"
	"src/util/time.hpp"
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
		"thirdparty/smhasher/src"
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
		SMHasherSupport
)

if(DESYNC_USE_CLANG_TIDY)
	find_program(CLANG_TIDY NAMES clang-tidy REQUIRED)
	set_property(
		TARGET desync-pred
		PROPERTY CXX_CLANG_TIDY "${CLANG_TIDY}" "-header-filter=src/"
	)
endif()

include(GNUInstallDirs)

set_target_properties(
	desync-pred
	PROPERTIES
		RUNTIME_OUTPUT_DIRECTORY "${CMAKE_INSTALL_BINDIR}"
)

add_custom_target(
	copy-desync-cc-file ALL
	COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/scripts/desync-cc.sh" "${CMAKE_INSTALL_BINDIR}/desync-cc"
	COMMENT "Copying desync-cc.sh to ${CMAKE_INSTALL_BINDIR}/desync-cc"
	DEPENDS desync-pred
)

add_custom_target(
	copy-desync-cc-subcommand-file ALL
	COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/scripts/desync-cc-subcommand.sh" "${CMAKE_INSTALL_BINDIR}/desync-cc-subcommand"
	COMMENT "Copying desync-cc-subcommand.sh to ${CMAKE_INSTALL_BINDIR}/desync-cc-subcommand"
	DEPENDS desync-pred
)

add_custom_target(
	copy-desync-junk-file ALL
	COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/src/junk/desync_jb_generator.py" "${CMAKE_INSTALL_BINDIR}/desync-junk"
	COMMENT "Copying desync_jb_generator.py to ${CMAKE_INSTALL_BINDIR}/desync-junk"
	DEPENDS desync-pred
)

add_custom_target(
	copy-config-dir ALL
	COMMAND ${CMAKE_COMMAND} -E copy_directory "${CMAKE_CURRENT_SOURCE_DIR}/config" "${CMAKE_INSTALL_DATADIR}"
	COMMENT "Copying config directory to ${CMAKE_INSTALL_DATADIR}"
	DEPENDS desync-pred
)

install(
	TARGETS desync-pred
	RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(
	FILES
		"${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}/desync-cc"
		"${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}/desync-cc-subcommand"
        "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}/desync-junk"
   PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
	DESTINATION "${CMAKE_INSTALL_BINDIR}"
)

install(
	DIRECTORY
		"${CMAKE_CURRENT_SOURCE_DIR}/config/"
	DESTINATION "${CMAKE_INSTALL_DATADIR}"
)

include(CTest)
if(BUILD_TESTING)
	add_subdirectory("test")
endif()
