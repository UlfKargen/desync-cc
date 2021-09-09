cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

project("desync-test")

add_test(
    NAME test-basic1
    COMMAND make check CC="${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}/desync-cc"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/basic1"
)

add_test(
    NAME test-basic2
    COMMAND make check CC="${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}/desync-cc"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/basic2"
)
