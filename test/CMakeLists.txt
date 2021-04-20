cmake_minimum_required(VERSION 3.12)

project("desync-test")

add_test(
    NAME test-basic
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/desync-test.sh" "${CMAKE_CURRENT_SOURCE_DIR}/basic"
)