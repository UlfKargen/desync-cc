cmake_minimum_required(VERSION 3.12)

project("desync-test")

add_test(
    NAME test-basic1
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/desync-test.sh" "${CMAKE_CURRENT_SOURCE_DIR}/basic1"
)

add_test(
    NAME test-basic2
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/../scripts/desync-test.sh" "${CMAKE_CURRENT_SOURCE_DIR}/basic2"
)
