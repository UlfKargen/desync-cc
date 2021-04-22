#!/bin/bash

# Make sure the project directory argument is provided.
if [[ $# -ne 1 ]]; then
    echo "Usage: desync-test <projectdir>"
    exit 2
fi

# Save base directory and project directory.
TEST_DIR=$(realpath $(dirname "$0"))
PROJECT_DIR=$1

# Change to given project directory.
cd $PROJECT_DIR || exit
echo "Running desync test: $(pwd)"

# Get path to GCC wrapper.
CC_WRAPPER=$TEST_DIR/desync-cc.sh
echo "Using gcc wrapper: $CC_WRAPPER"

# Export path to GCC subcommand wrapper.
export DESYNC_CC_SUB_WRAPPER=$TEST_DIR/desync-cc-subcommand.sh
echo "Using subcommand wrapper: $DESYNC_CC_SUB_WRAPPER"

# Export path to desync executable.
export DESYNC_TOOL=$TEST_DIR/../build/bin/desync
echo "Using desync path: $DESYNC_CC_SUB_WRAPPER"

# Clean the project.
make clean

# Compile the project (run make) using the wrapper.
make -j $(nproc) "CC=$CC_WRAPPER" || exit

# Test the project (run make check/test) using the wrapper.
make -j $(nproc) "CC=$CC_WRAPPER" check || make -j $(nproc) "CC=$CC_WRAPPER" test || exit

# Done.
echo "Desync test done"