#!/bin/bash

# Make sure the project directory argument is provided.
if [[ $# -ne 1 ]]; then
    echo "Usage: desync-test <projectdir>"
    exit 2
fi

# Save base directory and project directory.
BASE_DIR=$(pwd)
PROJECT_DIR=$1

# Change to given project directory.
cd $PROJECT_DIR || exit
echo "Running desync test: $(pwd)"

# Get path to GCC wrapper.
CC_WRAPPER=$BASE_DIR/test/desync-cc.sh
echo "Using gcc wrapper: $CC_WRAPPER"

# Export path to GCC subcommand wrapper.
export DESYNC_CC_SUB_WRAPPER=$BASE_DIR/test/desync-cc-subcommand.sh
echo "Using subcommand wrapper: $DESYNC_CC_SUB_WRAPPER"

# Export path to desync executable.
export DESYNC_TOOL=$BASE_DIR/build/bin/desync
echo "Using desync path: $DESYNC_CC_SUB_WRAPPER"

# Clean the project.
make clean || exit

# Compile the project (run make) using the wrapper.
make -j $(nproc) "CC=$CC_WRAPPER" || exit

# Test the project (run make check/test) using the wrapper.
make -j $(nproc) "CC=$CC_WRAPPER" check || make -j $(nproc) "CC=$CC_WRAPPER" test || exit

# Done.
echo "Desync test done"