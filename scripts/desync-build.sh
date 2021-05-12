#!/bin/bash

# Make sure the project directory argument is provided.
if [[ $# -ne 1 ]]; then
    echo "Usage: desync-build <projectdir>"
    exit 2
fi

# Export current directory as base directory.
export DESYNC_CONFIG_BASE_DIR="$(pwd)"

# Save script directory and project directory.
SCRIPTS_DIR=$(realpath $(dirname "$0"))
PROJECT_DIR="$1"

# Change to given project directory.
cd "$PROJECT_DIR" || exit
echo "Running desync build: $(pwd)"

# Export path to configuration filename.
export DESYNC_CONFIG_FILE="${DESYNC_CONFIG_FILE:-config.cfg}"
echo "Using config file: $DESYNC_CONFIG_FILE"

# Export path to desync executable.
export DESYNC_COMMAND="${DESYNC_COMMAND:-$SCRIPTS_DIR/../build/bin/desync}"
echo "Using desync: $DESYNC_COMMAND"

# Define path to GCC wrapper.
CC_WRAPPER="$SCRIPTS_DIR/desync-cc.sh"

# Clean the project.
make -j $(nproc) "CC=$CC_WRAPPER" clean

# Compile the project (run make) using the wrapper.
make -j $(nproc) "CC=$CC_WRAPPER" || exit

# Done.
echo "Desync build done"
