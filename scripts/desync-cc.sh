#!/bin/bash

# Are we specifying the path, or are executables in PATH?
if [[ "$0" == *\/* ]]
then
  export DESYNC_BINDIR="$(dirname "$0")"
else
  export DESYNC_BINDIR="$(dirname "$(which "$0")")"
fi

export DESYNC_CONFIG_BASE_DIR="$(realpath "$DESYNC_BINDIR"/../..)"
export DESYNC_CONFIG_FILE="${DESYNC_CONFIG_FILE:-config.cfg}"

# Run GCC with our given subcommand wrapper for each subcommand.
${DESYNC_CC_COMMAND:-gcc} "$@" -wrapper "$DESYNC_BINDIR"/desync-cc-subcommand
