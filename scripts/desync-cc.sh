#!/bin/bash

# Are we specifying the path, or are executables in PATH?
if [[ "$0" == *\/* ]]
then
  export DESYNC_BINDIR="$(dirname "$0")"
else
  export DESYNC_BINDIR="$(dirname "$(which "$0")")"
fi

export DESYNC_CONFIG_BASE_DIR="$(realpath "$DESYNC_BINDIR"/../../..)"
export DESYNC_CONFIG_FILE="${DESYNC_CONFIG_FILE:-config.cfg}"

# Run GCC with our given subcommand wrapper for each subcommand.
#   -fcf-protection=none is needed because Keystone currently lacks support for Intel CET instructions
#   -mno-red-zone is required when spilling registers to the stack in opaque predicates
${DESYNC_CC_COMMAND:-gcc} "$@" -fcf-protection=none -mno-red-zone -wrapper "$DESYNC_BINDIR"/desync-cc-subcommand
