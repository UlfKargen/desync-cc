#!/bin/bash

# Run GCC with our given subcommand wrapper for each subcommand.
${DESYNC_CC_COMMAND:-gcc} "$@" -wrapper $(dirname "$0")/desync-cc-subcommand.sh
