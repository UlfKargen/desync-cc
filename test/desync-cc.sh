#!/bin/bash

# Run GCC with our given subcommand wrapper for each subcommand.
$DESYNC_COMPILER_COMMAND "$@" -wrapper "$DESYNC_CC_SUB_WRAPPER"