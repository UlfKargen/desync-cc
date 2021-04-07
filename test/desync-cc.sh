#!/bin/bash

# Run GCC with our given subcommand wrapper for each subcommand.
gcc "$@" -wrapper "$DESYNC_CC_SUB_WRAPPER"