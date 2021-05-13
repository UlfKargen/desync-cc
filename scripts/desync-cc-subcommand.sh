#!/bin/bash

# Make sure at least the command argument is provided.
if [[ $# -lt 1 ]]; then
    echo "Usage: desync-cc-subcommand <command> [args...]"
    exit 2
fi

# Get the command filename.
COMMAND_NAME=$(basename "$1")

# Check which kind of command should be run.
if [[ "$COMMAND_NAME" = "cc1" ]]; then
    # Run the compiler as normal.

    "$@" || exit # Run the compiler.
elif [[ "$COMMAND_NAME" = "as" ]]; then
    # Run our tool with the assembly filenames given to the assembler command before running the assembler.

    # Extract the assembly filenames from the assembler arguments.
    ASSEMBLY_FILES=()
    for ARG in "${@:2}"; do
        if [[ "${ARG: -2}" = ".s" || "${ARG: -2}" = ".S" || "${ARG: -3}" = ".sx" ]]; then
            ASSEMBLY_FILES+=("$ARG")
        fi
    done

    # Run our tool with the -p flag.
    ${DESYNC_COMMAND:-desync} -p "${ASSEMBLY_FILES[@]}" # Don't exit on failure.

    "$@" || exit # Run the assembler.
elif [[ "$COMMAND_NAME" = "collect2" || "$COMMAND_NAME" = "ld" ]]; then
    # Run our tool with the output filename given to the linker command after running the linker.

    # Extract the output filename from the linker arguments.
    OUTPUT_FILE="a.out"
    OUTPUT_OPTION_EXPECTED=0
    for ARG in "${@:2}"; do
        if [[ $OUTPUT_OPTION_EXPECTED -ne 0 ]]; then
            OUTPUT_FILE="$ARG"
            break
        elif [[ "$ARG" = "-o" ]]; then
            OUTPUT_OPTION_EXPECTED=1
        else
            OUTPUT_OPTION_EXPECTED=0
        fi
    done

    "$@" || exit # Run the linker.

    # Run our tool with the -j flag.
    ${DESYNC_COMMAND:-desync} -j "$OUTPUT_FILE" # Don't exit on failure.
else
    # Run any other commands as normal.

    "$@" || exit # Run the command.
fi
