#!/bin/bash

# Make sure the project directory argument is provided.
if [[ $# -ne 1 ]]; then
    echo "Usage: desync-test <projectdir>"
    exit 2
fi

# Build the project.
. $(dirname "$0")/desync-build.sh $1

# Test the project (run make check/test) using the CC_WRAPPER defined by desync-build.sh.
make -q check
if [[ $? != 2 ]]; then
    make -j $(nproc) "CC=$CC_WRAPPER" check
else
    make -q test
    if [[ $? != 2 ]]; then
        make -j $(nproc) "CC=$CC_WRAPPER" test
    fi
fi

# Done.
echo "Desync test done"
