#!/bin/bash

# Make sure the project directory argument is provided.
if [[ $# -ne 1 ]]; then
    echo "Usage: nodesync-test <projectdir>"
    exit 2
fi

# Build the project.
. $(dirname "$0")/nodesync-build.sh $1

# Test the project (run make check/test).
make -q check
if [[ $? != 2 ]]; then
    make -j $(nproc) "SUBDIRS=." check
else
    make -q test
    if [[ $? != 2 ]]; then
        make -j $(nproc) test
    fi
fi

# Done.
echo "Nodesync test done"
