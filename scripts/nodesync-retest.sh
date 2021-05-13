#!/bin/bash

# Make sure the project directory argument is provided.
if [[ $# -ne 1 ]]; then
    echo "Usage: nodesync-retest <projectdir>"
    exit 2
fi

# Perform setup.
. $(dirname "$0")/desync-setup.sh $1

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
echo "Nodesync retest done"
