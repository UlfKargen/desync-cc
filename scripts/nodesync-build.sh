#!/bin/bash

# Make sure the project directory argument is provided.
if [[ $# -ne 1 ]]; then
    echo "Usage: nodesync-build <projectdir>"
    exit 2
fi

# Perform setup.
. $(dirname "$0")/desync-setup.sh $1

# Clean the project.
make -j $(nproc) clean

# Compile the project (run make) using the wrapper.
make -j $(nproc) || exit

# Done.
echo "Nodesync build done"
