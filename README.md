# Desync

Automatic Disassembly Desynchronization Obfuscator.

## Prerequisites

Python:

capstone package needs to be installed.
Can be installed with 
```sh
pip install capstone
```

The C++ project requires the following packages to build and install:

-   CMake 3.12+
-   GCC 10+

Optional packages for development:

-   clang-tidy 11+
-   clang-format 11+

## Building (Debug)

In the project directory, run the following commands:

```sh
mkdir build && cd build     # Create build directory and change to it.
cmake ..                    # Configure the project.
cmake --build .             # Compile the project.
```

The result is written to `build/bin`.

## Building (Release)

Follow the steps for **Building (Debug)**, but instead of `cmake --build .`, use:

```sh
cmake --build . --config Release
```

## Building (with static analysis)

Follow the steps for **Building (Debug)** or **Building (Release)**, but instead of `cmake ..`, use:

```sh
cmake -D DESYNC_USE_CLANG_TIDY:BOOL=ON ..
```

## Testing

Build the project as described in **Building (Debug)** or **Building (Release)**.
Then, in the `build` directory, run the following command:

```sh
ctest
```

## Installing

Build the project as described in **Building (Release)**.
Then, in the `build` directory, run the following command with super user privileges:

```sh
cmake --install .
```

## running

To build a project using the obfuscator run:

```sh
DESYNC_CONFIG_FILE=config.cfg scripts/desync-build.sh project_path
```

To build a project and run tests after: (requres that the project implements test or check in the makefile)
```sh
DESYNC_CONFIG_FILE=config.cfg scripts/desync-test.sh project_path
```

