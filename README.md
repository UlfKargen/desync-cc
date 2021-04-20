# Desync

Automatic Disassembly Desynchronization Obfuscator.

## Prerequisites

The project requires the following packages to build and install:

-   CMake 3.12+
-   GCC 10+
-   clang-tidy 11+

Optional packages for development:

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
