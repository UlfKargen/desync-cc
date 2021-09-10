# desync-cc --- Automatic Disassembly Desynchronization Obfuscator

desync-cc is designed as a drop-in replacement for gcc, which applies disassembly desynchronization during compilation. 

The tool supports opaque predicates with both always-taken branches (where the fallthrough leads to desynchronization), and never-taken branches (with a fake jump into the middle of an instruction).

## Prerequisites

For the Python scripts to run, the `capstone` and `pyelftools` modules needs to be installed.
Can be installed with:

```sh
pip install capstone pyelftools
```

The C++ project requires the following packages to build and install:

-   CMake 3.12+
-   GCC 10+

Optional packages for development:

-   clang-tidy 11+
-   clang-format 11+

## Building

In the project directory, run the following commands:

```sh
mkdir build && cd build     # Create build directory and change to it.
cmake ..                    # Configure the project.
cmake --build .             # Compile the project.
```

The result is written to `build/desync-cc/bin`. The default configuration directory is copied to `build/desync-cc/share`.

## Building (Debug)

To build a debug version in a separate build tree, run the following:

```sh
mkdir build/Debug && cd build/Debug
cmake .. -D CMAKE_BUILD_TYPE=Debug
cmake --build .
```

## Building (with static analysis)

Follow the steps for building above, but add the option `-D DESYNC_USE_CLANG_TIDY:BOOL=ON` when running `cmake ..`

## Testing

Build the project as described above.
Then, in the build directory, run the following command:

```sh
ctest
```

## Installing

After building the project, in the build directory, run the following command with super user privileges:

```sh
cmake --install .
```

The `desync-cc` directory (containing`bin` and `share`) are by default installed to `/usr/local`.
If you wish to install to a different directory, add the option `-D CMAKE_INSTALL_PREFIX=<path>` when running `cmake ..`

## Running

To build a project using the obfuscator, simply use desync-cc instead of the default compiler. For example, for a makefile project, run

```sh
make clean
make CC=<install or build path>/desync-cc/bin/desync-cc
```

This will use the default configuration in `<install or build path>/desync-cc/share`. To use a custom configuration, set the `DESYNC_CONFIG_BASE_DIR` environment variable:

```sh
make clean
DESYNC_CONFIG_BASE_DIR=<path to config dir> make CC=<desync-cc path>
```

The following additional environment variable can be used to control the behavior of desync-cc:

```
DESYNC_LOG_FILE=<path>    # Print the predicate generator output to a file instead of stderr
DESYNC_JUNK_DEBUG=1       # Have the junk-byte generator print some debug info
DESYNC_JUNK_BENCMARK=1    # Have the junk-byte generator print performance statistics
```

## Configuration

The program accepts the following configuration strings in the config.cfg file:

* **log_file** File to write printed info to
* **verbose** If true will print for each of the print settings below, regardless of their value
* **print_config** Print the used configuration (including any randomized seeds)
* **print_assembly** Print the assembly file as they were first read by the program
* **print_cfg** Print the control flow graph
* **print_result** Print the modified assembly
* **print_stats** Print the number of predicates inserted and the total number of instructions in the original assembly
* **dry_run** If true the assembly will not be overwritten, leaving any processed files as they were originally
* **seed** Accepts "random" for a random seed or a numeric value. Affects the used distributions
* **junk_length_distribution** Type of distribution for deciding the length of junk-byte blocks to insert. Accepts "constant", "uniform" or "normal"
* **junk_length** Value for constant distribution of junk-bytes length
* **junk_length_min** Minimum value for uniform distribution of junk-bytes length
* **junk_length_max** Maximum value for uniform distribution of junk-bytes length
* **junk_length_mean** Mean value for normal distribution of junk-bytes length
* **junk_length_stddev** Standard deviation for normal distribution of junk-bytes length
* **interval_distribution** Type of distribution for deciding number of instructions to skip between each predicate. Accepts "constant", "uniform" or "normal"
* **interval** Value for constant instruction interval
* **interval_min** Minimum value for uniform distribution of instruction intervals
* **interval_max** Maximum value for uniform distribution of instruction intervals
* **interval_mean** Mean value for normal distribution of instruction intervals
* **interval_stddev** Standard deviation for normal distribution of instruction intervals
* **instruction_pattern** Regex to match what instructions to insert predicates before
* **predicate_file** File containing predicate templates
* **predicate_pattern** Regex to match what named predicates to use from the template file
* **predicate_distribution** Type of distribution for deciding what predicate to use. Accepts "uniform" or "discrete"
* **predicate_weight** Weight to use for discrete distribution of predicates. Can specify a weight for each predicate on each new line
* **use_spilling** If true, attempt to use register spilling instead of simply giving up when there are not enough free registers to apply a predicate.
* **always_taken_fraction** Fraction of predicates that should be always-taken branches (the rest being never-taken). Default: 0.5
* **debug_cfg** If true every free register will be filled with constant -1 before every instruction in the assembly. Distributions will be ignored so every run will give the same result.

