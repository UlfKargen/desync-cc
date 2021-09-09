# desync-cc

Automatic Disassembly Desynchronization Obfuscator.

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

## Running

To build a project using the obfuscator run:

```sh
DESYNC_CONFIG_FILE=config.cfg scripts/desync-build.sh <project_path>
```

To build a project and run tests after: (requires that the project implements test or check in the makefile)
```sh
DESYNC_CONFIG_FILE=config.cfg scripts/desync-test.sh <project_path>
```

## Configuration

The program accepts the following configuration strings in the config.cfg file:

* **log_file** File to write printed info to
* **verbose** If true will print for each of the print setting, regardless of their value
* **print_config** Prints the used configuration (including any randomized seeds)
* **print_assembly** Prints the assembly file as they were first read by the program
* **print_cfg** Prints the control flow graph
* **print_result** Prints the modified assembly
* **print_stats** Prints the number of predicates inserted and the total numer of instructions in the original assembly
* **dry_run** If true the assembly will not be overwritten, leaving any processed files as they were originally
* **seed** Accepts "random" for a random seed or a numeric value. Affects the used distributions
* **junk_length_distribution** Type of distribution for deciding junk-bytes to insert. Accepts "constant", "uniform" or "normal"
* **junk_length** Value for constant distribution of junk-bytes
* **junk_length_min** Minimum value for uniform distribution of junk-bytes
* **junk_length_max** Maximum value for uniform distribution of junk-bytes
* **junk_length_mean** Mean value for normal distribution of junk-bytes
* **junk_length_stddev** Standard deviation for normal distribution of junk-bytes
* **interval_distribution** Type of distribution for deciding number of instructions to skip between each predicate. Accepts "constant", "uniform" or "normal"
* **interval** Value for constant interval
* **interval_min** Minimum value for uniform distribution of intervals
* **interval_max** Maximum value for uniform distribution of intervals
* **interval_mean** Mean value for normal distribution of intervals
* **interval_stddev** Standard deviation for normal distribution of intervals
* **instruction_pattern** Regex to match what instructions to insert predicates before
* **predicate_file** File containing predicate templates
* **predicate_pattern** Regex to match what named predicates to use from the template file
* **predicate_distribution** Type of distribution for deciding what predicate to use. Accepts "uniform" or "discrete"
* **predicate_weight** Weight to use for discrete distribution of predicates. Can specify a weight for each predicate on each new line
* **debug_cfg** If true every free register will be filled with constant -1 before every instruction in the assembly. Distributions will be ignored so every run will give the same result.

