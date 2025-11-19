# Instructions for Claude

## Communication

### Tone requirements
- Conversational: target kernel experts, not beginners
- Factual: no drama, just technical observations
- Questions: frame as questions about the code, not accusations
- Terminology: call issues "regressions" not "bugs" or "critical"

### Question phrasing
- ❌ "Did you corrupt memory here?"
- ✅ "Can this corrupt memory?"
- ❌ "Does this loop have a bounds checking issue?"
- ✅ "Does this code overflow xyz[]?"

### Formatting Rules

- Reference functions by name, not line numbers
- Use call chains for clarity: funcA()→funcB()

## Building and testing

Building and testing bpfilter should only be performed using instructions detailed in this section:

- Configure CMake: `cmake -S $SOURCE_DIR -B $BUILD_DIR -DCMAKE_BUILD_TYPE=$TYPE -DWITH_COVERAGE=$COVERAGE`, with:
    - `SOURCE_DIR`: the base directory of the repository
    - `BUILD_DIR`: usually `SOURCE_DIR/build`, unless specific otherwise
    - `TYPE`: `debug` or `release`, use `debug` during development
    - `COVERAGE`: 0 or 1, use `1` when `TYPE=debug`
- Build the project: `make -C $BUILD_DIR`
- Run the tests: `make -C $BUILD_DIR test`, the `test_bin` target should be build prior
- Run a specific test suite: `ctest --test-dir $BUILD_DIR --output-on-failure -L $SUITE`, with `SUITE` either `unit`, `integration, `check`, or `e2e`
- Run a specific test: `ctest --test-dir $BUILD_DIR --output-on-failure -R $TEST`, with `TEST` the path to the test file from `tests/` (excluded) and `/` replaced with `.`
- Collect the coverage results: `make -C build coverage`, the tests should be run prior
- Generate the documentation (includes the coverage report): `make -C build doc`, the coverage results should be collected prior

## Reviewing changes

When reviewing changes:
- Use git diff to identify changes
- Manually find function definitions and relationships with grep and other tools
- Document any missing context that affects review quality
- Ensure the changes build, and tests succeed, no build error or warning should be introduced, no test failure either
- New code lines should be covered by unit tests (at least 70% of new lines, and 100% of new functions)
- Ensure changes matches the commit message
- Focus on what should be improved, do not explain what is good