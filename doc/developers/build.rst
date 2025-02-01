Build from sources
==================

This document describes the process to build ``bpfilter`` from sources. While ``bpfilter`` can be built on most systems, a recent (6.4+) Linux kernel is required with ``libbpf`` 1.2+ to run the ``bpfilter`` daemon. ``bpfilter`` officially supports Fedora 39+, and Ubuntu 24.04+.

If you want to perform a full build of ``bpfilter``, the following dependencies are required:

.. code-block:: shell

    # Fedora 39+
    sudo dnf install -y bison bpftool clang-tools-extra cmake doxygen flex g++ gcc git google-benchmark-devel jq lcov libasan libbpf-devel libcmocka-devel libgit2-devel libnl3-devel libubsan pkgconf python3-breathe python3-furo python3-linuxdoc python3-sphinx

    # Ubuntu 24.04+
    sudo apt-get install -y bison clang-format clang-tidy cmake doxygen flex furo git jq lcov libpf-dev libcmocka-dev libbenchmark-dev libgit2-dev libnl-3-dev linux-tools-common python3-breathe python3-pip python3-sphinx pkgconf pip3 install linuxdoc

You can then use CMake to generate the build system:

.. code-block:: shell

    cmake -S $BPFILTER_SOURCE -B $BUILD_DIRECTORY

The usual CMake options are allowed (e.g. ``CMAKE_BUILD_TYPE``, ``CMAKE_INSTALL_PREFIX``...). The build configuration is modular, so you're free to enable/disable some parts of the projects according to your needs:

- ``-DNO_DOCS``: disable the documentation, including the coverage and benchmarks report.
- ``-DNO_TESTS``: disable unit tests, end-to-end tests, and integration tests.
- ``-DNO_CHECKS``: disable style check and static analyzer.
- ``-DNO_BENCHMARKS``: disable benchmarks.

A full configuration (without any part disabled) will provide the following targets:

- ``core``, ``bpfilter``, ``libbpfilter``, ``bfcli``: the ``bpfilter`` binaries.
- ``test``, ``e2e``, ``integration``: the test suits. See :doc:`tests` for more information.
- ``check``: run ``clang-tidy`` and ``clang-format`` against the source files.
- ``benchmarks``: run the benchmarks on ``bpfilter``.

The build artifacts are located in ``$BUILD_DIRECTORY/output``.
