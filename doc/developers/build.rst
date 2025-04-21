Build from sources
==================

This document describes the process to build ``bpfilter`` from sources. While ``bpfilter`` can be built on most systems, a recent (6.6+) Linux kernel is required with ``libbpf`` 1.2+ to run the ``bpfilter`` daemon. ``bpfilter`` officially supports Fedora 40+, CentOS Stream 9+, and Ubuntu 24.04+.

If you want to perform a full build of ``bpfilter`` (including all test tests, code check, benchmarks, and documentation), the following dependencies are required:

.. code-block:: shell

    # Fedora 40+
    sudo dnf -y install \
        autoconf \
        automake \
        gawk \
        bpftool \
        bison \
        clang-tools-extra \
        cmake \
        doxygen \
        flex \
        gcc \
        gcc-c++ \
        git-core \
        google-benchmark-devel \
        iproute \
        iputils \
        jq \
        lcov \
        libbpf-devel \
        libcmocka-devel \
        libgit2-devel \
        libnl3-devel \
        libtool \
        procps-ng \
        python3-breathe \
        python3-dateutil \
        python3-furo \
        python3-GitPython \
        python3-linuxdoc \
        python3-scapy \
        python3-sphinx

    # Ubuntu 24.04+
    sudo apt-get install -y \
        autoconf \
        automake \
        bison \
        clang-tidy \
        clang-format \
        cmake \
        doxygen \
        flex \
        furo \
        g++ \
        git \
        iproute2 \
        iputils-ping \
        lcov \
        libbenchmark-dev \
        libbpf-dev \
        libc-dev \
        libcmocka-dev \
        libgit2-dev \
        libnl-3-dev \
        libtool \
        linux-tools-common \
        make \
        pkgconf \
        procps \
        python3-breathe \
        python3-dateutil \
        python3-git \
        python3-pip \
        python3-scapy \
        python3-sphinx

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
