Build from sources
==================

This document describes the process to build ``bpfilter`` from sources. While ``bpfilter`` can be built on most systems, a recent (6.4+) Linux kernel is required with ``libbpf`` 1.2+ to run the ``bpfilter`` daemon. ``bpfilter`` officially supports Fedora 39+, and Ubuntu 24.04 LTS.

Required dependencies on Fedora and Ubuntu:

.. code-block:: shell

    # Fedora 39+
    sudo dnf install -y bison bpftool clang clang-tools-extra cmake doxygen flex g++ gcc git jq lcov libasan libbpf-devel libcmocka-devel libnl3-devel libubsan pkgconf python3-breathe python3-furo python3-linuxdoc python3-sphinx

    # Ubuntu
    sudo apt-get install -y bison clang clang-format clang-tidy cmake doxygen flex furo git jq lcov libpf-dev libcmocka-dev libnl-3-dev linux-tools-common python3-breathe python3-pip python3-sphinx pkgconf pip3 install linuxdoc

You can then use CMake to generate the build system:

.. code-block:: shell

    cmake -S $BPFILTER_SOURCE -B $BUILD_DIRECTORY

Apart from the usual CMake options (e.g. ``CMAKE_BUILD_TYPE``, ``CMAKE_INSTALL_PREFIX``, ...), subparts of the projects can be enabled or disabled during the configuration step using ``-DWITH_XXX``. More detail below.

Once CMake completes, you can build ``bpfilter``. The following Make targets are available:

* ``bpfilter``: build the ``bpfilter`` daemon.

* ``libbpfilter``: build a static and dynamic version of ``libbpfilter``.

* ``bfcli``: build ``bfcli`` command line interface.

* ``test``: build and run the unit tests.

* ``e2e``: build and run the end-to-end tests.

* ``doc``: generate ``bpfilter``'s documentation in ``$BUILD_DIRECTORY/doc/html``.

* ``coverage``: generate an HTML coverage report in ``$BUILD_DIRECTORY/doc/coverage``. This target will fail if ``make test`` hasn't been called before.

The build artefacts are located in ``$BUILD_DIRECTORY/output``.


**Benchmark**

The benchmarks require the following dependencies:

.. code-block:: shell

    # Fedora
    sudo dnf install -y google-benchmark-devel libgit2-devel

    # Ubuntu
    sudo apt-get install -y libbenchmark-dev libgit2-dev

Use ``-DWITH_BENCHMARK=on`` to enable the benchmark, build and run it using ``make benchmark``. See :ref:`tests-benchmark-label` for more information.


Building ``nftables`` and ``iptables``
--------------------------------------

``bpfilter``'s repository contains patches to add support for ``bpfilter`` to ``nftables`` and ``iptables``. You first need to install ``nftables``' and ``iptables``' build dependencies:

.. code-block:: shell

    # Fedora 39+
    sudo dnf install -y autoconf automake gmp-devel libtool libedit-devel libmnl-devel libnftnl-devel

    # Ubuntu 24.04
    sudo apt-get install -y autoconf bison flex libedit-dev libgmp-dev libmnl-dev libnftnl-dev libtool

Then, you can build both from ``bpfilter``'s build directory:

.. code-block:: shell

    make -C $BUILD_DIRECTORY nftables iptables

Once this command succeeds, ``nft`` (``nftables``'s command-line tool) and ``iptables`` are available in ``$BUILD_DIRECTORY/tools/install``.

With either ``nft`` or ``iptables``, you can now communicate directly with the ``bpfilter`` daemon instead of the kernel by using the ``--bpf`` flag. This allows your filtering rules to be translated into BPF programs by ``bpfilter``.
