Build from sources
==================

This document describes the process to build ``bpfilter`` from sources. While `bpfilter` can be built on most systems, a recent (6.4+) Linux kernel is required with ``libbpf`` 1.2+ to run the ``bpfilter`` daemon.

``bpfilter`` development is mostly done using Fedora (38 and 39), but Ubuntu (23.10+) is also officially supported. Other distributions may work as long as Linux 6.4+ is available, but they are not officially supported at the moment.

Required dependencies on Fedora and Ubuntu:

.. code-block:: shell

    # Fedora 40
    bpftool clang clang-tools-extra cmake libcmocka-devel doxygen lcov libasan libbpf-devel libnl3-devel libubsan python3-breathe python3-furo python3-sphinx pkgconf

    # Ubuntu 24.04
    clang clang-format clang-tidy cmake doxygen furo lcov libbpf-dev libcmocka-dev libnl-3-dev linux-tools-common pkgconf python3-breathe python3-sphinx

You can then use CMake to generate the build system:

.. code-block:: shell

    cmake -S $BPFILTER_SOURCE -B $BUILD_DIRECTORY

There is no ``bpfilter``-specific CMake option, but you can use the CMake-provided ones (e.g. ``CMAKE_BUILD_TYPE``, ``CMAKE_INSTALL_PREFIX``, ...), including ``-G`` to override the default build system generator (``ninja`` and ``make`` are supported).

Once CMake completes, you can build ``bpfilter``. The following Make targets are available:

* ``bpfilter``: build ``bpfilter`` daemon.

* ``libbpfilter``: build a static and dynamic version of ``libbpfilter``.

* ``test``: build and run unit tests.

* ``doc``: generate ``bpfilter``'s documentation in ``$BUILD_DIRECTORY/doc/html``.

* ``coverage``: generate an HTML coverage report in ``$BUILD_DIRECTORY/doc/coverage``. This target will fail if ``make test`` hasn't been called before.

``bpfilter`` daemon will be in ``$BUILD/src/bpfilter``, and ``libbpfilter.so`` will be in ``$BUILD/lib/libbpfilter.so``.


Building ``nftables`` and ``iptables``
--------------------------------------

``bpfilter``'s repository contains patches to add support for ``bpfilter`` to ``nftables`` and ``iptables``. You first need to install ``nftables``' and ``iptables``' build dependencies:

.. code-block:: shell

    # Fedora 40
    autoconf automake bison flex gmp-devel libedit-devel libmnl-devel libnftnl-devel libtool

    # Ubuntu 24.04
    autoconf bison flex libedit-dev libgmp-dev libmnl-dev libnftnl-dev libtool

Then, you can build both from ``bpfilter``'s build directory:

.. code-block:: shell

    make -C $BUILD_DIRECTORY nftables iptables

Once this command succeeds, ``nft`` (``nftables``'s command-line tool) and ``iptables`` are available in ``$BUILD_DIRECTORY/tools/install``.

With either ``nft`` or ``iptables``, you can now communicate directly with the ``bpfilter`` daemon instead of the kernel by using the ``--bpf`` flag. This allows your filtering rules to be translated into BPF programs by ``bpfilter``.
