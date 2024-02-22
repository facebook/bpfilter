Build from sources
==================

This document describes the process to build ``bpfilter`` from sources. While `bpfilter` can be built on most systems, a recent (6.4+) Linux kernel is required with ``libbpf`` 1.2+ to run the ``bpfilter`` daemon.

``bpfilter`` development is mostly done using Fedora (38 and 39), but Ubuntu is also officially supported.

Required dependencies on Fedora and Ubuntu:

.. code-block:: shell

    # Fedora 38 / 39
    clang-tools-extra cmake libcmocka-devel doxygen lcov libasan libbpf-devel libnl3-devel libubsan python3-breathe python3-furo python3-sphinx pkgconf

    # Ubuntu 23.10
    clang-format clang-tidy cmake doxygen furo lcov libbpf-dev libcmocka-dev libnl-3-dev python3-breathe python3-pip python3-sphinx pkgconf

You can then use CMake to generate the build system:

.. code-block:: shell

    cmake -S $BPFILTER_SOURCE -B $BUILD_DIRECTORY

There is no ``bpfilter``-specific CMake option, but you can use the CMake-provided ones (e.g. ``CMAKE_BUILD_TYPE``, ``CMAKE_INSTALL_PREFIX``, ...).

Once CMake completes, you can build ``bpfilter``. The following Make targets are available:

* ``bpfilter``: build ``bpfilter`` daemon.

* ``libbpfilter``: build a static and dynamic version of ``libbpfilter``.

* ``test``: build and run unit tests.

* ``doc``: generate ``bpfilter``'s documentation in ``$BUILD_DIRECTORY/doc/html``.

* ``coverage``: generate an HTML coverage report in ``$BUILD_DIRECTORY/doc/coverage``. This target will fail if ``make test`` hasn't been called before.

``bpfilter`` daemon will be in ``$BUILD/src/bpfilter``, and ``libbpfilter.so`` will be in ``$BUILD/lib/libbpfilter.so``.
