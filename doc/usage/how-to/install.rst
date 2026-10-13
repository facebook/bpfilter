Install bpfilter
================

bpfilter is packaged for Fedora 40+ and EPEL 9+, and supports Fedora 40+, CentOS Stream 9+, and Ubuntu 24.04+.

Install the package
-------------------

On Fedora, or on a system with EPEL enabled:

.. code-block:: shell

    $ sudo dnf install -y bpfilter
    Updating and loading repositories:
    [...]
    Repositories loaded.
    Package   Arch   Version        Repository      Size
    Installing:
     bpfilter x86_64 0:0.6.0-5.fc44 fedora     583.9 KiB
    Installing dependencies:
     libbpf   x86_64 2:1.6.3-2.fc44 updates    442.7 KiB

    Transaction Summary:
     Installing:         2 packages
    [...]
    Complete!

You can check that ``bfcli`` is available with:

.. code-block:: shell

    $ bfcli --version
    bfcli version 0.6.0, libbpfilter version 0.6.0
    $ bfcli --help
    Usage: bfcli [OPTION...] OBJECT ACTION
    Configure bpfilter chains and filtering rules.
    [...]

Build from sources
------------------

If you use a different distribution, you can still build and use bpfilter if you satisfy the requirements, see the :doc:`developer documentation <../../developers/build>`. Once built, ``bfcli`` will be located at ``$BUILD_DIRECTORY/output/sbin/bfcli``.

You can either use this path in place of ``bfcli``, or install bpfilter on your system:

.. code-block:: shell

    $ sudo cmake --install "$BUILD_DIRECTORY"
    -- Install configuration: "release"
    -- Installing: /usr/local/lib64/libbpfilter.so.0.7.0
    -- Installing: /usr/local/lib64/libbpfilter.so.0
    -- Installing: /usr/local/lib64/libbpfilter.so
    -- Installing: /usr/local/include/bpfilter
    [...]
    -- Installing: /usr/local/lib64/pkgconfig/bpfilter.pc
    -- Installing: /usr/local/sbin/bfcli
    -- Set non-toolchain portion of runtime path of "/usr/local/sbin/bfcli" to ""

Now that bpfilter is installed, you can create :doc:`your first filtering chain <../tutorials/first-chain>`.
