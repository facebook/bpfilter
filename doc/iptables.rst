``iptables``
============


The purpose of this document is to guide you through the process of using ``iptables`` as a front-end for ``bpfilter``. Although ``iptables`` does not officially support ``bpfilter``, it can still route its requests directly to the ``bpfilter`` daemon instead of the Linux kernel.

To facilitate the linking of ``iptables`` to ``bpfilter``, we recommend defining a directory for installing both. You can do this by using the following command:

.. code-block:: shell

    export INSTALL_DIRECTORY=$HOME/bpfilter_install


Build ``bpfilter``
------------------

There is no special flag to build ``bpfilter`` to be used with ``iptables``, however you need to override ``CMAKE_INSTALL_PREFIX`` with your custom install directory. To do this, navigate to the bpfilter source directory and run the following commands:

.. code-block:: shell

    # Configure CMake
    cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$INSTALL_DIRECTORY

    # Build and install bpfilter
    make -C build install

If you wish to build bpfilter in debug mode, simply add ``-DCMAKE_BUILD_TYPE=debug`` to the CMake command.

Upon successful installation, ``bpfilter`` will be available at ``$INSTALL_DIRECTORY/bin/bpfilter``. The ``libbpfilter.so`` file can be found in the ``lib64`` directory, which is adjacent to the ``bin`` directory.

Build ``iptables``
------------------

To use ``iptables`` with ``bpfilter``, you need to clone `this fork <https://github.com/qdeslandes/iptables.git>`_ and switch to the ``bpfilter`` branch. This version of ``iptables`` is identical to the one on your system, with the exception of the added ``--bpf`` option. This option allows ``iptables`` to communicate with ``bpfilter`` instead of the kernel.

To configure ``iptables``, navigate to its source directory and run the following commands:

.. code-block:: shell

    ./autogen.sh

    # Instruct the configure script where to find bpfilter and enable it.
    PKG_CONFIG_PATH=$INSTALL_DIRECTORY/share/pkgconfig ./configure \
        --prefix=$INSTALL_DIRECTORY \
        --disable-nftables \
        --enable-libipq \
        --enable-bpfilter

Upon completion of the configuration step, a summary of ``iptables``'s options will be displayed, including "bpfilter support".

You can then proceed to build and install your custom ``iptables`` with the following commands:

.. code-block:: shell

    make
    make install

Please note that running ``make install`` alone is not sufficient to properly build and install ``iptables``. You must first build it using ``make``, and then install it with ``make install``.

Usage
-----

With everything set up, you can now use ``iptables`` with ``bpfilter``. To initiate the daemon, use the following command:

.. code-block:: shell

    sudo $INSTALL_DIRECTORY/bin/bpfilter --transient --verbose

Given that ``bpfilter`` is a project under active development, it's recommended to run it in transient mode (``--transient``). This ensures that no cache or BPF programs remain on your system once the daemon is stopped. The ``--verbose`` option, while not mandatory, can be helpful in understanding the daemon's operations.

To use ``iptables`` and ensure that requests are routed to ``bpfilter``, use the ``--bpf`` switch:

.. code-block:: shell

    # List existing rules and counters
    sudo $INSTALL_DIRECTORY/sbin/iptables-legacy -L -v --bpf

    # Filter incoming ICMP packets
    sudo $INSTALL_DIRECTORY/sbin/iptables-legacy -I INPUT -p icmp -j DROP --bpf

The above example only filters incoming packets based on the protocol field. However, you're free to use the ``FORWARD`` or ``OUTPUT`` chains, and filter based on source or destination addresses, or ports.

If you encounter any issues or have any questions, don't hesitate to open an issue!
