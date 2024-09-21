Usage
=====

.. toctree::
   :hidden:
   :maxdepth: 2
   :caption: Usage

   daemon
   bfcli
   nftables
   iptables


.. note::

    ``bpfilter`` is not (yet) packaged for any distribution. If you want to try it, you will have to build it from sources. See :doc:`../developers/build`.

``bpfilter`` is composed of two main parts that work together: the **front-ends** are used by the users to define the filtering rules and send them to the **daemon** that performs the heavy lifting of generating the BPF bytecode.

Before anything, you will have to run the daemon on your system, see :doc:`daemon` for more details.

Once the daemon is running, you need to choose which front-end's CLI to use:

- :doc:`bfcli`: ``bpfilter``-specific CLI, developed as part of the project. ``bfcli`` supports new ``bpfilter`` features before other CLIs as it's used for development. It allows for a more flexible rule definition: you can use a combination of filters and hooks that might not be possible with other CLIs. However, it doesn't support ``nftables`` or ``iptables`` rules format.
- :doc:`nftables`: requires a custom version of the ``nft`` binary with ``bpfilter`` support (see below), and support for new ``bpfilter`` features is usually a bit delayed.
- :doc:`iptables`: similar to ``nftables``, however ``iptables`` has been deprecated globally in favor of ``nftables``.
