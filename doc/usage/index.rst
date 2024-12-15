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

Example Usage
-------------

.. note::

	This is only to be used as an example and a more interactive test to familiarize you with ``bpfilter``, more in-depth information can be found throughout the docs.

Initialize ``bpfilter`` daemon
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

	> cd path/to/bpfilter/
	> sudo ./build/output/bpfilter -t -v debug --no-iptables


Load ``bfcli`` filter(s)
~~~~~~~~~~~~~~~~~~~~~~~~

While the ``bpfilter`` daemon runs, now we will open up a separate window to use ``bfcli``

.. code-block:: bash

	> cd path/to/bpfilter/
	> sudo ./build/output/bfcli --str "chain BF_HOOK_NF_LOCAL_IN policy ACCEPT rule ip4.saddr in {192.168.1.1} ACCEPT"

The above program is just to make sure that ``bfcli`` is able to communicate with ``bpfilter``, when you run the commands you should see output from ``bpfilter`` registering that a filter has been loaded.

You can check by running:

.. code-block:: bash

	> ping 192.168.1.1
	... [pinging] ...
	--- 192.168.1.1 ping statistics ---
	4 packets transmitted, 4 packets received, 0.0% packet loss

.. note::
	If you run into errors here there may be problems with your system worth diagnosing before continuing

Now let's try changing the filter from ``{192.168.1.1} ACCEPT`` to ``DENY``

.. code-block:: bash

	sudo ./build/output/bfcli --str "chain BF_HOOK_NF_LOCAL_IN policy ACCEPT rule ip4.saddr in {192.168.1.1} DROP"

You should now observe a change in the behavior of ``ping``

.. code-block:: bash

	> ping 192.168.1.1
	... [attempting to ping] ...
	--- 192.168.1.1 ping statistics ---
	4 packets transmitted, 0 packets received, 100.0% packet loss

Congratulations you have now officially used ``bpfilter`` to systematically filter out your own packets. For documentation for more complex filtering options please check under the ``DEVELOPERS`` links and good luck!
