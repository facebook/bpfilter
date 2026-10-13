Update a blocklist
==================

If you only want to add or remove elements from a named set, you don't need to replace the whole chain: use ``bfcli chain update-set``. The update is atomic, and the chain's counters are preserved.

From here on, we assume you created the ``block_sources`` chain and its ``blocklist`` set from :doc:`block-addresses`.

Add or remove addresses
-----------------------

Add two addresses to the blocklist:

.. code-block:: shell

    $ sudo bfcli chain update-set --name block_sources --set-name blocklist \
        --add 192.0.2.3 --add 192.0.2.4
    info   : updated set 'blocklist' in chain 'block_sources'

Remove an address:

.. code-block:: shell

    $ sudo bfcli chain update-set --name block_sources --set-name blocklist \
        --remove 192.0.2.1
    info   : updated set 'blocklist' in chain 'block_sources'

You can also add and remove addresses with a single command:

.. code-block:: shell

    $ sudo bfcli chain update-set --name block_sources --set-name blocklist \
        --add 192.0.2.5 --remove 192.0.2.2
    info   : updated set 'blocklist' in chain 'block_sources'

Check the content of the set
----------------------------

.. code-block:: shell

    $ sudo bfcli chain get --name block_sources
    chain block_sources BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
        counters policy 0 packets 0 bytes; error 0 packets 0 bytes
        set blocklist (ip4.saddr) in {
            192.0.2.3
            192.0.2.4
            192.0.2.5
        }
        rule
            (ip4.saddr) in blocklist
            counters 0 packets 0 bytes
            DROP

The set should contain the addresses you expect. If you want to be sure, send some traffic from an address you added, and from one you removed.

If your set is large, printing every element makes the output unreadable. Use ``--no-set-content`` to only print the number of elements it contains:

.. code-block:: shell

    $ sudo bfcli chain get --name block_sources --no-set-content
    chain block_sources BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
        counters policy 0 packets 0 bytes; error 0 packets 0 bytes
        set blocklist (ip4.saddr) in { /* 3 elements, content elided */ }
        rule
            (ip4.saddr) in blocklist
            counters 0 packets 0 bytes
            DROP

A set can grow as much as needed through ``update-set``. If you know how many elements it will contain, you can reserve room for them when you define the set, using ``min-size`` (see :doc:`../reference/sets`). Anonymous sets can't be updated this way, as they have no name: use :doc:`update-chain` to replace their chain instead.
