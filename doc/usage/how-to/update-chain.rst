Update a chain without interrupting filtering
=============================================

If you want to change the rules of a chain without leaving your traffic unfiltered, use ``bfcli chain update``: the new chain will atomically replace the existing one.

Print the existing chain
------------------------

.. code-block:: shell

    $ sudo bfcli chain get --name block_sources
    chain block_sources BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
        counters policy 4 packets 292 bytes; error 0 packets 0 bytes
        set blocklist (ip4.saddr) in {
            192.0.2.1
            192.0.2.2
        }
        rule
            (ip4.saddr) in blocklist
            counters 3 packets 294 bytes
            DROP

Take note of its name and its hook: the new chain must use the same ones, or ``chain update`` will reject it.

Write the new chain
-------------------

Edit the file defining the chain, ``block_sources.bf`` here. For example, to block one more address on our TC ingress chain:

.. code-block:: text

    chain block_sources BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
        set blocklist (ip4.saddr) in { 192.0.2.1; 192.0.2.2; 192.0.2.3 }
        rule
            (ip4.saddr) in blocklist
            counter
            DROP

You can keep the hook options in the file: ``chain update`` will ignore them (``bfcli`` prints a warning), and keep the chain attached where it is. If you want to modify the hook options, use ``bfcli chain set`` instead, but the replacement won't be atomic.

The sets of the new chain will contain the elements defined in the file, and nothing else: if you changed them with ``chain update-set``, update the file first.

Validate and update
-------------------

.. code-block:: shell

    $ bfcli chain update --from-file block_sources.bf --dry-run
    warning: Hook options are ignored when updating a chain
    info   : --dry-run used, chain not updated
    $ sudo bfcli chain update --from-file block_sources.bf
    warning: Hook options are ignored when updating a chain
    $ sudo bfcli chain get --name block_sources
    chain block_sources BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
        counters policy 0 packets 0 bytes; error 0 packets 0 bytes
        set blocklist (ip4.saddr) in {
            192.0.2.1
            192.0.2.2
            192.0.2.3
        }
        rule
            (ip4.saddr) in blocklist
            counters 0 packets 0 bytes
            DROP

The chain should be printed with its new rules, and the same hook options as before. Send some matching traffic if you want to be sure it filters what you expect.

Updating a chain resets its counters. If you only want to add or remove elements from a named set, see :doc:`update-blocklist`: the counters are preserved, and you don't have to write the whole chain again.

See :doc:`../explanation/lifecycle` to understand what happens when a chain is replaced, and :doc:`../reference/bfcli` for the options of ``chain update``.
