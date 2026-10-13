Apply a ruleset from a file
===========================

If you manage more than a couple of chains, you will want to write them in a file and apply them all at once with ``bfcli ruleset set``.

Write the ruleset
-----------------

Write your chains in a file, ``filters.bf`` for example. The chain below will block the ``ping`` requests sent to ``192.0.2.1``:

.. code-block:: text

    chain block_ping BF_HOOK_NF_LOCAL_OUT{priorities=101-102} ACCEPT
        rule
            ip4.daddr eq 192.0.2.1
            ip4.proto eq icmp
            icmp.type eq echo-request
            counter
            DROP

Replace the destination with the address you want to filter, and pick Netfilter priorities that are not used yet. Don't forget the hook options: a chain defined without them will be loaded, but it won't be attached, so it won't filter anything. The options supported by each hook are listed in :doc:`../reference/hooks`.

Validate and apply
------------------

Before applying the ruleset, ask ``bfcli`` to validate it:

.. code-block:: shell

    $ bfcli ruleset set --from-file filters.bf --dry-run
    info   : --dry-run used, ruleset not applied

``bfcli`` will parse the file and check the chains, but it won't apply them. A valid file can still fail to apply: the BPF programs are not generated, loaded, or attached during a dry run.

.. warning::

    ``ruleset set`` replaces **all** the existing chains with the ones defined in the file, so the file must contain every chain you want to keep. The replacement is not atomic, and if one of the chains fails to load or attach, no chain is left in place. If you want to change a single chain, use ``chain set`` or :doc:`update-chain` instead.

Apply the ruleset, then print it:

.. code-block:: shell

    $ sudo bfcli ruleset set --from-file filters.bf
    $ sudo bfcli ruleset get
    chain block_ping BF_HOOK_NF_LOCAL_OUT{priorities=101-102} ACCEPT
        counters policy 0 packets 0 bytes; error 0 packets 0 bytes
        rule
            ip4.daddr eq 192.0.2.1
            ip4.proto eq icmp
            icmp.type eq echo-request
            counters 0 packets 0 bytes
            DROP

Your chains should be printed with their hook options and their rules. If you want to be sure they filter what you expect, send some matching traffic and watch the rules' counters go up.

If you only want to apply one of the chains defined in the file, select it by name:

.. code-block:: shell

    $ sudo bfcli chain set --name block_ping --from-file filters.bf

See :doc:`../reference/bfcli` for the commands' options, and :doc:`../reference/ruleset` for the syntax of the file.
