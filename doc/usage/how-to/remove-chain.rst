Remove a filtering chain
========================

If you don't need a chain anymore, use ``bfcli chain flush`` to detach it from its hook and unload it.

Find the chain
--------------

You need the name of the chain. If you don't remember it, print the ruleset:

.. code-block:: shell

    $ sudo bfcli ruleset get
    chain block_sources BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
        counters policy 0 packets 0 bytes; error 0 packets 0 bytes
        set blocklist (ip4.saddr) in {
            192.0.2.1
            192.0.2.2
        }
        rule
            (ip4.saddr) in blocklist
            counters 0 packets 0 bytes
            DROP
    chain block_ping BF_HOOK_NF_LOCAL_OUT{priorities=101-102} ACCEPT
        counters policy 0 packets 0 bytes; error 0 packets 0 bytes
        rule
            ip4.daddr eq 192.0.2.1
            ip4.proto eq icmp
            icmp.type eq echo-request
            counters 0 packets 0 bytes
            DROP

You can also print a single chain to be sure it's the one you want to remove. Let's use the chain created in :doc:`block-addresses` as an example:

.. code-block:: shell

    $ sudo bfcli chain get --name block_sources
    chain block_sources BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
        counters policy 0 packets 0 bytes; error 0 packets 0 bytes
        set blocklist (ip4.saddr) in {
            192.0.2.1
            192.0.2.2
        }
        rule
            (ip4.saddr) in blocklist
            counters 0 packets 0 bytes
            DROP

Remove it
---------

.. code-block:: shell

    $ sudo bfcli chain flush --name block_sources
    $ sudo bfcli ruleset get
    chain block_ping BF_HOOK_NF_LOCAL_OUT{priorities=101-102} ACCEPT
        counters policy 0 packets 0 bytes; error 0 packets 0 bytes
        rule
            ip4.daddr eq 192.0.2.1
            ip4.proto eq icmp
            icmp.type eq echo-request
            counters 0 packets 0 bytes
            DROP

``block_sources`` is gone, and so are its rules. The other chains are left untouched. If you try to print it with ``chain get``, ``bfcli`` will tell you the chain doesn't exist.

If you want to remove all your chains at once, use ``sudo bfcli ruleset flush``: once this command completes, bpfilter doesn't contain any filtering rules. It only applies to the chains pinned in the BPF filesystem used by ``bfcli``, see ``--bpffs-path`` in :doc:`../reference/bfcli` if you use more than one.
