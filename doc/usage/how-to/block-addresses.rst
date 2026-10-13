Block traffic from selected addresses
=====================================

Let's say you want to drop every packet coming from a few IPv4 addresses on a given interface. You could write a rule for each address, but a set is a better fit: the chain will look for the packet's source address in the set in a single operation, however many addresses it contains.

Find the interface
------------------

List the interfaces, and pick the one receiving the traffic you want to filter:

.. code-block:: shell

    $ ip -br link
    lo               UNKNOWN        00:00:00:00:00:00 <LOOPBACK,UP,LOWER_UP>
    eth0@if2         UP             6e:51:fe:e4:18:45 <BROADCAST,MULTICAST,UP,LOWER_UP>

bpfilter needs the index of the interface, not its name. Replace ``eth0`` with your interface:

.. code-block:: shell

    $ cat /sys/class/net/eth0/ifindex
    2

Create the chain
----------------

Write the following in ``block_sources.bf``. Replace ``2`` with the index of your interface, and the addresses with the ones you want to block:

.. code-block:: text

    chain block_sources BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
        set blocklist (ip4.saddr) in { 192.0.2.1; 192.0.2.2 }
        rule
            (ip4.saddr) in blocklist
            counter
            DROP

The chain will drop every packet entering the interface if its source address is in ``blocklist``. Everything else is accepted, including the packets that are not IPv4. If a chain named ``block_sources`` already exists, ``chain set`` will replace it.

Validate the chain, then apply it:

.. code-block:: shell

    $ bfcli chain set --from-file block_sources.bf --dry-run
    info   : --dry-run used, chain not set
    $ sudo bfcli chain set --from-file block_sources.bf

Check that it works
-------------------

Send some traffic to the interface from one of the blocked addresses, then print the chain:

.. code-block:: shell

    $ sudo bfcli chain get --name block_sources
    chain block_sources BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
        counters policy 8 packets 628 bytes; error 0 packets 0 bytes
        set blocklist (ip4.saddr) in {
            192.0.2.1
            192.0.2.2
        }
        rule
            (ip4.saddr) in blocklist
            counters 3 packets 294 bytes
            DROP

The rule's counter should go up: here, it dropped 3 ``ping`` requests sent from ``192.0.2.1``. Don't forget to try with an address that is not in the blocklist: its packets should still reach the host.

If you want to change the blocked addresses later, see :doc:`update-blocklist`: you won't have to replace the chain. To remove the chain, run:

.. code-block:: shell

    $ sudo bfcli chain flush --name block_sources

See :doc:`../reference/sets` for the sets syntax, and :doc:`../explanation/hooks` if you are not sure which hook to use.
