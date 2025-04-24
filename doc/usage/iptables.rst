``iptables``
============

A custom ``iptables`` binary is required to use with ``bpfilter``, but it can be built directly from the ``bpfilter`` source tree: ``make iptables``. Once you have build ``iptables``, you can force it to communicate with ``bpfilter`` instead of the kernel using ``--bpf``.

The following filters are supported:

- Source IPv4 address and mask.
- Destination IPv4 address and mask.
- Layer 4 protocol.

Filtering rules can be defined for any table, and ``ACCEPT`` and ``DROP`` action are supported. The ruleset can also be fetched back from ``bpfilter``. For example:

.. code:: shell

    # Start bpfilter daemon
    $ sudo bpfilter

    # Add a new rule to block ping requests
    $ sudo iptables -I INPUT --bpf -p icmp -j DROP

    # Show the rules and counters after the host was pinged
    $ sudo iptables --bpf -nv -L
    Chain INPUT (policy ACCEPT 327 packets, 42757 bytes)
    pkts bytes target     prot opt in     out     source               destination
        2   196 DROP       icmp --  *      *       0.0.0.0/0            0.0.0.0/0

    Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
    pkts bytes target     prot opt in     out     source               destination

    Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)
    pkts bytes target     prot opt in     out     source               destination
