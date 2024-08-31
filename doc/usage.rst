=====
Usage
=====

This page describes usage of the ``bpfilter`` daemon, as well as command line tools available to communicate with the daemon and define filtering rules.

.. note::

    ``bpfilter`` is not yet distributed in any distribution, if you want to try it, you will have to build it from sources. See :doc:`developers/build`.


``bpfilter`` daemon
===================

The ``bpfilter`` daemon is responsible for creating the BPF program corresponding to the user-provided filtering rules. The daemon will also load and manage the BPF programs on the system.

It is possible to customize the daemon's behavior using the following command-line flags:

- ``-t``, ``--transient``: if used, ``bpfilter`` won't pin any BPF program or map, and no data will be serialized to the filesystem. Hence, as soon as the daemon is stopped, the loaded BPF programs and maps will be removed from the system.
- ``--no-cli``: disable ``bfcli`` support.
- ``--no-nftables``: disable ``nftables`` support.
- ``--no-iptables``: disable ``iptables`` support.
- ``-b``, ``--buffer-len=BUF_LEN_POW``: size of the ``BPF_PROG_LOAD`` buffer as a power of 2. Only available if ``--verbose`` is used. ``BPF_PROG_LOAD`` system call can be provided a buffer for the BPF verifier to provide details in case the program can't be loaded. The required size for the buffer being hardly predictable, this option allows for the user to control it. The final buffer will have a size of ``1 << BUF_LEN_POWER``.
- ``-v``, ``--verbose``: print more detailed log messages.
- ``--debug``: generate the BPF programs in debug mode: if a call to a kfunc or a BPF helper fails, a log message will be printed to ``/sys/kernel/debug/tracing/trace_pipe``.
- ``--usage``: print a short usage message.
- ``-?``, ``--help``: print the help message.

The daemon alone is not sufficient as, it doesn't define any filtering rule by default. This is the role of the front-end, or CLI, and ``bpfilter`` supports multiple CLIs for users to define filtering rules:

- ``bfcli``: ``bpfilter``-specific CLI, developed as part of the project. ``bfcli`` supports new ``bpfilter`` features before other CLIs as it's used for development. It allows for a more flexible rule definition: you can use combination of filters and hooks that might not be possible with other CLIs. However, it doesn't support ``nftables`` or ``iptables`` rules format.
- ``nftables``: requires a custom version of the ``nft`` binary with ``bpfilter`` support (see below), and support for new ``bpfilter`` features is usually a bit delayed.
- ``iptables``: similar to ``nftables``, however ``iptables`` has been deprecated globally in favor of ``nftables``.


``bfcli``
=========

``bfcli`` is part of ``bpfilter`` sources, it has been created in order to speed up ``bpfilter`` development by providing a CLI using a trivial communication format with the daemon. For this reason, ``bfcli`` is the main CLI used to develop ``bpfilter``, and it uses the new features of ``bpfilter`` before any other front-end.

``bfcli`` reads a ruleset defined in a file and send it to the daemon to generate the filtering program(s):

.. code:: shell

    bfcli --file $RULESET

The following sections will use the dollar sign (``$``) to prefix values that should be replaced by the user, and brackets (``[]``) for optional values (whether it's a literal or a user-provided value).

Example of a ruleset:

.. code-block:: shell

    chain $HOOK policy $POLICY
        rule
            $MATCHER
            $VERDICT
        [...]
    [...]

A ruleset is composed of chain(s), rule(s), and matcher(s):
  - A **chain** is a set of rule(s) to match the packet against. It will use the rules to filter packets at a specific location in the kernel: a ``$HOOK``. There can be only one chain defined for a given kernel hook. Chains also have a ``$POLICY`` which specify the action to take with the packet if none of the rules matches.
  - A **rule** defines an action to take on a packet if it matches all its specified criteria. A rule will then apply a defined action to the packet if it's matched.
  - A **matcher** is a matching criterion within a rule. It can match a specific protocol, a specific field, a network interface... The number of matchers supported by ``bpfilter`` and ``bfcli`` is constantly growing.

.. note::

    Lines starting with ``#`` are comments and ``bfcli`` will ignore them. 


Chains
------

Chains are defined such as:

.. code:: shell

    chain $HOOK policy $POLICY

With:
  - ``$HOOK``: hook in the kernel to attach the chain to:

    - ``BF_HOOK_NFT_INGRESS``: XDP hook.
    - ``BF_HOOK_TC_INGRESS``: ingress TC hook.
    - ``BF_HOOK_IPT_PRE_ROUTING``: similar to ``nftables`` and ``iptables`` prerouting hook.
    - ``BF_HOOK_IPT_LOCAL_IN``: similar to ``nftables`` and ``iptables`` input hook.
    - ``BF_HOOK_IPT_FORWARD``: similar to ``nftables`` and ``iptables`` forward hook.
    - ``BF_HOOK_IPT_LOCAL_OUT``: similar to ``nftables`` and ``iptables`` output hook.
    - ``BF_HOOK_IPT_POST_ROUTING``: similar to ``nftables`` and ``iptables`` postrouting hook.
    - ``BF_HOOK_TC_EGRESS``: egress TC hook.

  - ``$POLICY``: action taken if no rule matches the packet, either ``ACCEPT`` forward the packet to the kernel, or ``DROP`` to discard it.


Rules
-----

Rules are defined such as:

.. code:: shell

    rule
        [$MATCHER...]
        [counter]
        $VERDICT

With:
  - ``$MATCHER``: zero or more matchers. Matchers are defined later.
  - ``counter``: optional literal. If set, the filter will counter the number of packets and bytes matched by the rule.
  - ``$VERDICT``: action taken by the rule if the packet is matched against **all** the criteria: either ``ACCEPT`` or ``DROP``.

In a chain, as soon as a rule matches a packet, its verdict is applied, and the subsequent rules are not processed. Hence, the rules' order matters. If no rule matches the packet, the chain's policy is applied.


Matchers
--------

Matchers are defined such as:

.. code:: shell

    $TYPE [$OP] $PAYLOAD

With:
  - ``$TYPE``: type of the matcher, defined which part of the processed network packet need to be compared against. All the exact matcher types are defined below.
  - ``$OP``: comparison operation, not all ``$TYPE`` of matchers support all the existing comparison operators:

    - ``eq``: exact equality.
    - ``not``: inequality.
    - ``any``: match the packet against a set of data defined as the payload. If any of the member of the payload set is found in the packet, the matcher is positive. For example, if you want to match all the ``icmp`` and ``udp`` packets: ``ip4.proto any icmp,udp``.
    - ``all``: match the packet against a set of data defined as the payload. If all the member of the payload set are found in the packet, the matcher is positive, even if the packet contains more than only the members defined in the payload. For example, to match all the packets containing *at least* the ``ACK`` TCP flag: ``tcp.flags all ACK``.

  - ``$PAYLOAD``: payload to compare to the processed network packet. The exact payload format depends on ``$TYPE``.


**Meta matchers**

.. flat-table::
    :header-rows: 1
    :widths: 2 2 1 4 12
    :fill-cells:

    * - Matches
      - Type
      - Operator
      - Payload
      - Notes
    * - L3 protocol
      - ``meta.l3_proto``
      - ``eq``
      - ``$PROTOCOL``
      - ``ipv4`` and ``ipv6`` are supported.
    * - L4 protocol
      - ``meta.l4_proto``
      - ``eq``
      - ``$PROTOCOL``
      - ``icmp``, ``icmpv6``, ``tcp``, ``udp`` are supported.

**IPv4 matchers**

.. flat-table::
    :header-rows: 1
    :widths: 2 2 1 4 12
    :fill-cells:

    * - Matches
      - Type
      - Operator
      - Payload
      - Notes
    * - :rspan:`1` Source address
      - :rspan:`1` ``ip4.saddr``
      - ``eq``
      - :rspan:`3` ``$IP/$MASK``
      - :rspan:`3` ``/$MASK`` is optional, `/32` is used by default.
    * - ``not``
    * - :rspan:`1` Destination address
      - :rspan:`1` ``ip4.daddr``
      - ``eq``
    * - ``not``
    * - Protocol
      - ``ip4.proto``
      - ``eq``
      - ``$PROTOCOL``
      - Only ``icmp`` is supported for now, more protocols will be added.


**TCP matchers**

.. flat-table::
    :header-rows: 1
    :widths: 2 2 1 4 12
    :fill-cells:

    * - Matches
      - Type
      - Operator
      - Payload
      - Notes
    * - :rspan:`1` Source port
      - :rspan:`1` ``tcp.sport``
      - ``eq``
      - :rspan:`1` ``$PORT``
      - :rspan:`3` ``$PORT`` is a valid port value, as a decimal integer.
    * - ``not``
    * - :rspan:`1` Destination port
      - :rspan:`1` ``tcp.dport``
      - ``eq``
      - :rspan:`1` ``$PORT``
    * - ``not``
    * - :rspan:`3` Flags
      - :rspan:`3` ``tcp.flags``
      - ``eq``
      - :rspan:`3` ``$FLAGS``
      - :rspan:`3` ``$FLAGS`` is a comma-separated list of capitalized TCP flags (``FIN``, ``RST``, ``ACK``, ``ECE``, ``SYN``, ``PSH``, ``URG``, ``CWR``).
    * - ``not``
    * - ``any``
    * - ``all``


**UDP matchers**

.. flat-table::
    :header-rows: 1
    :widths: 2 2 1 4 12
    :fill-cells:

    * - Matches
      - Type
      - Operator
      - Payload
      - Notes
    * - :rspan:`1` Source port
      - :rspan:`1` ``udp.sport``
      - ``eq``
      - :rspan:`1` ``$PORT``
      - :rspan:`3` ``$PORT`` is a valid port value, as a decimal integer.
    * - ``not``
    * - :rspan:`1` Destination port
      - :rspan:`1` ``udp.dport``
      - ``eq``
      - :rspan:`1` ``$PORT``
    * - ``not``


``nftables``
============

.. warning::

    ``nftables`` support is currently broken. Work is in progress to fix it.


``iptables``
============

A custom ``iptables`` binary is required to use with ``bpfilter``, but it can be build directly from the ``bpfilter`` source tree: ``make iptables``. Once you have build ``iptables``, you can force it to communicate with ``bpfilter`` instead of the kernel using ``--bpf``.

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
