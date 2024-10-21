``bfcli``
=========

``bfcli`` is part of ``bpfilter`` sources, it has been created in order to speed up ``bpfilter`` development by providing a CLI using a trivial communication format with the daemon. For this reason, ``bfcli`` is the main CLI used to develop ``bpfilter``, and it uses the new features of ``bpfilter`` before any other front-end.

``bfcli`` can read a ruleset from a source file (using ``--file``) or from its arguments (using ``--str``):

.. code:: shell

    bfcli --file myruleset.tx
    bfcli --str "chain BF_HOOK_XDP policy ACCEPT rule ip4.saddr in {192.168.1.1} ACCEPT"

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

    chain $HOOK{$OPTIONS} policy $POLICY

With:
  - ``$HOOK``: hook in the kernel to attach the chain to:

    - ``BF_HOOK_XDP``: XDP hook.
    - ``BF_HOOK_TC_INGRESS``: ingress TC hook.
    - ``BF_HOOK_NF_PRE_ROUTING``: similar to ``nftables`` and ``iptables`` prerouting hook.
    - ``BF_HOOK_NF_LOCAL_IN``: similar to ``nftables`` and ``iptables`` input hook.
    - ``BF_HOOK_CGROUP_INGRESS``: ingress cgroup hook.
    - ``BF_HOOK_CGROUP_EGRESS``: egress cgroup hook.
    - ``BF_HOOK_NF_FORWARD``: similar to ``nftables`` and ``iptables`` forward hook.
    - ``BF_HOOK_NF_LOCAL_OUT``: similar to ``nftables`` and ``iptables`` output hook.
    - ``BF_HOOK_NF_POST_ROUTING``: similar to ``nftables`` and ``iptables`` postrouting hook.
    - ``BF_HOOK_TC_EGRESS``: egress TC hook.

  - ``$POLICY``: action taken if no rule matches the packet, either ``ACCEPT`` forward the packet to the kernel, or ``DROP`` to discard it.

``$OPTIONS`` are hook-specific comma separated key value pairs:

.. flat-table::
   :header-rows: 1
   :widths: 2 2 12
   :fill-cells:

   * - Option
     - Supported values
     - Notes
   * - ``ifindex=$IFINDEX``
     - ``BF_HOOK_XDP``, ``BF_HOOK_TC_INGRESS``, ``BF_HOOK_TC_EGRESS``
     - Interface index to attach the program to.
   * - ``cgroup=$CGROUP_PATH``
     - ``BF_HOOK_CGROUP_INGRESS``, ``BF_HOOK_CGROUP_EGRESS``
     - Path to the cgroup to attach to.
   * - ``name=$CHAIN_NAME``
     - Allowed patern: ``[a-zA-Z0-9_]+``
     - Name of the chain, will be reused as the name of the BPF program. A same name can be reused for multiple chains. Must be at most ``BPF_OBJ_NAME_LEN - 1`` characters.
   * - ``attach=$BOOL``
     - ``yes`` or ``no``
     - If ``no``, the chain will be generated and loaded to the kernel, but not attached. Useful if you want to attach it manually, or validate the generation process. Default to ``yes``.

.. note::

    ``name=$CHAIN_NAME`` will only change the name of the BPF program loaded into the kernel. It won't affect the map names, not the pin path. Defining multiple programs with the same name is possible, but a name clash could prevent the program from being pinned.


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
    - ``in``: matches the packet against a hashed set of reference values. Using the ``in`` operator is useful when the packet's data needs to be compared against a large set of different values. Let's say you want to filter 1000 different IPv4 addresses, you can either define 1000 ``ip4.saddr eq $IP`` matcher, in which case ``bpfilter`` will compare the packet against every IP one after the other. Or you can use ``ip4.saddr in {$IP0,IP1,...}`` in which case ``bpfilter`` will compare the packet's data against the hashed set as a whole in 1 operation.
    - ``range``: matches in a range of values. Formatted as ``$START-$END``. Both ``$START`` and ``$END`` are included in the range.

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
    * - Interface index
      - ``meta.ifindex``
      - ``eq``
      - ``$IFINDEX``
      - For chains attached to an ingress hook, ``$IFINDEX`` is the input interface index. For chains attached to an egress hook, ``$IFINDEX`` is the output interface index.
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
    * - :rspan:`2` Source address
      - :rspan:`2` ``ip4.saddr``
      - ``eq``
      - :rspan:`1` ``$IP/$MASK``
      - :rspan:`1` ``/$MASK`` is optional, ``/32`` is used by default.
    * - ``not``
    * - ``in``
      - ``{$IP[,...]}``
      - Only support ``/32`` mask.
    * - :rspan:`2` Destination address
      - :rspan:`2` ``ip4.daddr``
      - ``eq``
      - :rspan:`1` ``$IP/$MASK``
      - :rspan:`1` ``/$MASK`` is optional, ``/32`` is used by default.
    * - ``not``
    * - ``in``
      - ``{$IP[,...]}``
      - Only support ``/32`` mask.
    * - Protocol
      - ``ip4.proto``
      - ``eq``
      - ``$PROTOCOL``
      - Only ``icmp`` is supported for now, more protocols will be added.


**IPv6 matchers**

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
      - :rspan:`1` ``ip6.saddr``
      - ``eq``
      - :rspan:`3` ``$IP/$MASK``
      - :rspan:`3` ``/$MASK`` is optional, `/128` is used by default.
    * - ``not``
    * - :rspan:`1` Destination address
      - :rspan:`1` ``ip6.daddr``
      - ``eq``
    * - ``not``


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
    * - :rspan:`2` Source port
      - :rspan:`2` ``tcp.sport``
      - ``eq``
      - :rspan:`1` ``$PORT``
      - :rspan:`1` ``$PORT`` is a valid port value, as a decimal integer.
    * - ``not``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.
    * - :rspan:`2` Destination port
      - :rspan:`2` ``tcp.dport``
      - ``eq``
      - :rspan:`1` ``$PORT``
      - :rspan:`1` ``$PORT`` is a valid port value, as a decimal integer.
    * - ``not``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.
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
    * - :rspan:`2` Source port
      - :rspan:`2` ``udp.sport``
      - ``eq``
      - :rspan:`1` ``$PORT``
      - :rspan:`1` ``$PORT`` is a valid port value, as a decimal integer.
    * - ``not``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.
    * - :rspan:`2` Destination port
      - :rspan:`2` ``udp.dport``
      - ``eq``
      - :rspan:`1` ``$PORT``
      - :rspan:`1` ``$PORT`` is a valid port value, as a decimal integer.
    * - ``not``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.
