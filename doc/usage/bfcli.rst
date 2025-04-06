``bfcli``
=========

``bfcli`` is part of the ``bpfilter`` project, it has been created to accelerate ``bpfilter`` development by providing a CLI using a trivial communication format with the daemon. For this reason, ``bfcli`` is the main CLI used to develop ``bpfilter``, and it uses the new features of ``bpfilter`` before any other front-end.

Commands
--------

``bfcli`` commands are structured as ``bfcli OBJECT ACTION``. The commands and actions supported by ``bfcli`` are described below.

``ruleset set``
~~~~~~~~~~~~~~~

Define a new ruleset: replace all the existing chains with the ruleset provided. Replacement is not atomic.

**Options**
  - ``--str RULESET``: read and apply the ruleset defining from the command line.
  - ``--file FILE``: read ``FILE`` and apply the ruleset contained in it.

``--str`` and ``--file`` are mutually exclusive.

**Example**

.. code:: shell

    bfcli ruleset set --file myruleset.tx
    bfcli ruleset set --str "chain BF_HOOK_XDP policy ACCEPT rule ip4.saddr in {192.168.1.1} ACCEPT"

``ruleset get``
~~~~~~~~~~~~~~~

Print the ruleset: request all the chains and rules from the daemon. Optionally include rule counter values.

**Options**
  - ``--with-counters``: print the counter values for each rule

**Example**

.. code:: shell

    $ sudo bfcli ruleset get
    chain BF_HOOK_NF_LOCAL_IN{attach=yes} policy ACCEPT
        rule
            ip4.saddr eq 0x0a 0x00 0x00 0x01 0xff 0xff 0xff 0xff
            ACCEPT

.. code:: shell

    $ sudo bfcli ruleset get --with-counters
    chain BF_HOOK_NF_LOCAL_IN{attach=yes} policy ACCEPT
        counters policy 3818 packets 2473532 bytes; error 0 packets 0 bytes
        rule
            ip4.saddr eq 0x0a 0x00 0x00 0x01 0xff 0xff 0xff 0xff
            counters 0 packets 0 bytes
            ACCEPT

``ruleset flush``
~~~~~~~~~~~~~~~~~

Remove all the chains and rules defined by the daemon. Once this command completes, the daemon doesn't contain any filtering rules, as if it was freshly started.

**Examples**

.. code:: shell

    bfcli ruleset flush

Filters definition
------------------

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
~~~~~~

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

  - ``$POLICY``: action taken if no rule matches the packet, either ``ACCEPT`` forward the packet to the kernel, or ``DROP`` to discard it. Note while ``CONTINUE`` is a valid verdict for rules, it is not supported for chain policy.

``$OPTIONS`` are hook-specific comma separated key value pairs:

.. flat-table::
   :header-rows: 1
   :widths: 2 2 2 12
   :fill-cells:

   * - Option
     - Required by
     - Supported by
     - Notes
   * - ``ifindex=$IFINDEX``
     - ``BF_HOOK_XDP``, ``BF_HOOK_TC``
     - N/A
     - Interface index to attach the program to.
   * - ``cgpath=$CGROUP_PATH``
     - ``BF_HOOK_CGROUP_INGRESS``, ``BF_HOOK_CGROUP_EGRESS``
     - N/A
     - Path to the cgroup to attach to.
   * - ``family=$FAMILY``
     - ``BF_HOOK_NF_*``
     - N/A
     - Netfilter hook version to attach the chain to: ``inet4`` for IPv4 or ``inet6`` for IPv6. Rules that are incompatible with the hook version will be ignored.
   * - ``priorities=$INT1-$INT2``
     - ``BF_HOOK_NF_*``
     - N/A
     - ``INT1`` and ``INT2`` are different non-zero integers. Priority values to use when attaching the chain. Two values are required to ensure atomic update of the chain.


Rules
~~~~~

Rules are defined such as:

.. code:: shell

    rule
        [$MATCHER...]
        [counter]
        $VERDICT

With:
  - ``$MATCHER``: zero or more matchers. Matchers are defined later.
  - ``counter``: optional literal. If set, the filter will counter the number of packets and bytes matched by the rule.
  - ``$VERDICT``: action taken by the rule if the packet is matched against **all** the criteria: either ``ACCEPT``, ``DROP`` or ``CONTINUE``.
    - ``ACCEPT``: forward the packet to the kernel
    - ``DROP``: discard the packet.
    - ``CONTINUE``: continue processing subsequent rules.

In a chain, as soon as a rule matches a packet, its verdict is applied. If the verdict is ``ACCEPT`` or ``DROP``, the subsequent rules are not processed. Hence, the rules' order matters. If no rule matches the packet, the chain's policy is applied.

Note ``CONTINUE`` means a packet can be counted more than once if multiple rules specify ``CONTINUE`` and ``counter``.


Matchers
~~~~~~~~

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
    * - :rspan:`2` Source port
      - :rspan:`2` ``meta.sport``
      - ``eq``
      - :rspan:`1` ``$PORT``
      - :rspan:`1` ``$PORT`` is a valid port value, as a decimal integer.
    * - ``not``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.
    * - :rspan:`2` Destination port
      - :rspan:`2` ``meta.dport``
      - ``eq``
      - :rspan:`1` ``$PORT``
      - :rspan:`1` ``$PORT`` is a valid port value, as a decimal integer.
    * - ``not``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.

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
      - :rspan:`3` ``$IP/$PREFIX``
      - :rspan:`3` ``/$PREFIX`` is optional, ``/128`` is used by default.
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
