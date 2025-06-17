``bfcli``
=========

``bfcli`` is a command line tool to communicate with the bpfilter daemon. It provides supports for extended features compared to the iptables client.

Commands
--------

``bfcli`` commands are structured as ``bfcli OBJECT ACTION``. The commands and actions supported by ``bfcli`` are described below.

``ruleset set``
~~~~~~~~~~~~~~~

Define a new ruleset: replace all the existing chains with the ruleset provided. Replacement is not atomic.

Chains with valid hook options defined are attached to their hook. Chains without hook options are only loaded into the kernel.

**Options**
  - ``--from-str RULESET``: read and apply the ruleset defining from the command line.
  - ``--from-file FILE``: read ``FILE`` and apply the ruleset contained in it.

``--from-str`` and ``--from-file`` are mutually exclusive.

**Example**

.. code:: shell

    bfcli ruleset set --from-file myruleset.txt
    bfcli ruleset set --from-str "chain my_xdp_chain BF_HOOK_XDP ACCEPT rule ip4.saddr in {192.168.1.1} ACCEPT"

``ruleset get``
~~~~~~~~~~~~~~~

Print the ruleset: request all the chains and rules from the daemon with counters values.

**Example**

.. code:: shell

    $ sudo bfcli ruleset get
      chain my_tc_chain BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
          counters policy 87 packets 9085 bytes; error 0 packets 0 bytes
          rule
              ip4.saddr eq 0xc0 0xa8 0x01 0x01 0xff 0xff 0xff 0xff
              counters 2 packets 196 bytes
              ACCEPT

``ruleset flush``
~~~~~~~~~~~~~~~~~

Remove all the chains and rules defined by the daemon. Once this command completes, the daemon doesn't contain any filtering rules, as if it was freshly started.

**Examples**

.. code:: shell

    $ sudo bfcli ruleset get
      chain my_tc_chain BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
          counters policy 87 packets 9085 bytes; error 0 packets 0 bytes
          rule
              ip4.saddr eq 0xc0 0xa8 0x01 0x01 0xff 0xff 0xff 0xff
              counters 2 packets 196 bytes
              ACCEPT
    $ sudo bfcli ruleset flush
    $ sudo bfcli ruleset get
    $ # Empty ruleset

``chain set``
~~~~~~~~~~~~~

Generate and load a chain into the kernel. If the chain definition contains hook options, the daemon will attach it to its hook. Any existing chain with the same name (attached or not) will be discarded and replaced with the new one.

If you want to update an existing chain without downtime, use ``bfcli chain update`` instead.

**Options**
  - ``--from-str CHAIN``: read the chain to set from the command line arguments.
  - ``--from-file FILEPATH``: read the chain from a file.
  - ``--name NAME``: if ``--from-str`` or ``--from-file`` provide multiple chains, ``NAME`` specify which one to send to the daemon.

**Examples**

.. code:: shell

    $ # Create an empty XDP chain, do not attach it
    $ sudo bfcli chain set --from-str "chain my_xdp_chain BF_HOOK_XDP ACCEPT"
    $ sudo bfcli chain get --name my_xdp_chain
      chain my_xdp_chain BF_HOOK_XDP ACCEPT
          counters policy 0 packets 0 bytes; error 0 packets 0 bytes

    # Create an empty TC chain and attach it
    $ sudo bfcli chain set --from-str "chain my_tc_chain BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT"
    $ sudo bfcli chain get --name my_tc_chain
      chain my_tc_chain BF_HOOK_TC_INGRESS{ifindex=2} ACCEPT
          counters policy 35 packets 4091 bytes; error 0 packets 0 bytes

``chain get``
~~~~~~~~~~~~~

Print a chain.

**Options**
  - ``--name NAME``: name of the chain to print.

**Examples**

.. code:: shell

    $ # Create a Netfilter chain and print it
    $ sudo bfcli chain set --from-str "chain my_input_chain BF_HOOK_NF_LOCAL_IN{family=inet4,priorities=101-102} ACCEPT"
    $ sudo bfcli chain get --name my_input_chain
      chain my_input_chain BF_HOOK_NF_LOCAL_IN{family=inet4,priorities=101-102} ACCEPT
          counters policy 1161 packets 149423 bytes; error 0 packets 0 bytes

``chain load``
~~~~~~~~~~~~~~

Generate and load a chain into the kernel. Hook options are ignored.

If a chain with the same name already exist, it won't be replaced. See ``bfcli chain set`` or ``bfcli chain update`` to replace an existing chain.

**Options**
  - ``--from-str CHAIN``: read the chain to set from the command line arguments.
  - ``--from-file FILEPATH``: read the chain from a file.
  - ``--name NAME``: if ``--from-str`` or ``--from-file`` provide multiple chains, ``NAME`` specify which one to send to the daemon.

**Examples**

.. code:: shell

    $ # Create an XDP chain and print it
    $ sudo bfcli chain load --from-str "chain my_xdp_chain BF_HOOK_XDP ACCEPT"
    $ sudo bfcli chain get --name my_xdp_chain
      chain my_xdp_chain BF_HOOK_XDP ACCEPT
          counters policy 0 packets 0 bytes; error 0 packets 0 bytes

    $ # Create a single chain from a string containing 2 chains. Hook options are ignored.
    $ sudo bfcli chain load --name my_other_xdp_chain --from-str "
        chain my_next_xdp_chain BF_HOOK_XDP DROP
        chain my_other_xdp_chain BF_HOOK_XDP ACCEPT"
    $ sudo bfcli chain get --name my_other_xdp_chain
      chain my_other_xdp_chain BF_HOOK_XDP ACCEPT
          counters policy 0 packets 0 bytes; error 0 packets 0 bytes

``chain attach``
~~~~~~~~~~~~~~~~

Attach a loaded chain to its hook.

Only loaded chains (not attached) can be attached. See ``bfcli chain set`` and ``bfcli chain update`` if you want to update an existing chain.

See below for a list of available hook options.

**Options**
  - ``--name NAME``: name of the chain to attach.
  - ``--option OPTION``: hook-specific options to attach the chain to its hook. See hook options below.

**Examples**

.. code:: shell

    $ # Load and attach an XDP chain, print it
    $ sudo bfcli chain load --from-str "chain my_xdp_chain BF_HOOK_XDP ACCEPT"
    $ sudo bfcli chain attach --name my_xdp_chain --option ifindex=2
    $ sudo bfcli chain get --name my_xdp_chain
      chain my_xdp_chain BF_HOOK_XDP{ifindex=2} ACCEPT
          counters policy 101 packets 11714 bytes; error 0 packets 0 bytes

``chain update``
~~~~~~~~~~~~~~~~

Update an existing chain. The new chain will atomically update the existing one. Hook options are ignored. The new chain will replace the existing chain with the same name.

If you want to modify the hook options, use ``bfcli chain set`` instead.

**Options**
  - ``--from-str CHAIN``: read the chain to set from the command line arguments.
  - ``--from-file FILEPATH``: read the chain from a file.
  - ``--name NAME``: if ``--from-str`` or ``--from-file`` provide multiple chains, ``NAME`` specify which one to send to the daemon.

**Examples**

.. code:: shell

    $ # Set an XDP chain and update it
    $ sudo bfcli chain set --from-str "chain my_xdp_chain BF_HOOK_XDP{ifindex=2} ACCEPT"
    $ sudo bfcli chain get --name my_xdp_chain
      chain my_xdp_chain BF_HOOK_XDP{ifindex=2} ACCEPT
          counters policy 307 packets 36544 bytes; error 0 packets 0 bytes
    $ sudo bfcli chain update --from-str "
          chain my_xdp_chain BF_HOOK_XDP{ifindex=2} ACCEPT
              rule
                  ip4.proto eq icmp
                  counter
                  DROP"
    $ sudo bfcli chain get --name my_xdp_chain
      chain my_xdp_chain BF_HOOK_XDP{ifindex=2} ACCEPT
          counters policy 204 packets 24074 bytes; error 0 packets 0 bytes
          rule
              ip4.proto eq 0x01
              counters 0 packets 0 bytes
              DROP

``chain flush``
~~~~~~~~~~~~~~~

Detach, unload, and discard an existing chain.

**Options**
  - ``--name NAME``: name of the chain to flush.

**Examples**

.. code:: shell

    $ # Set an XDP chain and update it
    $ sudo bfcli chain set --from-str "chain my_xdp_chain BF_HOOK_XDP ACCEPT"
    $ sudo bfcli chain get --name my_xdp_chain
      chain my_xdp_chain BF_HOOK_XDP ACCEPT
          counters policy 0 packets 0 bytes; error 0 packets 0 bytes
    $ sudo bfcli chain flush --name my_xdp_chain
    $ sudo bfcli chain get --name my_xdp_chain
    $ # No output, chain doesn't exist


Filters definition
------------------

The following sections will use the dollar sign (``$``) to prefix values that should be replaced by the user, and brackets (``[]``) for optional values (whether it's a literal or a user-provided value).

Example of a ruleset:

.. code-block:: shell

    chain $NAME $HOOK $HOOK_OPTIONS $POLICY
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

    chain $NAME $HOOK{$OPTIONS} $POLICY

With:
  - ``$NAME``: user-defined name for the chain.
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


Meta
####

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
    * - Probability
      - ``meta.probability``
      - ``eq``
      - ``$PROBABILITY``
      - ``$PROBABILITY`` is an integer between 0 and 100 followed by the ``%`` sign.

IPv4
####

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
    * - Source network
      - ``ip4.snet``
      - ``in``
      - ``{$IP/$MASK[,...]}``
    * - Destination network
      - ``ip4.dnet``
      - ``in``
      - ``{$IP/$MASK[,...]}``
    * - Protocol
      - ``ip4.proto``
      - ``eq``
      - ``$PROTOCOL``
      - Only ``icmp`` is supported for now, more protocols will be added.


IPv6
####

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
    * - Source network
      - ``ip6.snet``
      - ``in``
      - ``{$IP/$MASK[,...]}``
    * - Destination network
      - ``ip6.dnet``
      - ``in``
      - ``{$IP/$MASK[,...]}``


TCP
###

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


UDP
###

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

ICMP
####

.. flat-table::
    :header-rows: 1
    :widths: 2 2 1 4 12
    :fill-cells:

    * - Matches
      - Type
      - Operator
      - Payload
      - Notes
    * - :rspan:`1` Type
      - :rspan:`1` ``icmp.type``
      - ``eq``
      - :rspan:`1` ``$ICMP_TYPE``
      - :rspan:`1` ``$ICMP_TYPE`` is a valid ICMP message type as a decimal integer.
    * - ``not``
    * - :rspan:`1` Code
      - :rspan:`1` ``icmp.code``
      - ``eq``
      - :rspan:`1` ``$ICMP_CODE``
      - :rspan:`1` ``$ICMP_CODE`` is a valid ICMP message code as a decimal integer.
    * - ``not``

ICMPv6
######

.. flat-table::
    :header-rows: 1
    :widths: 2 2 1 4 12
    :fill-cells:

    * - Matches
      - Type
      - Operator
      - Payload
      - Notes
    * - :rspan:`1` Type
      - :rspan:`1` ``icmpv6.type``
      - ``eq``
      - :rspan:`1` ``$ICMPV6_TYPE``
      - :rspan:`1` ``$ICMPV6_TYPE`` is a valid ICMPv6 message type as a decimal integer.
    * - ``not``
    * - :rspan:`1` Code
      - :rspan:`1` ``icmpv6.code``
      - ``eq``
      - :rspan:`1` ``$ICMPV6_CODE``
      - :rspan:`1` ``$ICMPV6_CODE`` is a valid ICMPv6 message code as a decimal integer.
    * - ``not``
