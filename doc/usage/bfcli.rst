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
  - ``--dry-run``: parse and validate the ruleset, but do not apply it.

``--from-str`` and ``--from-file`` are mutually exclusive.

**Example**

.. code:: shell

    bfcli ruleset set --from-file myruleset.txt
    bfcli ruleset set --from-str "chain my_xdp_chain BF_HOOK_XDP ACCEPT rule (ip4.saddr) in {192.168.1.1} ACCEPT"

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
  - ``--dry-run``: parse and validate the chain, but do not apply it.

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

``chain logs``
~~~~~~~~~~~~~~

Print a chain's logged packets.

bfcli will print the logged headers as they are published by the chain. Only the headers requested in the ``log`` action will be printed. Hit ``Ctrl+C`` to quit.

For each logged packet, bfcli will print the receive timestamp and the packet size, followed by each requested layer (see the ``log`` action below). If one of the requested layer could not be processed by the chain, the corresponding output will be truncated.

**Options**
  - ``--name NAME``: name of the chain to print the logged packets for.

**Examples**

.. code:: shell

    $ # Create an XDP chain with logs and print the logs
    $ sudo bfcli chain set --from-str "
      chain my_input_chain BF_HOOK_XDP{ifindex=2} ACCEPT
          rule
              meta.l4_proto tcp
              log transport
              CONTINUE
      "
    $ sudo bfcli chain logs --name my_input_chain
      [15:14:32.652085] Packet: 66 bytes
        TCP       : 52719 → 22    [ack]
                    seq=1643155516 ack=1290470623 win=4618

      [15:14:32.652842] Packet: 66 bytes
        TCP       : 52719 → 22    [ack]
                    seq=1643155516 ack=1290470723 win=4619

      [...]

``chain load``
~~~~~~~~~~~~~~

Generate and load a chain into the kernel. Hook options are ignored.

If a chain with the same name already exist, it won't be replaced. See ``bfcli chain set`` or ``bfcli chain update`` to replace an existing chain.

**Options**
  - ``--from-str CHAIN``: read the chain to set from the command line arguments.
  - ``--from-file FILEPATH``: read the chain from a file.
  - ``--name NAME``: if ``--from-str`` or ``--from-file`` provide multiple chains, ``NAME`` specify which one to send to the daemon.
  - ``--dry-run``: parse and validate the chain, but do not apply it.

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
  - ``--dry-run``: parse and validate the chain, but do not apply it.

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
        [$SET...]
        [log link,internet,transport]
        [counter]
        [mark $MARK]
        $VERDICT

With:
  - ``$MATCHER``: zero or more matchers. Matchers are defined later.
  - ``log``: optional. If set, log the requested protocol headers. ``link`` will log the link (layer 2) header, ``internet`` with log the internet (layer 3) header, and ``transport`` will log the transport (layer 4) header. At least one header type is required.
  - ``counter``: optional literal. If set, the filter will counter the number of packets and bytes matched by the rule.
  - ``mark``: optional, ``$MARK`` must be a valid decimal or hexadecimal 32-bits value. If set, write the packet's marker value. This marker can be used later on in a rule (see ``meta.mark``) or with a TC filter.
  - ``$VERDICT``: action taken by the rule if the packet is matched against **all** the criteria: either ``ACCEPT``, ``DROP`` or ``CONTINUE``.
    - ``ACCEPT``: forward the packet to the kernel
    - ``DROP``: discard the packet.
    - ``CONTINUE``: continue processing subsequent rules.

In a chain, as soon as a rule matches a packet, its verdict is applied. If the verdict is ``ACCEPT`` or ``DROP``, the subsequent rules are not processed. Hence, the rules' order matters. If no rule matches the packet, the chain's policy is applied.

Note ``CONTINUE`` means a packet can be counted more than once if multiple rules specify ``CONTINUE`` and ``counter``.

Sets
~~~~

Sets defines a group of data of the same type. At runtime, the chain will check if the corresponding packet data is in the set, instead of checking against every single value from the set, which makes it much faster.

There are multiple ways to define sets in your ruleset. bpfilter supports named and anonymous sets:

.. code:: shell

    set $NAME $KEY in {
        $ELEMENT_0;
        $ELEMENT_1
    }

    rule
        $KEY in $NAME
        [...]

    rule
        $KEY in { $ELEMENT_0; $ELEMENT_1 }
        [...]

    rule
        $KEY in {
            $ELEMENT_0
            $ELEMENT_1
        }
        [...]

With:
  - ``$NAME``: name of the set, for named sets. Allows users to define a set at the beginning of the ruleset, then use it in multiple rules. Sets defined directly in a rule are anonymous, they can't be reused in a different rule. When using a named set, the key used in the rule to refer to the set must be the same as the key used to define the set.
  - ``$KEY``: the set's key, which is the format of the data stored in the set. Keys are defined as ``($MATCHER_0 [, $MATCHERS...])``. This instructs bpfilter that the key is formed from the payload of the list matchers. For example, ``(ip4.saddr, ip4.proto)`` describe the key as the source IPv4 address followed by the IPv4 protocol field. Each matcher defined in the key is called a "component". Parentheses are required even if the key contains a single component.
  - ``$ELEMENT``: elements are the data to store in the set, each component of the key should have a corresponding value in each element. Components of an element are comma-separated, elements themselves are delimited by semicolon or new line.

Here is an example:

.. code:: shell

    set dns (ip4.saddr) in { 1.1.1.1; 1.0.0.1 }

    rule
        (ip4.saddr) in dns
        counter
        ACCEPT

    rule
        (ip4.saddr, ip4.proto) in {
            192.168.1.1, tcp
            192.168.1.10, udp
            # More can be added...
        }
        ACCEPT

.. warning::

    While the IPv4 and IPv6 ``snet`` and ``dnet`` matchers are supported in sets, they can be mixed with other matchers. A set key can be a single ``ip4.snet``, ``ip4.dnet``, ``ip6.snet``, ``ip6.dnet``, or a combination of non-network matchers.

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
    - ``in``: matches the packet against a hashed set of reference values. Using the ``in`` operator is useful when the packet's data needs to be compared against a large set of different values. Let's say you want to filter 1000 different IPv4 addresses, you can either define 1000 ``ip4.saddr eq $IP`` matcher, in which case ``bpfilter`` will compare the packet against every IP one after the other. Or you can use ``(ip4.saddr) in {$IP0,IP1,...}`` in which case ``bpfilter`` will compare the packet's data against the hashed set as a whole in 1 operation.
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
    * - Interface
      - ``meta.iface``
      - ``eq``
      - ``$INTERFACE``
      - For chains attached to an ingress hook, ``$INTERFACE`` is the input interface, for chains attached to an egress hook, ``$INTERFACE`` is the output interface. ``$INTERFACE`` must be an interface name (e.g., "eth0", "wlan0") or a decimal interface index (e.g., "1", "2").
    * - L3 protocol
      - ``meta.l3_proto``
      - ``eq``
      - ``$PROTOCOL``
      - ``$PROTOCOL`` must be an internet layer protocol name (e.g. "IPv6", case insensitive), or a valid decimal or hexadecimal `IEEE 802 number`_.
    * - L4 protocol
      - ``meta.l4_proto``
      - ``eq``
      - ``$PROTOCOL``
      - ``$PROTOCOL`` must be a transport layer protocol name (e.g. "ICMP", case insensitive), or a valid decimal `internet protocol number`_.
    * - :rspan:`2` Source port
      - :rspan:`2` ``meta.sport``
      - ``eq``
      - :rspan:`1` ``$PORT``
      - :rspan:`1` ``$PORT`` must be a valid decimal port number.
    * - ``not``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.
    * - :rspan:`2` Destination port
      - :rspan:`2` ``meta.dport``
      - ``eq``
      - :rspan:`1` ``$PORT``
      - :rspan:`1` ``$PORT`` must be a valid decimal port number.
    * - ``not``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.
    * - Probability
      - ``meta.probability``
      - ``eq``
      - ``$PROBABILITY``
      - ``$PROBABILITY`` is a valid decimal percentage value (i.e., within [0%, 100%]).
    * - :rspan:`1` Mark
      - :rspan:`1` ``meta.mark``
      - ``eq``
      - :rspan:`1` ``$MARK``
      - :rspan:`1` ``$MARK`` must be a valid decimal or hexadecimal 32-bits value. Incompatible with ``BF_HOOK_XDP`` hook.
    * - ``not``

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
      - :rspan:`1` ``$ADDR``
      - :rspan:`5` ``$ADDR`` is an IPv4 address in dotted-decimal format, "ddd.ddd.ddd.ddd", where ddd is a decimal number of up to three digits in the range 0 to 255. To filter on an IPv4 network (using an IPv4 address and a subnet mask), see ``ip4.snet`` or ``ip4.dnet``.
    * - ``not``
    * - ``in``
      - ``{$ADDR[,...]}``
    * - :rspan:`2` Destination address
      - :rspan:`2` ``ip4.daddr``
      - ``eq``
      - :rspan:`1` ``$ADDR``
    * - ``not``
    * - ``in``
      - ``{$ADDR[,...]}``
    * - :rspan:`2` Source network
      - :rspan:`2` ``ip4.snet``
      - ``eq``
      - :rspan:`1` ``$ADDR/$MASK``
      - :rspan:`5` ``$ADDR`` is an IPv4 network address in dotted-decimal format, \"ddd.ddd.ddd.ddd\", where ddd is a decimal number of up to three digits in the range 0 to 255, ``$MASK`` is a subnet mask in the range 0 to 32.
    * - ``not``
    * - ``in``
      - ``{$ADDR/$MASK[,...]}``
    * - :rspan:`2` Destination network
      - :rspan:`2` ``ip4.dnet``
      - ``eq``
      - :rspan:`1` ``$ADDR/$MASK``
    * - ``not``
    * - ``in``
      - ``{$ADDR/$MASK[,...]}``
    * - :rspan:`1` Protocol
      - :rspan:`1` ``ip4.proto``
      - ``eq``
      - :rspan:`1` ``$PROTOCOL``
      - :rspan:`1` ``$PROTOCOL`` must be a transport layer protocol name (e.g. "ICMP", case insensitive), or a valid decimal `internet protocol number`_.
    * - ``not``


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
      - :rspan:`3` ``$ADDR``
      - :rspan:`3` ``$ADDR`` must be an IPv6 address composed of 8 hexadecimal numbers (abbreviations are supported). To filter on an IPv6 network (using an IPv6 address and a subnet mask), see ``ip6.snet`` or ``ip6.dnet``.
    * - ``not``
    * - :rspan:`1` Destination address
      - :rspan:`1` ``ip6.daddr``
      - ``eq``
    * - ``not``
    * - :rspan:`2` Source network
      - :rspan:`2` ``ip6.snet``
      - ``eq``
      - :rspan:`1` ``$ADDR/$MASK``
      - :rspan:`5` ``$ADDR`` must be an IPv6 address composed of 8 hexadecimal numbers (abbreviations are supported), ``$MASK`` is a subnet mask in the range 0 to 128.
    * - ``not``
    * - ``in``
      - ``{$ADDR/$MASK[,...]}``
    * - :rspan:`2` Destination network
      - :rspan:`2` ``ip6.dnet``
      - ``eq``
      - :rspan:`1` ``$ADDR/$MASK``
    * - ``not``
    * - ``in``
      - ``{$ADDR/$MASK[,...]}``
    * - :rspan:`1` Next header
      - :rspan:`1` ``ip6.nexthdr``
      - ``eq``
      - :rspan:`3` ``$NEXT_HEADER``
      - :rspan:`3` ``$NEXT_HEADER`` is a transport layer protocol name (e.g. "ICMP", case insensitive), an IPv6 extension header name, or a valid decimal `internet protocol number`_.
    * - ``not``

.. tip::

    The following IPv6 extension header names are recognized by bpfilter: hop, route, frag, ah, dst, mh.

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
    * - :rspan:`3` Source port
      - :rspan:`3` ``tcp.sport``
      - ``eq``
      - :rspan:`1` ``$PORT``
      - :rspan:`2` ``$PORT`` must be a valid decimal port number.
    * - ``not``
    * - ``in``
      - ``{$PORT[;...]}``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.
    * - :rspan:`3` Destination port
      - :rspan:`3` ``tcp.dport``
      - ``eq``
      - :rspan:`1` ``$PORT``
      - :rspan:`2` ``$PORT`` must be a valid decimal port number.
    * - ``not``
    * - ``in``
      - ``{$PORT[;...]}``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.
    * - :rspan:`3` Flags
      - :rspan:`3` ``tcp.flags``
      - ``eq``
      - :rspan:`3` ``$FLAG[,...]``
      - :rspan:`3` ``$FLAG`` is a comma-separated list of one or more TCP flags (``fin``, ``syn``, ``rst``, ``psh``, ``ack``, ``urg``, ``ece``, or ``cwr``). Flags are case-insensitive.
    * - ``not``
    * - ``any``
    * - ``all``

.. tip::

   The ``tcp.flags`` operators can be confusing, as they can be used to match all, some, or none of the flags available in the TCP header. This section aims to provide clarity to their exact behavior:

   - ``eq``: the TCP header must contain the exact same flags as defined in the rule. The matcher ``tcp.flags eq syn,ack`` will match ``syn,ack``, but not ``syn,ack,fin`` nor ``rst``.
   - ``not``: opposite of ``eq``, the TCP header must not contain the exact same flags as defined in the rule. The matcher ``tcp.flags eq syn,ack`` will match ``syn,ack,fin`` or ``rst``, but not ``syn,ack``.
   - ``any``: the TCP header must contain any of the flags defined in the rule. The matcher ``tcp.flags eq syn,ack`` will match ``syn``, or ``ack``, or ``syn,ack``, but not ``fin``.
   - ``all``: the TCP header must contain at least the flags defined in the rule. The matcher ``tcp.flags all syn,ack`` will match ``syn,ack,fin``, but not ``syn``, or ``ack,fin``.


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
    * - :rspan:`3` Source port
      - :rspan:`3` ``udp.sport``
      - ``eq``
      - :rspan:`1` ``$PORT``
      - :rspan:`2` ``$PORT`` must be a valid decimal port number.
    * - ``not``
    * - ``in``
      - ``{$PORT[;...]}``
    * - ``range``
      - ``$START-$END``
      - ``$START`` and ``$END`` are valid port values, as decimal integers.
    * - :rspan:`3` Destination port
      - :rspan:`3` ``udp.dport``
      - ``eq``
      - :rspan:`1` ``$PORT``
      - :rspan:`2` ``$PORT`` must be a valid decimal port number.
    * - ``not``
    * - ``in``
      - ``{$PORT[;...]}``
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
      - :rspan:`1` ``$TYPE``
      - :rspan:`1` ``$TYPE`` is an ICMP type name (e.g. "echo-reply", case insensitive), or a decimal or hexadecimal `ICMP type value`_.
    * - ``not``
    * - :rspan:`1` Code
      - :rspan:`1` ``icmp.code``
      - ``eq``
      - :rspan:`1` ``$CODE``
      - :rspan:`1` ``$CODE`` is a decimal or hexadecimal `ICMP code value`_.
    * - ``not``

.. tip::

    The following ICMP type name are recognized by bpfilter: echo-reply, destination-unreachable, source-quench, redirect, echo-request, time-exceeded, parameter-problem, timestamp-request, timestamp-reply, info-request, info-reply, address-mask-request, address-mask-reply, router-advertisement, router-solicitation.

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
      - :rspan:`1` ``$TYPE``
      - :rspan:`1` ``$TYPE`` is an ICMPv6 type name (e.g. "echo-reply", case insensitive), or a decimal or hexadecimal `ICMPv6 type value`_.
    * - ``not``
    * - :rspan:`1` Code
      - :rspan:`1` ``icmpv6.code``
      - ``eq``
      - :rspan:`1` ``$CODE``
      - :rspan:`1` ``$CODE`` is a decimal or hexadecimal `ICMPv6 code value`_.
    * - ``not``

.. tip::

    The following ICMPv6 type name are recognized by bpfilter: destination-unreachable, packet-too-big, time-exceeded, echo-request, echo-reply, mld-listener-query, mld-listener-report, mld-listener-reduction, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, parameter-problem, mld2-listener-report.


.. _IEEE 802 number: https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml cli,core: convert meta.l3_proto to new framework)
.. _internet protocol number: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
.. _ICMP type value: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-types
.. _ICMP code value: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml#icmp-parameters-codes
.. _ICMPv6 type value: https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-2
.. _ICMPv6 code value: https://www.iana.org/assignments/icmpv6-parameters/icmpv6-parameters.xhtml#icmpv6-parameters-3
