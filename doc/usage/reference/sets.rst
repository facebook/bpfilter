Sets
====

A set defines a group of data of the same type. At runtime, the chain will check if the corresponding packet data is in the set, instead of checking against every single value from the set, which makes it much faster.

Let's say you want to filter 1000 different IPv4 addresses. You can either define 1000 rules, each with its own ``ip4.saddr eq $IP`` matcher, in which case bpfilter will compare the packet against every IP one after the other. Or you can use ``(ip4.saddr) in {$IP0; $IP1; ...}``, in which case bpfilter will compare the packet's data against the hashed set as a whole, in 1 operation.

There are multiple ways to define sets in your ruleset. bpfilter supports named and anonymous sets:

.. code:: shell

    set $NAME $KEY [min-size=$MIN_SIZE] in {
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
  - ``$NAME``: name of the set, for named sets. Allows users to define a set before the rules in a chain, then use it in multiple rules. Sets defined directly in a rule are anonymous, they can't be reused in a different rule. When using a named set, the key used in the rule to refer to the set must be the same as the key used to define the set.
  - ``$KEY``: the set's key, which is the format of the data stored in the set. Keys are defined as ``($MATCHER_0 [, $MATCHERS...])``. This instructs bpfilter that the key is formed from the payload of the list matchers. For example, ``(ip4.saddr, ip4.proto)`` describes the key as the source IPv4 address followed by the IPv4 protocol field. Each matcher defined in the key is called a "component". Parentheses are required even if the key contains a single component. A key can contain up to 8 components.
  - ``$ELEMENT``: elements are the data to store in the set, each component of the key should have a corresponding value in each element. Components of an element are comma-separated, elements themselves are delimited by semicolon or new line.
  - ``$MIN_SIZE``: optional minimum capacity of the set, for named sets. The set's BPF map is created with room for at least ``$MIN_SIZE`` elements, so the set can be grown up to that many elements with ``bfcli chain update-set``. This is a lower bound, not a limit: a set containing more than ``$MIN_SIZE`` elements gets a map sized for its content. ``min-size=0`` is the default behavior.

The following matchers can be used as key components: ``meta.sport``, ``meta.dport``, ``meta.pid``, ``ip4.saddr``, ``ip4.daddr``, ``ip4.snet``, ``ip4.dnet``, ``ip4.proto``, ``ip6.saddr``, ``ip6.daddr``, ``ip6.snet``, ``ip6.dnet``, ``ip6.nexthdr``, ``tcp.sport``, ``tcp.dport``, ``udp.sport``, ``udp.dport``, ``icmp.type``, ``icmp.code``, ``icmpv6.type``, and ``icmpv6.code``. Each component must also be supported by the chain's hook (see :doc:`hooks`). The elements use the same format as the payload of the corresponding matcher (see :doc:`matchers`).

Here is an example:

.. code:: shell

    set dns (ip4.saddr) in { 1.1.1.1; 1.0.0.1 }

    # Reserve room for 1024 addresses, to be added with 'chain update-set'
    set blocklist (ip4.saddr) min-size=1024 in { 192.0.2.1 }

    rule
        (ip4.saddr) in dns
        counter
        ACCEPT

    rule
        (ip4.saddr, ip4.proto) in {
            192.168.1.1, tcp
            192.168.1.10, udp
        }
        ACCEPT

Port ranges
-----------

Sets with a single port component (``tcp.sport``, ``tcp.dport``, ``udp.sport``, ``udp.dport``, ``meta.sport`` or ``meta.dport``) support inclusive ranges written as ``START-END``. Both bounds must be between 0 and 65535, and the start must not exceed the end.

Ranges can appear anywhere in the set and can be mixed with individual ports. For example:

.. code:: shell

    set ports (tcp.dport) in { 11; 22; 27-30 }

This is equivalent to:

.. code:: shell

    set ports (tcp.dport) in { 11; 22; 27; 28; 29; 30 }

Port ranges are not supported in multi-component set keys. For example, ``(ip4.saddr, tcp.dport) in { 192.168.1.1, 80-82 }`` is rejected.

.. warning::

    While the IPv4 and IPv6 ``snet`` and ``dnet`` matchers are supported in sets, they cannot be mixed with other matchers. A set key can be a single ``ip4.snet``, ``ip4.dnet``, ``ip6.snet``, ``ip6.dnet``, or a combination of non-network matchers.

If you want to change the content of a named set without replacing its chain, see :doc:`../how-to/update-blocklist`.
