Your first filtering chain
==========================

This tutorial will block ``ping`` requests sent to the local host: we will create a chain, check that it did its job, then remove it. Everything happens on the loopback interface, so you don't need a remote server.

From here on, we assume bpfilter is :doc:`installed <../how-to/install>` on your system, and that you can use ``sudo``. If you built it locally, you will need to substitute the ``bfcli`` command with ``$BUILD_DIRECTORY/output/sbin/bfcli``.

We will create a chain named ``tutorial_ping``, attached to Netfilter with the priorities ``101-102``. If you already use bpfilter on this machine, run ``sudo bfcli ruleset get`` first to check that this name and those priorities are not used by another chain.

Can we ping now?
----------------

Let's check if we can ping the local host before we do anything:

.. code-block:: shell

    $ ping -n -c 3 -W 1 127.0.0.1
    PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
    64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.017 ms
    64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.021 ms
    64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.018 ms

    --- 127.0.0.1 ping statistics ---
    3 packets transmitted, 3 received, 0% packet loss, time 2049ms
    rtt min/avg/max/mdev = 0.017/0.018/0.021/0.001 ms

Create a filtering rule
-----------------------

Use ``bfcli`` to create a filtering chain. A chain is a set of rules to filter packets on. Write the following in ``tutorial_ping.bf``:

.. code-block:: text

    chain tutorial_ping BF_HOOK_NF_LOCAL_OUT{priorities=101-102} ACCEPT
        rule
            ip4.daddr eq 127.0.0.1
            ip4.proto eq icmp
            icmp.type eq echo-request
            counter
            DROP

We choose to attach our chain to ``BF_HOOK_NF_LOCAL_OUT``, which sees the packets sent by the local host, with ``ACCEPT`` as the default policy: if a packet doesn't match any of the rules defined, it will be accepted by default.

Our chain contains a single rule, matching the ``ping`` requests sent to ``127.0.0.1``. Packets matching this rule will be counted, then dropped.

Before we apply it, let's ask ``bfcli`` to validate our chain:

.. code-block:: shell

    $ bfcli chain set --from-file tutorial_ping.bf --dry-run
    info   : --dry-run used, chain not set

No error? Then we can apply it for real:

.. code-block:: shell

    $ sudo bfcli chain set --from-file tutorial_ping.bf

The options between braces tell bpfilter where to attach the chain: without them, the chain would be loaded, but it wouldn't filter anything. ``chain set`` only replaces the chain with the same name, so your other chains (if any) are left untouched.

Can we still ping?
------------------

Now that our filtering rule is in place, pings to the local host should be blocked. Let's check this out:

.. code-block:: shell

    $ ping -n -c 3 -W 1 127.0.0.1
    PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.

    --- 127.0.0.1 ping statistics ---
    3 packets transmitted, 0 received, 100% packet loss, time 2030ms

100% packet loss? That's great news! Depending on your version of ``ping``, you might also see an error for each request it failed to send. Let's see if this is bpfilter's doing:

.. code-block:: shell

    $ sudo bfcli chain get --name tutorial_ping
    chain tutorial_ping BF_HOOK_NF_LOCAL_OUT{priorities=101-102} ACCEPT
        counters policy 1 packets 90 bytes; error 0 packets 0 bytes
        rule
            ip4.daddr eq 127.0.0.1
            ip4.proto eq icmp
            icmp.type eq echo-request
            counters 3 packets 294 bytes
            DROP

Our rule matched 3 packets: the 3 requests we just sent. The policy counters will be different on your machine, as they count every other packet sent by the host.

Clean up
--------

We don't want to block pings forever, so let's remove our chain and check that ``ping`` works again:

.. code-block:: shell

    $ sudo bfcli chain flush --name tutorial_ping
    $ ping -n -c 3 -W 1 127.0.0.1
    PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
    64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.026 ms
    64 bytes from 127.0.0.1: icmp_seq=2 ttl=64 time=0.031 ms
    64 bytes from 127.0.0.1: icmp_seq=3 ttl=64 time=0.037 ms

    --- 127.0.0.1 ping statistics ---
    3 packets transmitted, 3 received, 0% packet loss, time 2055ms
    rtt min/avg/max/mdev = 0.026/0.031/0.037/0.004 ms

The replies are back! You can now delete ``tutorial_ping.bf``.

If you are eager to learn more ways to filter traffic using ``bfcli``, check how to :doc:`block traffic from selected addresses <../how-to/block-addresses>`, or read about :doc:`rule evaluation <../explanation/rule-evaluation>` to understand how matchers, verdicts, and policies work together.
