Usage
=====

.. toctree::
   :hidden:
   :maxdepth: 2
   :caption: Usage

   bfcli


``bpfilter`` is composed of two main parts: ``libbpfilter``, the core library that generates and manages BPF programs, and ``bfcli``, the CLI used to define filtering rules. ``bfcli`` calls ``libbpfilter`` directly to translate rules into BPF programs and load them into the kernel.

See :doc:`bfcli` for the full command reference and filter syntax.

Install
-------

**bpfilter** is packaged for Fedora 40+, EPEL 9+ and supports Fedora 40+, CentOS Stream 9+, and Ubuntu 24.04+.

.. code-block:: bash

	> sudo dnf install -y bpfilter

If you use a different distribution, you can still build and use **bpfilter** if you satisfy the requirements, see the :doc:`developer documentation <../developers/build>`.


Example usage
-------------

From here on, we assume **bpfilter** has been installed on your system. If you build it locally, you will need to substitute the ``bfcli`` command with ``$BUILD_DIR/output/bin/bfcli``. The example below is meant to familiarize you with **bpfilter**, more in-depth information can be found throughout the documentation.

This example will block ``ping`` requests sent going out of the local host to a remote server.

**Can we ping now?**

Let's check if we can ping ``facebook.com`` before we do anything:

.. code-block:: bash

	$ ping -n -c 4 facebook.com
	PING facebook.com (157.240.253.35) 56(84) bytes of data.
	64 bytes from 157.240.253.35: icmp_seq=1 ttl=128 time=24.9 ms
	64 bytes from 157.240.253.35: icmp_seq=2 ttl=128 time=23.6 ms
	64 bytes from 157.240.253.35: icmp_seq=3 ttl=128 time=28.6 ms
	64 bytes from 157.240.253.35: icmp_seq=4 ttl=128 time=24.8 ms

	--- facebook.com ping statistics ---
	4 packets transmitted, 4 received, 0% packet loss, time 3001ms
	rtt min/avg/max/mdev = 23.596/25.493/28.622/1.880 ms


**Create a new filtering rule**

Use ``bfcli`` to create a filtering chain. A chain is a set of rules to filter packets on:

.. code-block:: bash

	$ sudo bfcli ruleset set --from-str "
        chain my_chain BF_HOOK_XDP{ifindex=$IFINDEX} ACCEPT
            rule
                ip4.proto eq icmp
                counter
                DROP
	"

We split the chain over multiple lines, so it's easier to read. Alternatively, you can write the chain in a file and call ``bfcli ruleset set --from-file $MYFILE``. We choose to create a chain attached to ``BF_HOOK_XDP`` with ``ACCEPT`` as the default policy: if a packet doesn't match any of the rules defined, it will be accepted by default.

Our chain contains a single rule matching against the IPv4's ``protocol`` field. Packets matching this rule will be ``DROP`` ed.

**Can we still ping?**

Now that our filtering rule is in place, pings to ``facebook.com`` should be blocked, let's check this out:

.. code-block:: bash

	$ ping -n -c 4 facebook.com
	PING facebook.com (157.240.253.35) 56(84) bytes of data.

	--- facebook.com ping statistics ---
	4 packets transmitted, 0 received, 100% packet loss, time 3010ms


100% packet loss? That's great news! Let's see if this is bpfilter's doing:

.. code-block:: bash

    $ sudo bfcli ruleset get
    chain my_chain BF_HOOK_XDP{ifindex=2} ACCEPT
        counters policy 12942 packets 12436391 bytes; error 0 packets 0 bytes
        rule
            ip4.proto eq icmp
            counters 4 packets 392 bytes
            DROP

If you are eager to learn more ways to filter traffic using **bfcli**, check its :doc:`documentation <bfcli>`.
