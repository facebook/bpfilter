``bpfilter``
============

.. toctree::
   :hidden:
   :maxdepth: 2
   :caption: Users

   overview
   build

.. toctree::
   :hidden:
   :maxdepth: 2
   :caption: Developers

   developers/packets_processing
   developers/generation
   developers/fronts/index
   reference

``bpfilter`` is a BPF-based packet filtering framework. It is composed of a shared library (``libbpfilter``) and a daemon (``bpfilter``).

The ``bpfilter`` daemon running on the system receives a request from a client (``iptables``, ``nftables``, or any other client that could be created) and converts the client-provided ruleset into one or more BPF program(s).

If you want to try ``bpfilter`` with ``nftables`` or ``iptables``, have a look at :doc:`build`.

If you want to know more about ``bpfilter``'s internals, take a look at the following talks about the project:

* `BPF and firewall: kernel support to ease more complex packets filtering (LSFMMBPF 2023) <https://www.youtube.com/watch?v=UDZhCubE-Kk&list=PLbzoR-pLrL6rlmdpJ3-oMgU_zxc1wAhjS&index=47>`_
* `bpfilter: a BPF-based packet filtering framework (All Systems Go 2023) <https://media.ccc.de/v/all-systems-go-2023-196-bpfilter-a-bpf-based-packet-filtering-framework>`_
* `bpfilter: a BPF-based packet filtering framework (Linux Plumbers Conference 2023) <https://www.youtube.com/watch?v=J5Hm6PrJWI4&t=27649s>`_
