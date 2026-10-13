Where filtering happens
=======================

A hook is a location in the kernel where a chain can be attached to filter packets. Which one should you use? It depends on what you want to filter: each hook sees different packets, gives access to different data, and supports different verdicts. Hence, the same rule can behave differently depending on the hook its chain is attached to.

On an interface: XDP and TC
---------------------------

XDP and TC chains are attached to a network interface, defined by its index. XDP is the first hook to see a packet received by the interface, before the kernel's network stack processes it. TC ingress comes a bit later, and TC egress sees the packets leaving through the interface.

Let's take ``ping`` as an example: the request leaves the host, and the reply comes back in. A chain attached to XDP only sees incoming packets, so it can drop the reply, but the request is long gone. If you want to stop the request itself, use TC egress or Netfilter's local output hook.

Both XDP and TC can redirect a packet to another interface, with different constraints (see :doc:`../reference/rules`). On TC, ``NEXT`` lets the next BPF program attached to the interface decide what to do with the packet. Don't mix it up with ``CONTINUE``, which moves on to the next rule of the same chain.

Along the network stack: Netfilter
----------------------------------

Netfilter chains are not attached to an interface: they follow the packet through the network stack of the host.

- **Pre-routing**: incoming packets, before the routing decision.
- **Local input**: packets sent to the local host.
- **Forward**: packets routed through the host.
- **Local output**: packets sent by the local host.
- **Post-routing**: outgoing packets, after the routing decision.

Instead of an interface index, a Netfilter chain needs priorities, and it needs two of them: this is how bpfilter is able to update the chain atomically. The chain will be attached to both the IPv4 and IPv6 families: your matchers decide which packets the rules apply to.

For a group of processes: cgroups
---------------------------------

Cgroup chains are attached to a cgroup, defined by its path, and only see the traffic of the processes in this cgroup. There are two types of cgroup hooks:

- ``BF_HOOK_CGROUP_SKB_*`` hooks filter the packets received (ingress) or sent (egress) by these processes.
- ``BF_HOOK_CGROUP_SOCK_ADDR_*`` hooks don't filter packets: they are called when a process connects a socket, or sends a UDP datagram.

The ``BF_HOOK_CGROUP_SOCK_ADDR_*`` hooks are a good fit if what matters is which process talks to whom. They know about the process and the socket, but as there is no packet, few matchers are available, and you can't log packet headers or redirect anything.

Long story short: choose your hook depending on the direction of the traffic, the interface or processes you target, and the matchers and verdicts your rules need. :doc:`../reference/hooks` contains the list of hooks with their options and restrictions, and :doc:`../how-to/block-addresses` shows an example using TC ingress.
