The daemon
==========

The ``bpfilter`` daemon is responsible for creating the BPF program corresponding to the user-provided filtering rules. The daemon will also load and manage the BPF programs on the system.

It is possible to customize the daemon's behavior using the following command-line flags:

- ``-t``, ``--transient``: if used, ``bpfilter`` won't pin any BPF program or map, and no data will be serialized to the filesystem. Hence, as soon as the daemon is stopped, the loaded BPF programs and maps will be removed from the system.
- ``--no-cli``: disable ``bfcli`` support.
- ``--no-nftables``: disable ``nftables`` support.
- ``--no-iptables``: disable ``iptables`` support.
- ``-b``, ``--buffer-len=BUF_LEN_POW``: size of the ``BPF_PROG_LOAD`` buffer as a power of 2. Only available if ``--verbose`` is used. ``BPF_PROG_LOAD`` system call can be provided a buffer for the BPF verifier to provide details in case the program can't be loaded. The required size for the buffer being hardly predictable, this option allows for the user to control it. The final buffer will have a size of ``1 << BUF_LEN_POWER``.
- ``-v=VERBOSE_FLAG``, ``--verbose=VERBOSE_FLAG``: enable verbose logs for ``VERBOSE_FLAG``. Currently, 3 verbose flags are supported:

  - ``debug``: enable all the debug logs in the application.
  - ``bpf``: insert log messages into the BPF programs to log failed kernel function calls. Those messages can be printed with ``bpftool prog tracelog`` or ``cat /sys/kernel/debug/tracing/trace_pipe``.
  - ``bytecode``: dump a program's bytecode before loading it.

- ``--usage``: print a short usage message.
- ``-?``, ``--help``: print the help message.


Runtime data
------------

``bpfilter`` runtime data is located in two different directories:

- ``/run/bpfilter``: runtime context. Contains the socket used to communicate with the daemon, and the serialized data (except in ``--transient`` mode).
- ``/sys/fs/bpf/bpfilter``: directory used to pin the BPF objects (except in ``--transient`` mode) so they persist across restarts of the daemon.

.. warning::
    If ``bpfilter`` fails to restore its state after restarting, its data can be cleanup up by removing both those directories. Doing so will remove all your filtering rules.

Namespaces
----------

``bpfilter`` supports the network and mount Linux namespaces. The daemon will automatically switch to the client's namespace before attaching a BPF program, so it is guaranteed to have the same view of the system as the client.

The network namespace will define the available interface indexes to attach the XDP and TC chains, as well as the interface indexes to filter packets on.

The mount namespace is required to ensure the daemon will attach a CGroup chain to the proper CGroup.
