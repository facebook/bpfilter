The daemon
==========

The ``bpfilter`` daemon is responsible for creating the BPF program corresponding to the user-provided filtering rules. The daemon will also load and manage the BPF programs on the system.

It is possible to customize the daemon's behavior using the following command-line flags:

- ``-t``, ``--transient``: if used, ``bpfilter`` won't pin any BPF program or map, and no data will be serialized to the filesystem. Hence, as soon as the daemon is stopped, the loaded BPF programs and maps will be removed from the system.
- ``--no-cli``: disable ``bfcli`` support.
- ``--no-nftables``: disable ``nftables`` support.
- ``--no-iptables``: disable ``iptables`` support.
- ``--with-bpf-token``: if set, the daemon will associate a BPF token to every ``bpf()`` system call. This is required when the daemon runs in user namespaces. The daemon will create the token from the bpffs mounted at ``/sys/fs/bpf``. The user is responsible for configuring the file system, so a token can be created. Only supported for kernel v6.9+, if the current kernel doesn't support BPF token, the daemon will stop with a non-zero exit code.
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
