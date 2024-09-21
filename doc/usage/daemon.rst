The daemon
==========

The ``bpfilter`` daemon is responsible for creating the BPF program corresponding to the user-provided filtering rules. The daemon will also load and manage the BPF programs on the system.

It is possible to customize the daemon's behavior using the following command-line flags:

- ``-t``, ``--transient``: if used, ``bpfilter`` won't pin any BPF program or map, and no data will be serialized to the filesystem. Hence, as soon as the daemon is stopped, the loaded BPF programs and maps will be removed from the system.
- ``--no-cli``: disable ``bfcli`` support.
- ``--no-nftables``: disable ``nftables`` support.
- ``--no-iptables``: disable ``iptables`` support.
- ``-b``, ``--buffer-len=BUF_LEN_POW``: size of the ``BPF_PROG_LOAD`` buffer as a power of 2. Only available if ``--verbose`` is used. ``BPF_PROG_LOAD`` system call can be provided a buffer for the BPF verifier to provide details in case the program can't be loaded. The required size for the buffer being hardly predictable, this option allows for the user to control it. The final buffer will have a size of ``1 << BUF_LEN_POWER``.
- ``-v``, ``--verbose``: print more detailed log messages.
- ``--debug``: generate the BPF programs in debug mode: if a call to a kfunc or a BPF helper fails, a log message will be printed to ``/sys/kernel/debug/tracing/trace_pipe``.
- ``--usage``: print a short usage message.
- ``-?``, ``--help``: print the help message.
