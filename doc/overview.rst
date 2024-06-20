Overview
========

Command line options
--------------------

The bpfilter daemon must be run as root in order to write to `/run` and manipulate BPF programs. It supports the following arguments:

- ``-t``, ``--transient``: if used, ``bpfilter`` won't pin any BPF program or map, and no data will be serialized to the filesystem. Hence, as soon as the daemon is stopped, the loaded BPF programs and maps will be removed from the system.
- ``--no-iptables``: disable ``iptables`` support. If ``iptables`` is enabled, ``bpfilter`` will create pass-through programs to represent the ``INPUT``, ``OUTPUT``, and ``FORWARD`` hook used by ``iptables``, with ``ACCEPT`` as the default policy. If ``iptables`` support is disabled, no BPF program will be generated for ``iptables`` and ``bpfilter`` will answer to every request coming from ``iptables`` with a failure response.
- ``-b``, ``--buffer-len=BUF_LEN_POW``: size of the ``BPF_PROG_LOAD`` buffer as a power of 2. Only available if ``--verbose`` is used. ``BPF_PROG_LOAD`` system call can be provided a buffer for the BPF verifier to provide details in case the program can't be loaded. The required size for the buffer being hardly predictable, this option allows for the user to control it. The final buffer will have a size of ``1 << BUF_LEN_POWER``.
- ``-v``, ``--verbose``: print more detailed log messages.
- ``--usage``: print a short usage message.
- ``-?``, ``--help``: print the help message

``bpfilter`` on the system
--------------------------

Unless ``bpfilter`` is run in transient mode (``--transient``), it will create a new ``/run/bpfilter`` directory if it doesn't exist in order to store its socket file to listen on. This directory contains the serialized rulesets, allowing ``bpfilter`` to restore its internal state and keep track of its BPF program if the daemon is restarted.

``bpfilter`` will use ``/run/bpfilter`` to store its runtime environment, as well as a serialized version of the current rulesets.
