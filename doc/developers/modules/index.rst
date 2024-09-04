Modules
=======

.. toctree::
   :maxdepth: 2
   :caption: Modules

   daemon

``bpfilter`` is composed of multiple modules depending on each other. Splitting the project in different modules allows for the source code to be efficiently reused, be it for ``bfcli``, ``bpfilter``'s daemon, or ``libbpfilter``:

- ``core``: core definitions used by the daemon, ``bfcli``, and ``libpfilter``.
- ``daemon``: daemon-specific logic, including translation of the front-end (client) data into ``bpfilter``'s internal format, and the BPF bytecode generation logic.
- ``cli``: ``bfcli`` sources and ruleset parsing.
- ``lib``: ``libbpfilter`` sources, used to be both the static and the shared version of the library.
- ``external``: non-``bpfilter`` code, imported into the project to provide consistent external definitions.