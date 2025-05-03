Modules
=======

.. toctree::
   :maxdepth: 2
   :caption: Modules

   core
   bpfilter
   xlate/index
   lib

``bpfilter`` is composed of multiple modules depending on each other. Splitting the project in different modules allows for the source code to be efficiently reused, be it for ``bfcli``, ``bpfilter``'s daemon, or ``libbpfilter``:

- ``core``: core definitions used by the daemon, ``bfcli``, and ``libbpfilter``.
- ``bpfilter``: daemon logic, including translation of the front-end (client) data into ``bpfilter``'s internal format, and the BPF bytecode generation logic.
- ``bfcli``: generic client to communicate with the daemon.
- ``libbpfilter``: static and shared library to communicate with the daemon.
- ``external``: non-``bpfilter`` code, imported into the project to provide consistent external definitions.
