Modules
=======

.. toctree::
   :maxdepth: 2
   :caption: Modules

   libbpfilter/libbpfilter

``bpfilter`` is composed of multiple modules depending on each other. Splitting the project in different modules allows for the source code to be efficiently reused:

- ``core``: core definitions used by ``bfcli`` and ``libbpfilter``.
- ``libbpfilter``: core library containing all filtering logic, BPF code generation, and program lifecycle management.
- ``bfcli``: CLI tool for defining and managing filtering rules via ``libbpfilter``.
- ``external``: non-``bpfilter`` code, imported into the project to provide consistent external definitions.
