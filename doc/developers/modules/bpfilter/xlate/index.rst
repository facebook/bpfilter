xlate
=====

``xlate`` (``src/bpfilter/xlate``) is the translation layer between a source format (e.g. sent by ``iptables``) to ``bpfilter``'s internal format. That translation is performed by components called "front-end".

See the documentation for the following front-ends:

.. toctree::
   :maxdepth: 1

   ipt
   nft
