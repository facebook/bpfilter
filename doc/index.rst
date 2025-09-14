
.. toctree::
   :hidden:
   :maxdepth: 2
   :caption: Users

   Overview <self>
   usage/index

.. toctree::
   :hidden:
   :maxdepth: 2
   :caption: Developers

   developers/build
   developers/style
   developers/modules/index
   developers/packets_processing
   developers/generation
   developers/tests

.. toctree::
   :hidden:
   :caption: External

   GitHub repository <https://github.com/facebook/bpfilter>
   external/benchmarks/index
   external/coverage/index

|
|

.. raw:: html

   <h5 align="center">An <a href="https://ebpf.io/">eBPF</a>-based packet filtering framework.</h5>

|

**bpfilter** transforms how you control network traffic by leveraging the power of eBPF technology. This framework elegantly translates filtering rules into optimized BPF programs, bringing unparalleled performance and flexibility to your packet filtering needs.

|

.. image:: _static/demo_light.gif
   :class: only-light
   :align: center
   :width: 600

.. image:: _static/demo_dark.gif
   :class: only-dark
   :align: center
   :width: 600

|

.. raw:: html

   <h5>Key features</h5>

- **High performance**: utilizes eBPF's near-native performance capabilities
- **Flexible integration**: use the custom ``iptables`` integration or **bpfilter**'s ``bfcli`` command line for extended functionalities
- **Low overhead**: minimal resource consumption with maximized efficiency
- **Developer-friendly**: clean architecture with clear separation of components

**bpfilter** combines three components: a CLI that allows users to define filtering rules in human-readable text, a daemon that converts these rules into efficient BPF programs, and a library that facilitates seamless communication between applications and the filtering subsystem.

Want to know more about **bpfilter**? Check the :doc:`user's guide <usage/index>`, the :doc:`developer documentation <developers/build>`, or watch our talk at `Scale <https://www.youtube.com/watch?v=fzaPEm4PXn0>`_!
