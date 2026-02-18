Contributing
============

If you want to start contributing to bpfilter, the best way to get to know the codebase would be to start with one of the ``@todo`` available in the code. Most of those tasks are small, self-contained, work trivial enough that they do not deserve their GitHub issue.

Once you know your way around the structure of the project, feel free to continue with the ``@todo``, or jump on a bigger issue in the `GitHub issues tracker <https://github.com/facebook/bpfilter/issues>`_.

You are welcome to reach out to qde@naccy.de if you need help, or have any question!


To do
-----

* Remove the RPM ``x86_64`` macro `workaround <https://pagure.io/epel/issue/325>`_ from the Fedora ``bpfilter.spec``.
* Gate the documentation generate in Fedora's ``bpfilter.spec`` with a ``bcond``.
* Add support for CMake 4.0 and ``ninja``.
* Handle extra characters in the lexer (currently, any non-matched token will be printed to ``stdout``).
* Add support for missing matcher operators (e.g. ``meta.l4_proto not``).
* Add a Fedora 43 build in the CI.


From the code
~~~~~~~~~~~~~

.. doxygenpage:: todo
