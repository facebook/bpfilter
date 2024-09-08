Coding style
============

.. warning::

    This document is not yet complete, it will evolve gradually over time. If you are unsure about a specific rule: check ClangFormat's configuration (``.clang-format``), check this document, and check the existing code. If none of those can answer your question, do as you want.

``bpfilter`` coding style is enforced by ClangFormat, as defined in its configuration file ``.clang-format`` at the root of the repository. The ``check`` build target can be used to validate all the source files under ``src``, but the issues won't be resolved automatically: changes performed by ClangFormat should be controlled by a developer.

To format a source file using ClangFormat (from the root of the repository):

.. code:: shell

    clang-format --style=file:.clang-format -i $FILE

.. warning::

    Not all ClangFormat versions are born equal: from a ClangFormat version to another, the behavior of a specific option could change (unfortunately). The proper version of ClangFormat to use with ``bpfilter`` is expected to be the version available in the latest Fedora release.

ClangFormat is not sufficient to define a consistent code style, as its set of configuration option can't cover every use case. Hence, this document should serve as a reference for the code style ClangFormat can't validate.

Comments
--------

Comments are either single-line (``//``) or multi-lines (``/* */``) C comments, reserve single-line comments for comments that fit on a single line, and multi-lines comments for comments that require... multiple lines.

For multi-lines comments: repeat and align the asterisk on each line, avoid empty lines, and close the comment on the last line containing text:

.. code:: c

    /*
        This is a badly formatted multi-lines comment.
    */

    /* This is a properly formatted multi-lines comments, as there is no empty
     * line, and asterisks are aligned. */

The technical documentation is generated from the Doxygen comments in the source files. Not all functions deserve to be documented: there's no point documenting a getter, except wasting space and making the file more difficult to read. A function should be documented when its behavior needs to be explained or clarified (ideally the function is clear enough not to be clarified though), or when its arguments have specific requirements.

Usually, pointer arguments should be expected to be non-NULL, if this expectation differs for a function, it must be documented.

Regarding Doxygen usage:

- For the sake of clarity, a function's multi-lines documentation should have the first and last comment line empty. This is specific to Doxygen comments, for all other use cases, the rule above still stands.
- The first line of a function's documentation should be a brief explanation of its purpose, but ``@brief`` should not be used: ``@brief`` doesn't affect the generated output, avoid using it anywhere to maintain consistency.
- Parameters are tagged with ``@param``. If a parameter's documentation is too long to fit on a single line, indent the next line properly to fit under the parameter's name (see example below).
- Return value (if any) is tagged with ``@return``. The same line break rule applies as to ``@param``.
- Always use the ``@`` version of the Doxygen directives, not the ``\`` one.
- Use ``@ref`` to refer to other symbols from ``bpfilter`` and ``@p`` to refer to external symbols or parameter names.
- Use ``@code{.c}`` and ``@endcode`` to integrate code example. Remember about this, as it's sometimes clearer to have a simple code example than 20 lines of text.

.. code:: c

    /**
     * Get the index and name of all the interfaces on the host.
     *
     * The memory allocated by this function for @p ifaces must be freed by the
     * caller.
     *
     * @param ifaces Array of @ref bf_if_iface structures. The array will be
     *        allocated by the function and the caller is responsible for
     *        freeing it.
     * @return On success, return the number of interfaces contained in
     *         @p ifaces . On failure, return a negative errno value.
     */
