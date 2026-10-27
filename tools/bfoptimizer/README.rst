bfoptimizer
===========

bfoptimizer uses OpenRouter to propose and implement BPF optimizations. It
builds and tests each change, commits it, and keeps improvements after
benchmarking.

Setup
-----

Install the Python dependencies::

    python3 -m pip install GitPython diskcache jinja2 numpy paramiko pint rich textual textual-plot

Install Bash and ripgrep for the agent's shell and search tools. The source
checkout also needs the usual bpfilter build and benchmark dependencies.
Neither the Anthropic SDK nor the Claude Agent SDK is required.

Set ``OPENROUTER_API_KEY`` in your environment. Run from the repository root::

    python3 -m tools.bfoptimizer --sources-dir /path/to/clean/bpfilter

The source checkout must have no uncommitted or untracked files. bfoptimizer
commits validated changes and resets failed attempts to their starting commit.

Models
------

Pass OpenRouter model IDs directly. A new model needs no code change::

    python3 -m tools.bfoptimizer \
        --proposal-model anthropic/claude-opus-5.5 \
        --impl-model anthropic/claude-sonnet-5.5 \
        --commit-model anthropic/claude-haiku-5.5 \
        --effort high

The proposal and implementation models default to
``anthropic/claude-opus-5.5``. The commit model defaults to the implementation
model. Proposal and implementation models must support tool calling. Commit
messages use plain text, so the commit model does not need structured outputs.

At startup, bfoptimizer checks each model ID against OpenRouter's public model
list, and checks that the proposal and implementation models support tool
calling. An ID can also use an OpenRouter preset, which is a configuration
saved in the OpenRouter web app. ``@preset/name`` alone is not checked,
because the preset selects the model. ``vendor/model@preset/name`` is
checked as ``vendor/model``.

``--effort`` accepts ``low``, ``medium``, ``high``, ``xhigh``, and ``max``.
bfoptimizer sends this as OpenRouter's unified ``reasoning.effort`` parameter.
Support and interpretation depend on the model and provider. Commit messages
use ``low`` effort and no ``max_tokens``: reasoning tokens count against that
limit, and a small one could leave no room for the message.

The displayed cost is the sum of OpenRouter's ``usage.cost`` field over every
request, commit messages included. It misses responses that time out, because
OpenRouter still bills them but bfoptimizer never receives their usage.

Agent behavior
--------------

Each phase has a limit of 100 model responses. The agent can read files, search
with ripgrep, list files with glob patterns, and execute Bash commands. The
implementation phase also exposes exact text edits and file writes under
``src/libbpfilter/cgen/``. Relative paths and shell commands start at the
repository root. The root ``AGENTS.md`` instructions are included when present.
``CLAUDE.md`` and ``CLAUDE.local.md`` are not.

The proposal prompt prohibits writes. Bash runs with the invoking user's
permissions in both phases. The file tool restrictions do not sandbox Bash.
Commands get no standard input and no ``OPENROUTER_API_KEY``, because their
output goes to the model provider.

Shell commands time out after 120 seconds. Tool output is truncated at 32,000
characters. Read returns up to 2,000 lines and ends with the offset to continue
from. Grep and Glob skip ignored files, such as the build directory. Tools
reject the arguments they do not support.

bfoptimizer retries rate limits, server errors, and network failures up to 6
times, with an exponential backoff that honors ``Retry-After``. Responses are
not streamed, so a response must arrive within 30 minutes. A response that
times out is not retried: OpenRouter keeps generating and billing it, and a
retry would likely pay for the same slow generation again. Other API failures
and exhausted response limits fail the attempt through the existing reset path.

Requests in the tool loop set a top-level ``cache_control``, which Anthropic
models need to cache the conversation from one tool round to the next.

The loop preserves reasoning details between tool calls. It does not provide
the Claude Agent SDK's context compaction, subagents, or session management.
Choose a model with enough context for the source files and tool results.

References
----------

See OpenRouter's documentation on `tool calling`_, `reasoning tokens`_, and
`prompt caching`_ for model requirements and parameter behavior.

.. _tool calling: https://openrouter.ai/docs/guides/features/tool-calling
.. _reasoning tokens: https://openrouter.ai/docs/guides/best-practices/reasoning-tokens
.. _prompt caching: https://openrouter.ai/docs/guides/best-practices/prompt-caching
