# Copyright (c) Meta Platforms, Inc. and affiliates.
import logging
import pathlib
import re

import jinja2

from .agent_tools import AgentTools
from .api import completion, error_text
from .log import log_message
from .models import Effort, History

_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(pathlib.Path(__file__).parent / "templates"),
    trim_blocks=True,
    lstrip_blocks=True,
    undefined=jinja2.StrictUndefined,
)

MAX_TOOL_ROUNDS = 100
_CGEN_DIR = "src/libbpfilter/cgen"

log = logging.getLogger("bfoptimizer")


def proposal_system_prompt(history: History) -> str:
    return _env.get_template("proposal.j2").render(cgen_dir=_CGEN_DIR, history=history)


def implementation_system_prompt(history: History, failures) -> str:
    return _env.get_template("implementation.j2").render(
        cgen_dir=_CGEN_DIR, history=history, failures=failures
    )


def _system_prompt(history: History) -> str:
    prompt = (
        "You are a performance engineer with a deep understanding of BPF bytecode, "
        "the kernel BPF subsystem, packet filtering, and packet matching. "
        "Use the available tools to inspect the repository and complete the task. "
        "All relative paths and shell commands start at the repository root: "
        f"{history.config.sources_dir.resolve()}. "
        "Do not build, test, or commit. The optimizer handles these steps."
    )
    path = history.config.sources_dir / "AGENTS.md"
    if path.is_file():
        prompt += f"\n\nProject instructions (AGENTS.md):\n{path.read_text()}"
    return prompt


async def _request(
    history: History, model: str, messages: list[dict], effort: Effort, **options
) -> dict:
    """Send one completion request, count its cost, and return its message."""

    attempt = history.current_attempt
    if attempt is None:
        raise RuntimeError("model queried, but no Attempt in progress")

    response = await completion(
        model, messages, reasoning={"effort": effort.value}, **options
    )
    attempt.cost += (response.get("usage") or {}).get("cost") or 0.0
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise RuntimeError("OpenRouter returned no assistant message")

    choice = choices[0]
    if choice.get("error"):
        raise RuntimeError(f"OpenRouter provider error: {error_text(choice['error'])}")
    if not isinstance(choice.get("message"), dict):
        raise RuntimeError("OpenRouter returned no assistant message")

    # Some providers leave finish_reason empty on complete responses.
    if choice.get("finish_reason") not in {"stop", "tool_calls", None}:
        raise RuntimeError(f"OpenRouter completion failed: {choice['finish_reason']}")

    return choice["message"]


async def _query(
    history: History, prompt: str, model: str, *, writable: bool = False
) -> str | None:
    """Run the tool loop, preserving provider reasoning and tracking every request."""

    tools = AgentTools(history.config.sources_dir, _CGEN_DIR, writable=writable)
    messages = [
        {"role": "system", "content": _system_prompt(history)},
        {"role": "user", "content": prompt},
    ]

    for _ in range(MAX_TOOL_ROUNDS):
        message = await _request(
            history,
            model,
            messages,
            history.config.effort,
            tools=tools.definitions,
            # Each round resends the whole conversation, which Anthropic
            # models only cache when asked to.
            cache_control={"type": "ephemeral"},
        )
        log_message(message)

        calls = message.get("tool_calls") or []
        if not calls:
            return message.get("content") or None

        # Echo reasoning_details verbatim, including encrypted provider state.
        messages.append(message)
        for call in calls:
            function = call["function"]
            result = await tools.execute(function["name"], function["arguments"])
            messages.append(
                {"role": "tool", "tool_call_id": call["id"], "content": result}
            )

    raise RuntimeError(f"OpenRouter agent exceeded {MAX_TOOL_ROUNDS} rounds")


async def query_proposal(history: History) -> None:
    log.info("Requesting the proposal")
    plan = await _query(
        history, proposal_system_prompt(history), history.config.proposal_model
    )
    attempt = history.current_attempt
    attempt.plan = plan or ""
    if attempt.plan:
        log.info(f"Proposal complete (total cost ${attempt.cost:.2f})")


async def query_implementation(history: History, failures) -> None:
    log.info("Requesting the implementation")

    # The final message is not needed: the edits are already on disk, and the
    # build and tests decide whether they are valid.
    await _query(
        history,
        implementation_system_prompt(history, failures),
        history.config.impl_model,
        writable=True,
    )

    log.info(
        f"Implementation completed (total cost ${history.current_attempt.cost:.2f})"
    )


_COMMIT_LABEL = re.compile(r"^(subject|body):\s*", re.IGNORECASE)


def _commit_message(text: str) -> str:
    """Remove the Markdown fence and labels that a model may add."""
    lines = text.strip().splitlines()
    if len(lines) > 1 and lines[0].startswith("```") and lines[-1] == "```":
        lines = lines[1:-1]
    lines = [_COMMIT_LABEL.sub("", line) for line in lines]
    subject, _, body = "\n".join(lines).strip().partition("\n")
    return f"{subject.strip()}\n\n{body.strip()}".strip()


async def generate_commit_message(history: History, plan: str, diff: str) -> str:
    # No max_tokens: reasoning counts against it, and could leave no room for
    # the message itself.
    message = await _request(
        history,
        history.config.commit_model,
        [
            {
                "role": "user",
                "content": f"""Generate a git commit message for this change to the bpfilter project.

Return only the commit message as plain text: the subject line, a blank line,
then the body. Do not add labels, Markdown fences, or commentary.

The subject line follows `component: subcomponent: short description`:
- Components: lib, cli, tests, build, tools, doc
- Subcomponents examples: cgen, matcher, chain, rule, hook
- Lowercase, imperative mood, no period, ≤72 chars total
- Describe WHY the change improves things, not what lines changed

The body has 2-4 sentences explaining the intent behind the change and why it
improves the generated BPF programs. Wrap lines at 72 characters. Do not
repeat the subject or describe the diff line by line.

Plan (intent):
{plan}

Diff:
{diff}
""",
            }
        ],
        Effort.LOW,
    )

    text = _commit_message(message.get("content") or "")
    if not text:
        raise RuntimeError("OpenRouter returned an empty commit message")

    return text
