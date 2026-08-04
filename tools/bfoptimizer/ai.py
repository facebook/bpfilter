# Copyright (c) Meta Platforms, Inc. and affiliates.
import functools
import json
import logging
import pathlib

import anthropic
import claude_agent_sdk
import jinja2

from .log import log_message
from .models import Attempt, History, Model

_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(pathlib.Path(__file__).parent / "templates"),
    trim_blocks=True,
    lstrip_blocks=True,
    undefined=jinja2.StrictUndefined,
)

# Cap on conversation turns per agent query (ClaudeAgentOptions.max_turns).
MAX_TOOL_ROUNDS = 100

# The optimization scope: agents run from this directory, and both prompt
# templates reference it as {{ cgen_dir }}.
_CGEN_DIR = "src/libbpfilter/cgen"

log = logging.getLogger("bfoptimizer")


def proposal_system_prompt(history: History) -> str:
    return _env.get_template("proposal.j2").render(cgen_dir=_CGEN_DIR, history=history)


def implementation_system_prompt(history: History, failures) -> str:
    return _env.get_template("implementation.j2").render(
        cgen_dir=_CGEN_DIR, history=history, failures=failures
    )


@functools.cache
def _anthropic_client() -> anthropic.Anthropic:
    return anthropic.Anthropic()


async def _query(
    history: History,
    prompt: str,
    model: Model,
    allowed_tools: list[str],
    disallowed_tools: list[str] | None = None,
) -> str | None:
    """Run a claude_agent_sdk query, logging messages and accumulating cost.

    Returns the final result text, or None if the query produced none.
    """
    attempt: Attempt | None = history.current_attempt
    if not attempt:
        raise RuntimeError("model queried, but no Attempt in progress")

    result: str | None = None
    async for message in claude_agent_sdk.query(
        prompt=prompt,
        options=claude_agent_sdk.ClaudeAgentOptions(
            system_prompt={  # how it behaves, every turn
                "type": "preset",
                "preset": "claude_code",  # keep the coding persona
                "append": "You are a performance engineer with a deep understanding "
                "of the BPF bytecode and subsystem in the kernel, as well as packet "
                "filtering and usual packet matching practices.",
            },
            cwd=str(history.config.sources_dir / _CGEN_DIR),
            allowed_tools=allowed_tools,
            disallowed_tools=disallowed_tools or [],
            permission_mode="bypassPermissions",
            max_turns=MAX_TOOL_ROUNDS,
            model=model.value,
            **model.agent_options(history.config.effort),
            stderr=lambda line: log.debug(line),
        ),
    ):
        log_message(message)

        if isinstance(message, claude_agent_sdk.ResultMessage):
            attempt.cost += message.total_cost_usd or 0.0
            if not message.is_error:
                result = message.result

    return result


async def query_proposal(history: History) -> None:
    log.info("Requesting the proposal")

    plan = await _query(
        history,
        proposal_system_prompt(history),
        history.config.proposal_model,
        allowed_tools=["Read", "Grep", "Glob", "Bash", "ToolSearch"],
        disallowed_tools=["ScheduleWakeup"],
    )

    # An empty plan is left for the caller to handle: it aborts the attempt,
    # not the run.
    attempt = history.current_attempt
    attempt.plan = plan or ""
    if attempt.plan:
        log.info(f"Proposal complete (total cost ${attempt.cost:.2f})")


async def query_implementation(history: History, failures) -> None:
    log.info("Requesting the implementation")

    await _query(
        history,
        implementation_system_prompt(history, failures),
        history.config.impl_model,
        allowed_tools=["Read", "Grep", "Glob", "Bash", "Edit", "Write"],
    )

    cost = history.current_attempt.cost
    log.info(f"Implementation completed (total cost ${cost:.2f})")


def generate_commit_message(plan: str, diff: str) -> str:
    response = _anthropic_client().messages.create(
        model=Model.CLAUDE_HAIKU_4_5.value,
        max_tokens=500,
        output_config={
            "format": {
                "type": "json_schema",
                "schema": {
                    "type": "object",
                    "properties": {
                        "subject": {"type": "string"},
                        "body": {"type": "string"},
                    },
                    "required": ["subject", "body"],
                    "additionalProperties": False,
                },
            }
        },
        messages=[
            {
                "role": "user",
                "content": f"""Generate a git commit message (subject and body) for this change to the bpfilter project.

Subject: `component: subcomponent: short description`
- Components: lib, cli, tests, build, tools, doc
- Subcomponents examples: cgen, matcher, chain, rule, hook
- Lowercase, imperative mood, no period, ≤72 chars total
- Describe WHY the change improves things, not what lines changed

Body: 2-4 sentences explaining the intent behind the change and why it
improves the generated BPF programs. Wrap lines at 72 characters. Do not
repeat the subject or describe the diff line by line.

Plan (intent):
{plan}

Diff:
{diff}
""",
            }
        ],
    )
    message = json.loads(response.content[0].text)
    return f"{message['subject'].strip()}\n\n{message['body'].strip()}"
