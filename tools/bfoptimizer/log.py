# Copyright (c) Meta Platforms, Inc. and affiliates.
"""Translation of OpenRouter messages into bfoptimizer log records."""

import enum
import logging

log = logging.getLogger("bfoptimizer")


class RenderAs(enum.StrEnum):
    PLAIN = "plain"
    MARKDOWN = "markdown"
    RICH = "rich"


_TOOL_KEYS = {
    "Read": ["file_path"],
    "Write": ["file_path"],
    "Edit": ["file_path"],
    "Grep": ["path", "pattern"],
    "Glob": ["pattern"],
    "Bash": ["command"],
}


def log_message(message: dict) -> None:
    """Log assistant text without exposing encrypted reasoning blocks."""

    if message.get("content"):
        log.info(message["content"], extra={"render_as": RenderAs.MARKDOWN})


def log_tool(name: str, arguments: dict) -> None:
    # Tools without a curated subset log their full input.
    keys = _TOOL_KEYS.get(name, list(arguments))
    log.info(
        name, extra={"kv": {key: arguments[key] for key in keys if key in arguments}}
    )
