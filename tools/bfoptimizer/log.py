"""Translation of claude_agent_sdk messages into bfoptimizer log records."""

import enum
import logging

import claude_agent_sdk

log = logging.getLogger("bfoptimizer")


class RenderAs(enum.StrEnum):
    PLAIN = "plain"
    MARKDOWN = "markdown"
    RICH = "rich"


# Input keys to log for tool-use blocks: a curated subset for tools whose
# input is too noisy to show in full (Write's content, Edit's old/new
# strings), None to hide the block entirely. Tools not listed here log
# their full input.
_BLOCK_KV: dict[str, list[str] | None] = {
    "Read": ["file_path"],
    "Write": ["file_path"],
    "Edit": ["file_path"],
    "Agent": [],
    "Grep": ["path", "pattern"],
    "ToolSearch": ["query"],
    "Glob": ["pattern"],
    "Bash": ["command"],
    "ExitPlanMode": None,
}


def log_message(message: claude_agent_sdk.Message) -> None:
    """Log a claude_agent_sdk message to the bfoptimizer logger."""
    if isinstance(message, claude_agent_sdk.AssistantMessage):
        for block in message.content:
            _log_block(block)
    elif isinstance(message, claude_agent_sdk.ResultMessage):
        if message.is_error:
            log.error(f"API error: {message.result}")
    elif isinstance(
        message,
        (
            claude_agent_sdk.TaskProgressMessage,
            claude_agent_sdk.TaskNotificationMessage,
            claude_agent_sdk.TaskUpdatedMessage,
            claude_agent_sdk.TaskStartedMessage,
        ),
    ):
        # Subagent lifecycle events. These subclass SystemMessage, so they
        # must be matched before the SystemMessage branch below, which would
        # otherwise catch them and log their repr.
        pass
    elif isinstance(message, claude_agent_sdk.SystemMessage):
        if message.subtype not in ["init", "thinking_tokens"]:
            log.info(message)
    elif isinstance(message, claude_agent_sdk.UserMessage):
        pass
    else:
        log.info(f"Unsupported message: {message}")


def _log_block(block: claude_agent_sdk.ContentBlock) -> None:
    if isinstance(block, claude_agent_sdk.ThinkingBlock):
        if not block.thinking:
            # Some models return empty thinking blocks
            return
        log.info(block.thinking, extra={"render_as": RenderAs.MARKDOWN})
    elif isinstance(block, claude_agent_sdk.ToolUseBlock):
        keys = _BLOCK_KV.get(block.name, list(block.input))
        if keys is None:
            return

        log.info(
            block.name,
            extra={"kv": {key: block.input.get(key, "<NONE>") for key in keys}},
        )
    elif isinstance(block, claude_agent_sdk.ToolResultBlock):
        log.info(f"ToolResultBlock {block}")
    elif isinstance(block, claude_agent_sdk.TextBlock):
        log.info(block.text, extra={"render_as": RenderAs.MARKDOWN})
    else:
        log.info(block)
