# Copyright (c) Meta Platforms, Inc. and affiliates.
"""Local tools exposed to OpenRouter models during optimization."""

import asyncio
import json
import os
import pathlib
import signal
import subprocess
import tempfile

from .log import log_tool

MAX_OUTPUT_CHARS = 32_000
COMMAND_TIMEOUT = 120
READ_LIMIT = 2000


def _tool(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        },
    }


_STRING = {"type": "string"}
_READ_TOOLS = [
    _tool(
        "Read",
        f"Read a UTF-8 file with line numbers. Paths are relative to the repository root. Returns up to {READ_LIMIT} lines by default, and ends with the offset to continue from when the file is longer.",
        {
            "file_path": _STRING,
            "offset": {"type": "integer", "minimum": 1},
            "limit": {"type": "integer", "minimum": 1},
        },
        ["file_path"],
    ),
    _tool(
        "Grep",
        "Search file contents with a ripgrep regular expression, skipping ignored files. Use Bash for other ripgrep options.",
        {"pattern": _STRING, "path": _STRING},
        ["pattern"],
    ),
    _tool(
        "Glob",
        "List files using a glob relative to the repository root, including **. Ignored files, such as the build directory, are skipped.",
        {"pattern": _STRING},
        ["pattern"],
    ),
    _tool(
        "Bash",
        f"Run a Bash command from the repository root, without standard input. Commands time out after {COMMAND_TIMEOUT} seconds.",
        {"command": _STRING},
        ["command"],
    ),
]


def _write_tools(cgen_dir: str) -> list[dict]:
    return [
        _tool(
            "Edit",
            f"Replace one exact occurrence of old_string with new_string in a file under {cgen_dir}/.",
            {"file_path": _STRING, "old_string": _STRING, "new_string": _STRING},
            ["file_path", "old_string", "new_string"],
        ),
        _tool(
            "Write",
            f"Create or overwrite a UTF-8 file under {cgen_dir}/.",
            {"file_path": _STRING, "content": _STRING},
            ["file_path", "content"],
        ),
    ]


class AgentTools:
    def __init__(self, sources_dir: pathlib.Path, cgen_dir: str, *, writable: bool):
        self.root = sources_dir.resolve()
        self.write_root = (self.root / cgen_dir).resolve()
        writes = _write_tools(cgen_dir) if writable else []
        self.definitions = [*_READ_TOOLS, *writes]
        self._parameters = {
            tool["function"]["name"]: tool["function"]["parameters"]
            for tool in self.definitions
        }
        self._writes = {tool["function"]["name"] for tool in writes}

    def _path(self, file_path: str, *, write: bool = False) -> pathlib.Path:
        path = (self.root / file_path).resolve()
        boundary = self.write_root if write else self.root
        if not path.is_relative_to(boundary):
            raise ValueError(f"path must be under {boundary}")

        return path

    async def execute(self, name: str, raw_arguments: str) -> str:
        """Return tool failures to the model so it can correct its arguments."""
        try:
            parameters = self._parameters.get(name)
            if parameters is None:
                raise ValueError(f"tool is not available: {name}")

            arguments = json.loads(raw_arguments)
            if not isinstance(arguments, dict):
                raise ValueError("tool arguments must be an object")

            log_tool(name, arguments)

            # Ignoring an argument would let the model believe it took effect.
            supported = parameters["properties"]
            unknown = sorted(arguments.keys() - supported.keys())
            if unknown:
                raise ValueError(
                    f"unsupported arguments: {', '.join(unknown)} (supported: {', '.join(supported)})"
                )

            result = await self._execute(name, **arguments)
            if len(result) > MAX_OUTPUT_CHARS:
                result = result[:MAX_OUTPUT_CHARS] + "\n[output truncated]"

            return result
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            subprocess.SubprocessError,
        ) as error:
            return f"Error: {error}"

    async def _execute(self, name: str, **arguments) -> str:
        if name == "Bash":
            return await self._command("bash", "-c", arguments["command"])
        if name == "Grep":
            path = self._path(arguments.get("path", "."))
            return await self._command(
                "rg",
                "--line-number",
                "--no-heading",
                "--color=never",
                "--",
                arguments["pattern"],
                str(path),
            )
        # File operations run in a worker so they do not block the TUI.
        return await asyncio.to_thread(self._file_tool, name, **arguments)

    def _file_tool(self, name: str, **arguments) -> str:
        if name == "Glob":
            return self._glob(arguments["pattern"])

        path = self._path(arguments["file_path"], write=name in self._writes)
        if name == "Read":
            return self._read(
                path, arguments.get("offset", 1), arguments.get("limit", READ_LIMIT)
            )
        if name == "Edit":
            old = arguments["old_string"]
            content = path.read_text(encoding="utf-8")
            if not old or content.count(old) != 1:
                raise ValueError("old_string must match exactly once")
            path.write_text(
                content.replace(old, arguments["new_string"], 1), encoding="utf-8"
            )
        elif name == "Write":
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(arguments["content"], encoding="utf-8")
        return f"Updated {path.relative_to(self.root)}"

    def _glob(self, pattern: str) -> str:
        if pathlib.Path(pattern).is_absolute() or ".." in pathlib.Path(pattern).parts:
            raise ValueError("glob pattern must be relative to the repository root")
        # Unlike Path.glob(), Git skips ignored trees such as the build
        # directory, as Grep does. --others adds the files the agent created.
        listing = subprocess.run(
            [
                "git",
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
                "--",
                f":(glob){pattern}",
            ],
            cwd=self.root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=COMMAND_TIMEOUT,
        )
        if listing.returncode != 0:
            raise ValueError(listing.stderr.decode(errors="replace").strip())

        paths = {
            path
            for path in listing.stdout.decode(errors="replace").split("\0")
            # The index still lists tracked files deleted from the tree.
            if path and (self.root / path).is_file()
        }

        return "\n".join(sorted(paths)) or "No files found."

    def _read(self, path: pathlib.Path, offset: int, limit: int) -> str:
        if offset < 1 or limit < 1:
            raise ValueError("offset and limit must be positive")

        lines = path.read_text(encoding="utf-8").splitlines()
        if offset > len(lines):
            return (
                f"[Offset {offset} is past the end: the file has {len(lines)} lines.]"
            )

        shown: list[str] = []
        size = 0
        for number, line in enumerate(lines[offset - 1 : offset - 1 + limit], offset):
            entry = f"{number}: {line}"
            size += len(entry) + 1
            # Stop on a line boundary, and leave room for the note below.
            if shown and size > MAX_OUTPUT_CHARS - 100:
                break
            shown.append(entry)

        last = offset + len(shown) - 1
        if last < len(lines):
            shown.append(
                f"[Lines {offset}-{last} of {len(lines)}. Read from offset {last + 1} for more.]"
            )

        return "\n".join(shown)

    async def _command(self, *command: str) -> str:
        # Output goes to a file, not a pipe: process.wait() would also wait for
        # background jobs that keep a pipe open. The file is in the temporary
        # directory, which can be tmpfs: a huge output then uses memory until
        # the command ends.
        with tempfile.TemporaryFile() as output:
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=self.root,
                # The TUI reads the terminal: commands must not take its input.
                stdin=asyncio.subprocess.DEVNULL,
                stdout=output,
                stderr=asyncio.subprocess.STDOUT,
                # Command output goes to the model provider.
                env={
                    key: value
                    for key, value in os.environ.items()
                    if key != "OPENROUTER_API_KEY"
                },
                start_new_session=True,
            )

            try:
                await asyncio.wait_for(process.wait(), timeout=COMMAND_TIMEOUT)
            except (TimeoutError, asyncio.CancelledError) as error:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()
                if isinstance(error, asyncio.CancelledError):
                    raise
                return f"Error: command timed out after {COMMAND_TIMEOUT} seconds"

            output.seek(0)
            # A UTF-8 character takes up to 4 bytes. Reading this many bytes
            # gives execute() more than MAX_OUTPUT_CHARS characters whenever
            # the output has them, so it marks the result as truncated.
            data = output.read(4 * (MAX_OUTPUT_CHARS + 1))

        return f"Exit code: {process.returncode}\n{data.decode(errors='replace')}"
