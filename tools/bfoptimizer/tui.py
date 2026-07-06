"""Textual UI for bfoptimizer.

Owns every widget and the App shell. The optimization loop itself is
injected into Optimizer as a coroutine function: the UI renders a run, it
doesn't drive it.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
from collections.abc import Awaitable, Callable

import rich.console
import rich.markdown
import rich.table
import rich.text
import textual.events
import textual.widgets
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Header, Static

from tests.benchmarks.bfbencher import SHORT_SHA_LEN

from .log import RenderAs
from .models import History


class LogView(textual.widgets.RichLog):
    DEFAULT_CSS = """
    LogView {
        height: 1fr;
        border: round $primary;
        background: $background;
        padding: 0 1;
    }
    """

    def __init__(self) -> None:
        # RichLog retains rendered lines forever by default; bound the
        # scrollback so an overnight run's build output and LLM messages
        # don't grow memory without limit.
        super().__init__(wrap=True, max_lines=10_000)

    def on_mount(self) -> None:
        self.border_title = "Logs"

    def on_mouse_scroll_up(self, event: textual.events.MouseScrollUp) -> None:
        self.auto_scroll = False

    def on_mouse_scroll_down(self, event: textual.events.MouseScrollDown) -> None:
        if self.is_vertical_scroll_end:
            self.auto_scroll = True


class LogHandler(logging.Handler):
    def __init__(self, widget: LogView, history: History) -> None:
        super().__init__()

        self._widget = widget
        self._history = history
        self._loop = asyncio.get_running_loop()

    def _write(self, renderable) -> None:
        """Write to the widget from the app's event loop.

        Textual widgets are not thread-safe, and emit() is also called from
        worker threads (e.g. the benchmark renderer running in
        asyncio.to_thread()).
        """
        try:
            self._loop.call_soon_threadsafe(self._widget.write, renderable)
        except RuntimeError:
            # The loop is closed: a worker thread logged during app teardown,
            # there is nowhere left to render to.
            pass

    def emit(self, record: logging.LogRecord) -> None:
        time = datetime.datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        attempt_id = len(self._history.attempts)
        step = (
            self._history.current_attempt.step.value
            if self._history.current_attempt
            else "-"
        )

        # A pre-built renderable (e.g. a compare table) is used as the
        # message as-is, but still goes through the metadata grid below.
        renderable = getattr(record, "renderable", None)
        render_as = getattr(record, "render_as", RenderAs.PLAIN)
        if renderable is not None:
            message: rich.console.RenderableType = renderable
        elif render_as == RenderAs.MARKDOWN:
            message = rich.markdown.Markdown(
                record.getMessage(),
                code_theme="solarized-light",
                inline_code_lexer="c",
                inline_code_theme="solarized-light",
            )
        elif render_as == RenderAs.RICH:
            message = rich.text.Text.from_markup(record.getMessage())
        elif render_as == RenderAs.PLAIN:
            message = rich.text.Text(record.getMessage())
        else:
            raise RuntimeError(f"Unsupported RenderAs.{render_as}")

        kv: dict[str, str] | None = getattr(record, "kv", None)
        if kv is not None and isinstance(message, rich.text.Text):
            message.stylize("bold")
            for k, v in kv.items():
                message.append(f" {k}=", style="dim")
                message.append(str(v), style="dim italic")

        table = rich.table.Table.grid(padding=(0, 1))
        table.add_column(width=8, no_wrap=True)
        table.add_column(width=8, no_wrap=True)
        table.add_column(width=12, no_wrap=True)
        table.add_column(ratio=1)
        table.add_row(
            rich.text.Text(time, style="dim"),
            rich.text.Text(
                f"[{attempt_id}/{self._history.config.iterations}]",
                style="bold cyan",
            ),
            rich.text.Text(step, style="yellow"),
            message,
        )

        self._write(table)


class StatColumn(Static):
    """One column in the stats bar: label / value / sublabel."""

    DEFAULT_CSS = """
    StatColumn {
        width: 1fr;
        padding: 0 2;
        border: round $primary;
    }
    """

    def __init__(self, label: str, **kwargs) -> None:
        super().__init__("", **kwargs)
        self.border_title = label

    def set(self, value: rich.text.Text | str, sublabel: str = "") -> None:
        t = rich.table.Table.grid()
        t.add_column()
        t.add_row(
            value
            if isinstance(value, rich.text.Text)
            else rich.text.Text(value, style="bold")
        )
        t.add_row(rich.text.Text(sublabel, style="dim"))
        self.update(t)


class MetaLine(Static):
    DEFAULT_CSS = """
    MetaLine {
        height: 1;
        padding: 0 1;
    }
    """

    def __init__(self, history: History) -> None:
        super().__init__("")
        self._history = history

    def refresh_meta(self) -> None:
        h = self._history
        self.update(
            rich.text.Text.assemble(
                ("run ", "dim"),
                (h.id, "dim bold"),
                (" · base ", "dim"),
                (h.baseline_sha[:SHORT_SHA_LEN], "dim bold"),
                (" · prop model ", "dim"),
                (h.config.proposal_model, "dim bold"),
                (" · impl model ", "dim"),
                (h.config.impl_model, "dim bold"),
                (" · effort ", "dim"),
                (h.config.effort, "dim bold"),
                (" · sources ", "dim"),
                (str(h.config.sources_dir), "dim bold"),
                *(
                    [(" · hint: ", "dim"), (h.config.hint, "dim italic")]
                    if h.config.hint
                    else []
                ),
            )
        )


class StatsBar(Vertical):
    DEFAULT_CSS = """
    StatsBar {
        height: 5;
    }
    StatsBar Horizontal {
        height: 5;
        padding: 0 1;
    }
    """

    def __init__(self, history: History) -> None:
        super().__init__()
        self._history = history

    def compose(self) -> ComposeResult:
        with Horizontal():
            yield StatColumn("Attempts", id="stat-attempts")
            yield StatColumn("Kept", id="stat-kept")
            yield StatColumn("Rejected", id="stat-rejected")
            yield StatColumn("Cumulative Δtime", id="stat-delta")
            yield StatColumn("Cost", id="stat-cost")
            yield StatColumn("Wall", id="stat-wall")

    def refresh_stats(self) -> None:
        h = self._history

        n = len(h.attempts)
        kept = h.attempts_kept
        delta_pct = h.cumulative_progress()
        secs = int(h.duration)
        accept = (
            f"{kept / h.attempts_complete * 100:.0f}% accept"
            if h.attempts_complete
            else "—"
        )
        step = h.current_attempt.step.value if h.current_attempt else "—"
        delta_style = (
            "bold green"
            if delta_pct < 0
            else ("bold red" if delta_pct > 0 else "bold dim")
        )

        self.query_one("#stat-attempts", StatColumn).set(
            f"{n}/{h.config.iterations}", step
        )
        self.query_one("#stat-kept", StatColumn).set(str(kept), accept)
        self.query_one("#stat-rejected", StatColumn).set(
            str(h.attempts_rejected), "build / test / bench"
        )
        self.query_one("#stat-delta", StatColumn).set(
            rich.text.Text(f"{delta_pct:+.2f}%", style=delta_style),
            f"vs baseline {h.baseline_sha[:SHORT_SHA_LEN]}",
        )
        self.query_one("#stat-cost", StatColumn).set(f"${h.cost:.2f}", "total run cost")
        self.query_one("#stat-wall", StatColumn).set(
            f"{secs // 60}m {secs % 60}s", "elapsed · live"
        )


class Optimizer(App):
    TITLE = "bfoptimizer"

    def __init__(self, history: History, worker: Callable[[], Awaitable[None]]) -> None:
        super().__init__()

        self._history = history
        self._worker = worker

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static()
        yield MetaLine(self._history)
        yield Static()
        yield StatsBar(self._history)
        yield LogView()

    def on_mount(self) -> None:
        self.theme = "solarized-light"

        handler = LogHandler(self.query_one(LogView), self._history)
        handler.setLevel(logging.DEBUG)

        logger = logging.getLogger("bfoptimizer")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        # The meta line only shows immutable run metadata: render it once,
        # only the stats need the periodic refresh.
        self.query_one(MetaLine).refresh_meta()
        self.query_one(StatsBar).refresh_stats()
        self.set_interval(1, self.query_one(StatsBar).refresh_stats)

        self.run_worker(self._worker(), exclusive=True)
