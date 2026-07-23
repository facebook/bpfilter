# Copyright (c) Meta Platforms, Inc. and affiliates.
"""Textual UI for bfoptimizer.

Owns every widget and the App shell. The optimization loop itself is
injected into Optimizer as a coroutine function: the UI renders a run, it
doesn't drive it.
"""

from __future__ import annotations

import asyncio
import collections
import datetime
import logging
from collections.abc import Awaitable, Callable

import rich.box
import rich.console
import rich.markdown
import rich.panel
import rich.syntax
import rich.table
import rich.text
import textual.events
import textual.widgets
import textual_plot
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Header, Static, TabbedContent, TabPane
from textual.widgets.option_list import Option

from tests.benchmarks.bfbencher import SHORT_SHA_LEN, compare_table

from .log import RenderAs
from .models import Attempt, AttemptResult, CommitInfo, History

# Attempt result colors, shared by the attempt list and summary. Results
# not listed here are failures.
_RESULT_STYLES = {
    AttemptResult.IN_PROGRESS: "yellow",
    AttemptResult.SUCCESS: "green",
}


def _result_style(result: AttemptResult) -> str:
    return _RESULT_STYLES.get(result, "red")


def _delta_style(delta_pct: float) -> str:
    return "green" if delta_pct < 0 else ("red" if delta_pct > 0 else "dim")


# Background for code blocks in the attempt summary: solarized base2, one
# step darker than the app's base3 background, so the block reads as a
# full-width surface instead of a per-character highlight.
_CODE_BACKGROUND = "#eee8d5"


def _section(title: str) -> rich.text.Text:
    return rich.text.Text(title.upper(), style="bold dim")


def _stat_box(label: str, value: rich.text.Text | str) -> rich.panel.Panel:
    if isinstance(value, str):
        value = rich.text.Text(value, style="bold")
    return rich.panel.Panel(
        rich.console.Group(rich.text.Text(label, style="dim"), value),
        box=rich.box.ROUNDED,
        padding=(0, 1),
        expand=False,
    )


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

        # RichLog.write() renders into fixed-width strips immediately, and
        # while the Attempts tab is active this widget's content region is
        # zero-wide, so records logged in the meantime would be wrapped at
        # RichLog.min_width for good. Buffer them until the view is shown
        # again, bounded like the scrollback.
        self._pending: collections.deque[rich.console.RenderableType] = (
            collections.deque(maxlen=10_000)
        )

    def log_write(self, renderable: rich.console.RenderableType) -> None:
        # Also buffer while a backlog exists: a record arriving between Show
        # and the _flush() that follows it must not jump ahead of the
        # buffered ones.
        if self._pending or not self.scrollable_content_region.width:
            self._pending.append(renderable)
        else:
            self.write(renderable)

    def clear(self) -> LogView:
        self._pending.clear()
        super().clear()
        return self

    def on_show(self) -> None:
        # Flush after the layout pass: the content region is still
        # zero-wide when Show is dispatched.
        self.call_after_refresh(self._flush)

    def _flush(self) -> None:
        while self._pending and self.scrollable_content_region.width:
            self.write(self._pending.popleft())

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
        self._last_attempt = 0

    def _call(self, fn, *args) -> None:
        """Invoke fn on the app's event loop.

        Textual widgets are not thread-safe, and emit() is also called from
        worker threads (e.g. the benchmark renderer running in
        asyncio.to_thread()).
        """
        try:
            self._loop.call_soon_threadsafe(fn, *args)
        except RuntimeError:
            # The loop is closed: a worker thread logged during app teardown,
            # there is nowhere left to render to.
            pass

    def _write(self, renderable) -> None:
        self._call(self._widget.log_write, renderable)

    def _clear(self) -> None:
        self._widget.clear()
        # Re-arm auto-scroll: the user may have scrolled up during the
        # previous attempt, which would leave the new one's log stuck.
        self._widget.auto_scroll = True

    def emit(self, record: logging.LogRecord) -> None:
        time = datetime.datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        attempt_id = len(self._history.attempts)

        # The Logs tab only shows the current attempt: past attempts are
        # summarized in the Attempts tab. Handler.handle() serializes emit(),
        # and call_soon_threadsafe() preserves the clear/write order.
        if attempt_id != self._last_attempt:
            self._last_attempt = attempt_id
            self._call(self._clear)
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


class AttemptList(textual.widgets.OptionList):
    DEFAULT_CSS = """
    AttemptList {
        width: 34;
        height: 1fr;
        border: round $primary;
        background: $background;
    }
    """

    def __init__(self, history: History) -> None:
        super().__init__()
        self._history = history

    def on_mount(self) -> None:
        self.border_title = "Attempts"

    def _prompt(self, index: int, attempt: Attempt) -> rich.table.Table:
        status = rich.text.Text(no_wrap=True)
        status.append(f"#{index + 1:<3}", style="bold cyan")
        if attempt.result == AttemptResult.IN_PROGRESS:
            status.append(attempt.step.value, style="yellow")
        else:
            status.append(attempt.result.value, style=_result_style(attempt.result))

        if attempt.benchmark_results:
            delta = rich.text.Text(
                f"{attempt.delta_pct:+.2f}%",
                style=_delta_style(attempt.delta_pct),
                no_wrap=True,
            )
        else:
            delta = rich.text.Text("—", style="dim", no_wrap=True)

        # An expanded two-column grid pins the result to the right edge of
        # the list, so the deltas line up across attempts.
        prompt = rich.table.Table.grid(expand=True)
        prompt.add_column(no_wrap=True)
        prompt.add_column(justify="right", no_wrap=True)
        prompt.add_row(status, delta)
        return prompt

    def refresh_attempts(self) -> None:
        attempts = self._history.attempts

        # Follow the newest attempt unless the user moved the cursor away
        # from it, mirroring LogView's auto-scroll semantics.
        follow = self.highlighted is None or self.highlighted == self.option_count - 1

        # Prompts are replaced in place: rebuilding the list would reset the
        # highlighted option under the user.
        for i in range(self.option_count):
            self.replace_option_prompt_at_index(i, self._prompt(i, attempts[i]))
        for i in range(self.option_count, len(attempts)):
            self.add_option(Option(self._prompt(i, attempts[i]), id=str(i)))

        if follow and self.option_count:
            self.highlighted = self.option_count - 1


class AttemptSummary(VerticalScroll):
    DEFAULT_CSS = """
    AttemptSummary {
        width: 1fr;
        height: 1fr;
        border: round $primary;
        background: $background;
        padding: 0 1;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._shown: tuple[int, AttemptResult] | None = None

    def compose(self) -> ComposeResult:
        yield Static(id="summary-body")

    def on_mount(self) -> None:
        self.border_title = "Summary"

    def show(self, index: int, attempt: Attempt) -> None:
        # Completed attempts are rendered once: rebuilding the diff Syntax
        # every second would be wasteful and disturb the user's scroll
        # position. In-progress attempts re-render on every tick so the
        # step/duration metrics stay live.
        key = (index, attempt.result)
        if key == self._shown and attempt.result != AttemptResult.IN_PROGRESS:
            return
        self._shown = key

        self.border_title = f"Attempt {index + 1}" + (
            f" · {attempt.commit.subject}" if attempt.commit else ""
        )
        self.query_one("#summary-body", Static).update(self._summary(attempt))

    # Not named _render(): Widget._render() is part of Textual's rendering
    # pipeline.
    def _summary(self, attempt: Attempt) -> rich.console.Group:
        parts: list[rich.console.RenderableType] = [
            self._headline(attempt),
            rich.text.Text(),
            self._metrics(attempt),
            rich.text.Text(),
        ]

        if attempt.commit:
            parts.append(_section("commit"))
            parts.append(self._commit(attempt.commit))
            rows = [
                r
                for r in attempt.benchmark_results
                if r.delta_time_pct != 0 or r.delta_insn not in (None, 0)
            ]
            if rows:
                parts.append(rich.text.Text())
                parts.append(_section("benchmarks"))
                parts.append(
                    compare_table(rows, attempt.commit.parent_sha, attempt.commit.sha)
                )
            parts.append(rich.text.Text())
            parts.append(_section("diff"))
            parts.append(
                rich.syntax.Syntax(
                    attempt.commit.diff,
                    "diff",
                    theme="solarized-light",
                    background_color=_CODE_BACKGROUND,
                )
            )
        elif attempt.result == AttemptResult.IN_PROGRESS:
            parts.append(rich.text.Text("attempt in progress", style="dim italic"))
        else:
            parts.append(
                rich.text.Text(
                    "no commit: the attempt did not reach the commit stage",
                    style="dim italic",
                )
            )

        return rich.console.Group(*parts)

    def _headline(self, attempt: Attempt) -> rich.text.Text:
        text = rich.text.Text(no_wrap=True)
        text.append(
            attempt.result.value, style=f"bold {_result_style(attempt.result)}"
        )
        if attempt.result == AttemptResult.IN_PROGRESS:
            text.append(" · ", style="dim")
            text.append(attempt.step.value, style="yellow")
        if attempt.commit:
            text.append(" · commit ", style="dim")
            text.append(attempt.commit.sha[:SHORT_SHA_LEN], style="bold yellow")
        return text

    def _metrics(self, attempt: Attempt) -> rich.table.Table:
        secs = int(attempt.duration)

        row = rich.table.Table.grid(padding=(0, 1))
        row.add_row(
            _stat_box(
                "ΔTime",
                rich.text.Text(
                    f"{attempt.delta_pct:+.2f}%",
                    style=f"bold {_delta_style(attempt.delta_pct)}",
                ),
            ),
            _stat_box("Duration", f"{secs // 60}m {secs % 60}s"),
            _stat_box("Cost", f"${attempt.cost:.2f}"),
        )
        return row

    def _commit(self, commit: CommitInfo) -> rich.text.Text:
        text = rich.text.Text()
        text.append(f"{commit.sha[:SHORT_SHA_LEN]} ", style="bold yellow")
        text.append(commit.subject, style="bold")
        if commit.body:
            text.append("\n\n")
            text.append(commit.body, style="dim")
        return text


class AttemptsPane(Horizontal):
    DEFAULT_CSS = """
    AttemptsPane {
        height: 1fr;
    }
    """

    def __init__(self, history: History) -> None:
        super().__init__()
        self._history = history

    def compose(self) -> ComposeResult:
        yield AttemptList(self._history)
        yield AttemptSummary()

    def on_option_list_option_highlighted(
        self, event: textual.widgets.OptionList.OptionHighlighted
    ) -> None:
        self.query_one(AttemptSummary).show(
            event.option_index, self._history.attempts[event.option_index]
        )

    def refresh_attempts(self) -> None:
        self.query_one(AttemptList).refresh_attempts()

        index = self.query_one(AttemptList).highlighted
        if index is not None:
            self.query_one(AttemptSummary).show(index, self._history.attempts[index])


class ProgressPane(Vertical):
    DEFAULT_CSS = """
    ProgressPane {
        height: 1fr;
    }
    ProgressPane PlotWidget {
        height: 1fr;
        border: round $primary;
        background: $background;
    }
    """

    def __init__(self, history: History) -> None:
        super().__init__()
        self._history = history

    def compose(self) -> ComposeResult:
        yield textual_plot.PlotWidget()

    def on_mount(self) -> None:
        plot = self.query_one(textual_plot.PlotWidget)
        plot.border_title = "Progress"
        plot.show_legend(textual_plot.LegendLocation.BOTTOMLEFT)

    def refresh_progress(self) -> None:
        attempts = self._history.attempts

        kept: list[tuple[int, float]] = []
        rejected: list[tuple[int, float]] = []
        # The overall line starts at the run baseline and only moves on kept
        # attempts: regressions are reverted, so progress stays flat through
        # them.
        overall: list[tuple[int, float]] = [(0, 0.0)]
        for i, attempt in enumerate(attempts):
            if attempt.result == AttemptResult.IN_PROGRESS:
                continue
            overall.append((i + 1, self._history.cumulative_progress(up_to=i)))
            if not attempt.benchmark_results:
                continue
            marks = kept if attempt.result == AttemptResult.SUCCESS else rejected
            marks.append((i + 1, attempt.delta_pct))

        plot = self.query_one(textual_plot.PlotWidget)
        plot.clear()
        plot.set_xlabel("attempt")
        plot.set_ylabel("Δtime %")
        plot.set_xlimits(0, self._history.config.iterations)
        plot.plot(
            [x for x, _ in overall],
            [y for _, y in overall],
            line_style="blue",
            hires_mode=textual_plot.HiResMode.BRAILLE,
            label="overall",
        )
        if kept:
            plot.scatter(
                [x for x, _ in kept],
                [y for _, y in kept],
                marker="●",
                marker_style="green",
                label="kept",
            )
        if rejected:
            plot.scatter(
                [x for x, _ in rejected],
                [y for _, y in rejected],
                marker="x",
                marker_style="red",
                label="regression",
            )


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
    CSS = """
    TabbedContent {
        height: 1fr;
    }
    """

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
        with TabbedContent(initial="tab-logs"):
            with TabPane("Logs", id="tab-logs"):
                yield LogView()
            with TabPane("Attempts", id="tab-attempts"):
                yield AttemptsPane(self._history)
            with TabPane("Progress", id="tab-progress"):
                yield ProgressPane(self._history)

    def on_mount(self) -> None:
        self.theme = "solarized-light"

        handler = LogHandler(self.query_one(LogView), self._history)
        handler.setLevel(logging.DEBUG)

        logger = logging.getLogger("bfoptimizer")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)

        # The meta line only shows immutable run metadata: render it once,
        # only the stats and attempts need the periodic refresh.
        self.query_one(MetaLine).refresh_meta()
        self._refresh()
        self.set_interval(1, self._refresh)

        self.run_worker(self._worker(), exclusive=True)

    def _refresh(self) -> None:
        self.query_one(StatsBar).refresh_stats()
        self.query_one(AttemptsPane).refresh_attempts()
        self.query_one(ProgressPane).refresh_progress()
