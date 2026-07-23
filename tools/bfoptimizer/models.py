# Copyright (c) Meta Platforms, Inc. and affiliates.
"""Data models for the bfoptimizer package."""

from __future__ import annotations

import dataclasses
import enum
import pathlib
import random
import string
import time
from collections.abc import Generator

import git

from tests.benchmarks.bfbencher import Report


class Model(enum.StrEnum):
    CLAUDE_FABLE_5 = "claude-fable-5"
    CLAUDE_OPUS_4_8 = "claude-opus-4-8"
    CLAUDE_SONNET_4_6 = "claude-sonnet-4-6"
    CLAUDE_HAIKU_4_5 = "claude-haiku-4-5"

    def agent_options(self, effort: "Effort") -> dict:
        """Return kwargs to unpack into ClaudeAgentOptions for this model and effort."""
        if self == Model.CLAUDE_HAIKU_4_5:
            return {}
        return {"effort": effort.value, "thinking": {"type": "adaptive"}}


class Effort(enum.StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    MAX = "max"


@dataclasses.dataclass(frozen=True)
class Config:
    """Optimizer configuration."""

    sources_dir: pathlib.Path
    build_dir: pathlib.Path

    iterations: int
    proposal_model: Model
    impl_model: Model
    effort: Effort
    hint: str | None
    benchmark_host: str | None
    benchmark_ssh_key: pathlib.Path | None
    benchmark_bind_node: int | None
    benchmark_no_preempt: bool
    benchmark_cpu_pin: int | None
    benchmark_slice: str | None
    benchmark_exclude_flags: list[str]


@dataclasses.dataclass(frozen=True)
class CommitInfo:
    """Commit produced by an attempt.

    Kept on the attempt even when the commit is later reverted (regression):
    parent_sha/sha stay valid for rendering even though the commit is no
    longer reachable from HEAD.
    """

    sha: str
    parent_sha: str
    subject: str
    body: str
    diff: str


class AttemptStep(enum.Enum):
    READY = "ready"
    PROPOSE = "propose"
    IMPLEMENT = "implement"
    BUILD = "build"
    TEST = "test"
    EVALUATE = "evaluate"
    DONE = "done"


class AttemptResult(enum.Enum):
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    PLAN_FAILED = "plan_failed"
    BUILD_FAILED = "build_failed"
    TEST_FAILED = "test_failed"
    REGRESSION = "regression"
    FAILED = "failed"


class Attempt:
    """Single optimization attempt within a run."""

    def __init__(self) -> None:
        self._step = AttemptStep.READY
        self._start_time: float | None = None
        self._stop_time: float | None = None
        self.result = AttemptResult.IN_PROGRESS
        self.plan: str | None = None
        self.benchmark_results: list[Report.CompareRow] = []
        self.cost = 0.0
        self.commit: CommitInfo | None = None

    @property
    def step(self) -> AttemptStep:
        return self._step

    @step.setter
    def step(self, step: AttemptStep) -> None:
        boundaries = (AttemptStep.READY, AttemptStep.DONE)
        if self._step in boundaries or step in boundaries:
            raise RuntimeError(
                "READY and DONE transitions go through start()/complete()"
            )
        self._step = step

    @property
    def duration(self) -> float:
        if self._start_time is None:
            return 0.0
        end = self._stop_time if self._stop_time is not None else time.time()
        return end - self._start_time

    @property
    def delta_pct(self) -> float:
        """Mean Δtime% across this attempt's benchmarks (negative = faster)."""
        return (
            sum(r.delta_time_pct for r in self.benchmark_results)
            / len(self.benchmark_results)
            if self.benchmark_results
            else 0.0
        )

    def start(self) -> None:
        self._step = AttemptStep.PROPOSE
        self._start_time = time.time()

    def complete(self, result: AttemptResult) -> None:
        self.result = result
        self._step = AttemptStep.DONE
        self._stop_time = time.time()


class History:
    """Per-run history of optimization attempts."""

    def __init__(self, config: Config) -> None:
        self.id = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
        self.config = config
        self.baseline_sha = git.Repo(config.sources_dir).head.commit.hexsha
        self.attempts: list[Attempt] = []

    @property
    def current_attempt(self) -> Attempt | None:
        return self.attempts[-1] if self.attempts else None

    @property
    def attempts_kept(self) -> int:
        return sum(
            1 for attempt in self.attempts if attempt.result == AttemptResult.SUCCESS
        )

    @property
    def attempts_complete(self) -> int:
        return sum(
            1
            for attempt in self.attempts
            if attempt.result != AttemptResult.IN_PROGRESS
        )

    @property
    def attempts_rejected(self) -> int:
        return self.attempts_complete - self.attempts_kept

    @property
    def cost(self) -> float:
        return sum(attempt.cost for attempt in self.attempts)

    @property
    def duration(self) -> float:
        return sum(attempt.duration for attempt in self.attempts)

    def cumulative_progress(self, up_to: int | None = None) -> float:
        """Δtime% from the original baseline to the current best commit.

        Only attempts up to index up_to (inclusive) are considered when
        provided, giving the progress as of that attempt.

        Returns 0.0 when there are no successful attempts with benchmark data.
        """
        attempts = self.attempts if up_to is None else self.attempts[: up_to + 1]
        successes = [
            attempt
            for attempt in attempts
            if attempt.result == AttemptResult.SUCCESS
        ]
        if not successes:
            return 0.0

        first = successes[0]
        last = successes[-1]

        base_by_name = {row.name: row.base_time_ns for row in first.benchmark_results}
        ref_by_name = {row.name: row.ref_time_ns for row in last.benchmark_results}
        deltas = [
            (ref_by_name[name] - base_ns) / base_ns * 100
            for name, base_ns in base_by_name.items()
            if name in ref_by_name and base_ns > 0
        ]

        return sum(deltas) / len(deltas) if deltas else 0.0

    def iter_attempts(self) -> Generator[Attempt, None, None]:
        for _ in range(self.config.iterations):
            self.attempts.append(Attempt())
            yield self.attempts[-1]
