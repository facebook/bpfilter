---
allowed-tools: Task
argument-hint: <target> (PR number, commit/range, path, or empty for working tree)
description: Run the memory-auditor subagent on a change set
---

Delegate to the `memory-auditor` subagent with target: `$ARGUMENTS`.

If `$ARGUMENTS` is empty, ask the subagent to audit the working-tree diff against `HEAD`.

Pass the target verbatim — the subagent knows how to interpret PR numbers, git revspecs, paths, and empty input. Return its report unchanged.
