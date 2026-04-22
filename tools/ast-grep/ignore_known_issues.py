#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Meta Platforms, Inc. and affiliates.

"""Filter ast-grep scan output against per-rule known-issues baselines.

Two modes:
  --check  (default): read ast-grep JSON stream from stdin, drop matches that
                      appear in tools/ast-grep/known_issues/<rule>.yml, print
                      the remainder to stderr, exit nonzero iff the remainder
                      is non-empty.
  --regen           : same input, but overwrite the known_issues tree with
                      exactly the set of currently-observed violations.

The identity key for an entry is (file, textSha, occurrence). Rule is implicit
from the filename stem. See the header comment emitted at the top of each YAML
file for the schema.
"""

import argparse
import hashlib
import json
import pathlib
import sys
from collections import defaultdict

try:
    import yaml
except ImportError:
    sys.stderr.write(
        "ERROR: PyYAML is required to run ignore_known_issues.py.\n"
        "  Fedora/RHEL  : dnf install -y python3-pyyaml\n"
        "  Debian/Ubuntu: apt-get install -y python3-yaml\n"
        "  pip          : pip install pyyaml\n"
    )
    sys.exit(2)


HEADER_TEMPLATE = """\
# Known issues for ast-grep rule `{rule}`.
#
# Suppressed during check.astgrep so only NEW violations fail CI. Regenerate
# this file (and all siblings) by running: make -C build astgrep-known-issues
#
# Schema: list of
#   file:        path relative to repo root
#   textSha:     first 12 hex chars of sha256(match.text)
#   occurrence:  0-based index among identical (file, textSha) matches
#
# Do not hand-edit — the directory is regenerated deterministically.

"""


def parse_args(argv):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true",
                      help="filter stdin against known_issues/ (default)")
    mode.add_argument("--regen", action="store_true",
                      help="rewrite known_issues/ from stdin")
    p.add_argument("--known-issues-dir", required=True, type=pathlib.Path,
                   help="path to the known_issues/ directory")
    p.add_argument("--repo-root", required=True, type=pathlib.Path,
                   help="repo root used to emit relative paths in ast-grep output")
    args = p.parse_args(argv)
    if not args.regen:
        args.check = True
    return args


def read_observations(stream, repo_root):
    prefix = str(repo_root).rstrip("/") + "/"
    obs = []
    for raw in stream:
        raw = raw.strip()
        if not raw:
            continue
        d = json.loads(raw)
        rule = d["ruleId"]
        path = d["file"]
        if path.startswith(prefix):
            path = path[len(prefix):]
        text = d["text"]
        text_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]
        byte_off = d["range"]["byteOffset"]["start"]
        line_num = d["range"]["start"]["line"] + 1
        message = d.get("message", "")
        obs.append({
            "rule": rule,
            "file": path,
            "textSha": text_sha,
            "byteOffset": byte_off,
            "line": line_num,
            "message": message,
        })
    return obs


def assign_occurrences(observations):
    groups = defaultdict(list)
    for o in observations:
        groups[(o["rule"], o["file"], o["textSha"])].append(o)
    out = []
    for items in groups.values():
        items.sort(key=lambda o: o["byteOffset"])
        for i, o in enumerate(items):
            o["occurrence"] = i
            out.append(o)
    return out


def load_all_known_issues(directory):
    known = {}
    if not directory.exists():
        return known
    for path in sorted(directory.glob("*.yml")):
        with open(path) as f:
            data = yaml.safe_load(f) or []
        rule = path.stem
        known[rule] = {(e["file"], e["textSha"], e["occurrence"]) for e in data}
    return known


def write_known_issues_file(path, rule, entries):
    header = HEADER_TEMPLATE.format(rule=rule)
    body = yaml.safe_dump(entries, default_flow_style=False, sort_keys=False,
                          width=200, allow_unicode=True)
    path.write_text(header + body)


def cmd_check(args):
    known = load_all_known_issues(args.known_issues_dir)
    observed = assign_occurrences(read_observations(sys.stdin, args.repo_root))
    leftovers = []
    for o in observed:
        key = (o["file"], o["textSha"], o["occurrence"])
        if key in known.get(o["rule"], set()):
            continue
        leftovers.append(o)
    if not leftovers:
        return 0
    leftovers.sort(key=lambda o: (o["file"], o["line"], o["rule"]))
    for o in leftovers:
        sys.stderr.write(
            f"{o['file']}:{o['line']} [{o['rule']}] {o['message']}\n"
        )
    sys.stderr.write(
        f"\n{len(leftovers)} new ast-grep violation(s) not in known_issues/. "
        "Run `make -C build astgrep-known-issues` to refresh the baseline "
        "once these are intentional.\n"
    )
    return 1


def cmd_regen(args):
    observed = assign_occurrences(read_observations(sys.stdin, args.repo_root))
    by_rule = defaultdict(list)
    for o in observed:
        by_rule[o["rule"]].append({
            "file": o["file"],
            "textSha": o["textSha"],
            "occurrence": o["occurrence"],
        })
    for rule in by_rule:
        by_rule[rule].sort(
            key=lambda e: (e["file"], e["textSha"], e["occurrence"])
        )
    args.known_issues_dir.mkdir(parents=True, exist_ok=True)
    existing = {p.stem: p for p in args.known_issues_dir.glob("*.yml")}
    for stem, path in existing.items():
        if stem not in by_rule:
            path.unlink()
    for rule, entries in by_rule.items():
        write_known_issues_file(
            args.known_issues_dir / f"{rule}.yml", rule, entries
        )
    return 0


def main(argv):
    args = parse_args(argv)
    if args.regen:
        return cmd_regen(args)
    return cmd_check(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
