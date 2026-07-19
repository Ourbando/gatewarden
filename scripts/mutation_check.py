#!/usr/bin/env python3
"""Prove the tests have teeth.

A green suite is worthless if the tests would still pass with the safety logic broken. This
applies a set of hand-picked mutations to the decision core and the policy loader, each of which
removes a real protection, and asserts the suite goes RED for every one. A mutation the tests do
not catch (a "survivor") is a hole in the tests and fails this gate. Wired into CI; run locally
with ``python scripts/mutation_check.py``.
"""
from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# (file, find, replace, what protection this removes). Each must make at least one test fail.
MUTATIONS = [
    ("railward/decide.py",
     '_SEVERITY = ("allow", "ask", "deny")',
     '_SEVERITY = ("deny", "ask", "allow")',
     "invert severity so 'most restrictive' becomes least restrictive"),
    ("railward/decide.py",
     'for idx, frag in enumerate([command, *_fragments(command)]):',
     'for idx, frag in enumerate([command]):',
     "disable compound-command decomposition"),
    ("railward/decide.py",
     'for tgt in _read_targets(command):',
     'for tgt in []:',
     "stop checking input-redirection reads"),
    ("railward/decide.py",
     'if not isinstance(request, dict):',
     'if False and not isinstance(request, dict):',
     "drop the not-a-mapping guard (a non-dict request would crash the gate)"),
    ("railward/policy.py",
     'if _is_catastrophic_regex(self.command):',
     'if False and _is_catastrophic_regex(self.command):',
     "accept catastrophic-backtracking policy regexes"),
    ("railward/hook.py",
     'if decision.verdict == "deny":',
     'if False and decision.verdict == "deny":',
     "let the hook stop emitting deny"),
]

# Fast, high-signal subset; the mutations all live in these areas.
TESTS = [
    "tests/test_decide.py", "tests/test_compound.py", "tests/test_redirection.py",
    "tests/test_policy_validation.py", "tests/test_fuzz.py", "tests/test_hook_failclosed.py",
    "tests/test_purity.py",
]


def _suite_passes() -> bool:
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *TESTS],
        cwd=ROOT, capture_output=True, text=True,
    )
    return r.returncode == 0


def main() -> int:
    killed, survivors = 0, []
    applied = MUTATIONS
    for path, find, replace, what in applied:
        f = ROOT / path
        original = f.read_text(encoding="utf-8")
        if find not in original:
            survivors.append(f"{path}: mutation target not found ({what})")
            continue
        f.write_text(original.replace(find, replace, 1), encoding="utf-8")
        try:
            if _suite_passes():
                survivors.append(f"{path}: SURVIVED, not caught: {what}")
            else:
                killed += 1
                print(f"  killed: {what}")
        finally:
            f.write_text(original, encoding="utf-8")

    total = len(applied)
    print(f"\nmutants killed: {killed}/{total}")
    if survivors:
        print("SURVIVORS (the tests do not catch these):", file=sys.stderr)
        for s in survivors:
            print(f"  - {s}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
