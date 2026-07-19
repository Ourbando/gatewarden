"""Declarative policy: an ordered list of rules, evaluated first-match-wins.

The default is fail-closed. A policy may only set ``default: deny`` or ``default: ask``;
``default: allow`` is rejected on load, so a policy can never silently permit everything.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

EFFECTS = ("allow", "deny", "ask")

# A group that contains an unbounded quantifier and is itself quantified, e.g. ``(a+)+`` or
# ``(.*)*``. This is the classic catastrophic-backtracking (ReDoS) shape: matching a crafted input
# can take exponential time, which would hang the gate. Such a regex is rejected at load, so a
# policy typo cannot turn the gate into a denial-of-service (a hang is a fail-open).
_CATASTROPHIC = re.compile(r"\([^()]*[+*}][^()]*\)[*+{]")


def _is_catastrophic_regex(pattern: str) -> bool:
    return _CATASTROPHIC.search(pattern) is not None


@dataclass(frozen=True)
class Rule:
    effect: str                 # allow | deny | ask
    action: str = "*"           # fnmatch glob on the request action (e.g. "bash", "write", "*")
    command: str | None = None  # regex (case-insensitive) matched against the command
    path: str | None = None     # fnmatch glob matched against the canonicalized path
    reason: str = ""
    id: str = ""
    # Precompiled at construction so an invalid regex is a loud load error, never a silent skip at
    # decision time (a skipped deny rule is a fail-open by typo).
    command_re: "re.Pattern[str] | None" = field(default=None, compare=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.effect not in EFFECTS:
            raise ValueError(f"bad effect {self.effect!r}, expected one of {EFFECTS}")
        if self.command is not None:
            try:
                compiled = re.compile(self.command, re.IGNORECASE)
            except re.error as exc:
                raise ValueError(
                    f"rule {self.id!r}: invalid command regex {self.command!r}: {exc}"
                ) from exc
            if _is_catastrophic_regex(self.command):
                raise ValueError(
                    f"rule {self.id!r}: command regex {self.command!r} can catastrophically "
                    f"backtrack (a quantified group over an unbounded quantifier); simplify it so "
                    f"the gate cannot be hung by a crafted command"
                )
            object.__setattr__(self, "command_re", compiled)


@dataclass(frozen=True)
class Policy:
    rules: tuple[Rule, ...]
    default: str = "deny"       # fail-closed


def load_policy(source: str | Path, *, text: bool = False) -> Policy:
    """Load a policy from a YAML file (or, with ``text=True``, a YAML string)."""
    raw = str(source) if text else Path(source).read_text(encoding="utf-8")
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise ValueError("policy must be a mapping")

    default = data.get("default", "deny")
    if default not in ("deny", "ask"):
        raise ValueError("default must be 'deny' or 'ask' (allow-by-default is forbidden)")

    rules: list[Rule] = []
    for i, r in enumerate(data.get("rules") or []):
        if not isinstance(r, dict):
            raise ValueError("each rule must be a mapping")
        if "effect" not in r:
            raise ValueError(f"rule {i} is missing 'effect'")
        rules.append(
            Rule(
                effect=str(r["effect"]),
                action=str(r.get("action", "*")),
                command=None if r.get("command") is None else str(r["command"]),
                path=None if r.get("path") is None else str(r["path"]),
                reason=str(r.get("reason", "")),
                id=str(r.get("id", f"rule-{i}")),
            )
        )
    return Policy(rules=tuple(rules), default=default)
