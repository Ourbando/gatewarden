"""The gate: a pure decision function.

``decide(request, policy)`` returns a :class:`Decision`. It never touches the network or
filesystem and has no global state, so the same inputs always give the same output.

Design choices that matter for safety:

* Default-deny. If no rule matches, the policy default (deny or ask) applies.
* Fail-closed on bad input. A non-mapping request, a missing action, an oversized or
  unparseable command, or a non-string path is denied, not waved through.
* Evasion-resistant matching. Commands are tokenized and the argv[0] basename is used, so
  ``/bin/rm``, ``RM`` (case), extra whitespace, and ``a; rm -rf /`` style injection are all
  seen as the same ``rm``. Command regexes match case-insensitively. Paths are canonicalized
  (``.`` and ``..`` collapsed) before globbing, so ``work/../../etc`` cannot masquerade as an
  in-scope path.
* Compound-aware. A shell command is only as safe as its most dangerous part. The whole command,
  every top-level segment (split on ``| ; && || &``), every command- and process-substitution
  body (``$(...)``, ``<(...)``, ``>(...)`` and backticks, recursively), every output-redirection
  target (checked as a write) and every input-redirection target (checked as a read) are each
  evaluated, and the most restrictive verdict wins. An anchored allow (``^echo``) can no longer
  wave a payload through a pipe, and an allowed command cannot read a protected file through
  ``< secrets``. The whole command is always evaluated too, so a gap in decomposition can only
  miss an added deny, never open a hole.
"""
from __future__ import annotations

import fnmatch
import posixpath
import shlex
from dataclasses import dataclass

from .policy import Policy

_MAX_COMMAND = 100_000  # bound the matching input
_SEVERITY = ("allow", "ask", "deny")  # index is severity; most restrictive (highest) wins


@dataclass(frozen=True)
class Decision:
    verdict: str    # allow | deny | ask
    reason: str
    rule_id: str    # "" when the policy default applied


def _normalized_command(command: str) -> str | None:
    """Return a normalized command string, or None if it cannot be parsed."""
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    if not argv:
        return ""
    head = posixpath.basename(argv[0]) or argv[0]
    return " ".join([head, *argv[1:]])


def _canonical_path(path: str) -> str:
    # Pure normalization, no filesystem access: collapses '.', '..', and duplicate slashes.
    return posixpath.normpath(path)


def _glob(pattern: str, value: str) -> bool:
    return fnmatch.fnmatchcase(value, pattern)


def _segments(command: str) -> list[str]:
    """Split a command on top-level shell control operators (| || & && ; newline), respecting
    single and double quotes and backslash escapes, so an escaped or quoted operator is not a
    split point."""
    segs: list[str] = []
    buf: list[str] = []
    i, n = 0, len(command)
    quote: str | None = None
    while i < n:
        c = command[i]
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            buf.append(c)
            buf.append(command[i + 1])
            i += 2
            continue
        if c in ("'", '"'):
            quote = c
            buf.append(c)
            i += 1
            continue
        if command[i:i + 2] in ("&&", "||"):
            segs.append("".join(buf))
            buf = []
            i += 2
            continue
        if c in (";", "|", "&", "\n"):
            segs.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    segs.append("".join(buf))
    return [s.strip() for s in segs if s.strip()]


def _substitutions(command: str) -> list[str]:
    """Return the bodies of command and process substitutions: ``$(...)``, ``<(...)``, ``>(...)``
    (all nested-aware) and backticks, each of which executes a command. Single-quoted regions are
    skipped (no expansion happens there); double-quoted regions are scanned, because substitutions
    do execute inside double quotes."""
    subs: list[str] = []
    i, n = 0, len(command)
    in_single = False
    while i < n:
        c = command[i]
        if in_single:
            if c == "'":
                in_single = False
            i += 1
            continue
        if c == "'":
            in_single = True
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if command[i:i + 2] in ("$(", "<(", ">("):  # command and process substitution
            depth, j = 1, i + 2
            start = j
            while j < n and depth:
                if command[j] == "(":
                    depth += 1
                elif command[j] == ")":
                    depth -= 1
                j += 1
            subs.append(command[start:j - 1])
            i = j
            continue
        if c == "`":
            j = command.find("`", i + 1)
            if j == -1:
                break
            subs.append(command[i + 1:j])
            i = j + 1
            continue
        i += 1
    return subs


def _redirect_targets(command: str) -> list[str]:
    """Return write targets introduced by output redirection (``>`` ``>>`` ``>|`` ``&>``),
    quote-aware. These are files the command writes, so they are checked against write rules."""
    targets: list[str] = []
    i, n = 0, len(command)
    quote: str | None = None
    while i < n:
        c = command[i]
        if quote:
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == ">":
            j = i + 1
            while j < n and command[j] in (">", "|", "&"):
                j += 1
            while j < n and command[j] in (" ", "\t"):
                j += 1
            if j < n and command[j] == "(":  # >(cmd) is process substitution, handled elsewhere
                i = j + 1
                continue
            start = j
            while j < n and command[j] not in (" ", "\t", ";", "|", "&", "<", ">", "\n"):
                if command[j] in ("'", '"'):
                    qq = command[j]
                    j += 1
                    while j < n and command[j] != qq:
                        j += 1
                j += 1
            tgt = command[start:j].strip("'\"")
            if tgt:
                targets.append(tgt)
            i = j
            continue
        i += 1
    return targets


def _read_targets(command: str) -> list[str]:
    """Return files opened for reading via input redirection (``< file``), quote-aware. A heredoc
    (``<<``) delimiter and a process substitution (``<(...)``) are not files and are skipped; the
    latter is handled as a substitution. These targets are checked against read rules, so an
    allowed command cannot read a protected file through a redirection the path rules never saw."""
    targets: list[str] = []
    i, n = 0, len(command)
    quote: str | None = None
    while i < n:
        c = command[i]
        if quote:
            if c == quote:
                quote = None
            i += 1
            continue
        if c in ("'", '"'):
            quote = c
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            i += 2
            continue
        if c == "<":
            if command[i + 1:i + 2] in ("<", "("):  # heredoc or process substitution, not a file
                i += 2
                continue
            j = i + 1
            while j < n and command[j] in (" ", "\t"):
                j += 1
            start = j
            while j < n and command[j] not in (" ", "\t", ";", "|", "&", "<", ">", "\n"):
                if command[j] in ("'", '"'):
                    qq = command[j]
                    j += 1
                    while j < n and command[j] != qq:
                        j += 1
                j += 1
            tgt = command[start:j].strip("'\"")
            if tgt:
                targets.append(tgt)
            i = j
            continue
        i += 1
    return targets


def _fragments(command: str) -> list[str]:
    """Every independently-executable command string inside ``command``: top-level segments plus
    the bodies of every command substitution, recursively."""
    out: list[str] = []
    stack = [command]
    while stack:
        cur = stack.pop()
        out.extend(_segments(cur))
        stack.extend(_substitutions(cur))
    return out


def _match(action: str, normalized: str | None, command: str | None,
           canonical: str | None, policy: Policy) -> Decision:
    """The atomic rule loop: first match wins, else the fail-closed default."""
    for rule in policy.rules:
        if not _glob(rule.action, action):
            continue
        if rule.command is not None:
            if normalized is None or command is None:
                continue
            # Precompiled and validated at load, so it is never None here and never re-raises.
            rx = rule.command_re
            if not (rx.search(normalized) or rx.search(command)):
                continue
        if rule.path is not None:
            if canonical is None or not _glob(rule.path, canonical):
                continue
        return Decision(rule.effect, rule.reason or f"matched {rule.id}", rule.id)
    return Decision(policy.default, f"default-{policy.default}: no rule matched", "")


def _most_restrictive(decisions: list[Decision]) -> Decision:
    # max returns the first element on ties, and the whole-command decision is always first, so a
    # compound that resolves to the same severity keeps the whole command's rule attribution.
    return max(decisions, key=lambda d: _SEVERITY.index(d.verdict))


def _prepare(request: object) -> tuple[Decision | None, str, str | None, str | None]:
    """Shared front matter for decide/trace: validate the request. Returns an early fail-closed
    Decision (and empty rest) on malformed input, else (None, action, command, canonical)."""
    if not isinstance(request, dict):
        return Decision("deny", "malformed request: not a mapping", ""), "", None, None
    action = request.get("action")
    if not isinstance(action, str) or not action:
        return Decision("deny", "malformed request: missing action", ""), "", None, None
    command = request.get("command")
    if command is not None and (not isinstance(command, str) or len(command) > _MAX_COMMAND):
        return Decision("deny", "malformed command", ""), "", None, None
    path = request.get("path")
    if path is not None and not isinstance(path, str):
        return Decision("deny", "malformed path", ""), "", None, None
    canonical = _canonical_path(path) if path is not None else None
    return None, action, command, canonical


def _evaluate(action: str, command: str | None, canonical: str | None,
              policy: Policy) -> list[tuple[str, Decision]]:
    """Every labelled sub-decision that feeds the final verdict, in evaluation order. The whole
    command (with the request path), then each extra fragment as a command, then each output
    redirection as a write and each input redirection as a read."""
    if command is None:
        return [("action", _match(action, None, None, canonical, policy))]

    out: list[tuple[str, Decision]] = []
    seen: set[str] = set()
    for idx, frag in enumerate([command, *_fragments(command)]):
        if frag in seen:
            continue
        seen.add(frag)
        normalized = _normalized_command(frag)
        if normalized is None:
            return [("unparseable command", Decision("deny", "unparseable command", ""))]
        label = "command" if idx == 0 else "sub-command"
        frag_path = canonical if idx == 0 else None
        out.append((f"{label}: {frag}", _match(action, normalized, frag, frag_path, policy)))

    for tgt in _redirect_targets(command):
        out.append((f"writes: {tgt}", _match("write", None, None, _canonical_path(tgt), policy)))
    for tgt in _read_targets(command):
        out.append((f"reads: {tgt}", _match("read", None, None, _canonical_path(tgt), policy)))
    return out


def decide(request: object, policy: Policy) -> Decision:
    early, action, command, canonical = _prepare(request)
    if early is not None:
        return early
    return _most_restrictive([d for _, d in _evaluate(action, command, canonical, policy)])


def trace(request: object, policy: Policy) -> list[tuple[str, Decision]]:
    """The labelled sub-decisions behind ``decide``, for ``railward explain``. The final verdict is
    the most restrictive of these."""
    early, action, command, canonical = _prepare(request)
    if early is not None:
        return [("request", early)]
    return _evaluate(action, command, canonical, policy)
