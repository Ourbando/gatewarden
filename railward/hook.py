"""Claude Code PreToolUse adapter: fail-closed and veto-only.

Reads the hook JSON on stdin, decides via the pure gate, and prints the ``hookSpecificOutput``
Claude Code expects. Two safety properties it guarantees:

* Veto-only. It never emits ``allow``. It can only DENY or ASK, so the gate tightens the
  harness's permissions and never widens them. A safe or allow-verdict action emits nothing and
  the harness's own permission flow governs. A policy bug can therefore only over-restrict (the
  safe direction), never over-permit.
* Fail-closed, never fail-open. An unset ``RAILWARD_POLICY`` makes the gate invisible (zero
  behavior change on install). A configured policy that cannot load, unparseable input, a
  non-mapping payload, or any internal error all resolve to ASK. The hook never crashes: a
  crashing PreToolUse hook exits non-zero, which a harness treats as a non-blocking error and
  runs the tool anyway, which would be fail-open. So every path is guarded.

Wire it up in ``.claude/settings.json``::

    {"hooks": {"PreToolUse": [{"matcher": "*",
       "hooks": [{"type": "command", "command": "python -m railward.hook"}]}]}}

Set ``RAILWARD_POLICY`` to your policy file to enable the gate; unset means it is not installed.
"""
from __future__ import annotations

import json
import os
import sys

from . import art as _art
from .decide import decide
from .policy import load_policy


def tool_to_request(tool_name: str, tool_input: dict) -> dict:
    tool_input = tool_input or {}
    if tool_name == "Bash":
        return {"action": "bash", "command": tool_input.get("command", "")}
    if tool_name in ("Edit", "Write", "MultiEdit", "NotebookEdit"):
        return {"action": "write", "path": tool_input.get("file_path") or tool_input.get("path", "")}
    if tool_name == "Read":
        return {"action": "read", "path": tool_input.get("file_path", "")}
    request = {"action": (tool_name or "unknown").lower()}
    if tool_input.get("file_path"):
        request["path"] = tool_input["file_path"]
    if tool_input.get("command"):
        request["command"] = tool_input["command"]
    return request


def _emit(permission_decision: str, reason: str) -> None:
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": permission_decision,
                    "permissionDecisionReason": reason,
                }
            }
        )
    )


def resolve(stdin_text: str, policy_source: str | None) -> tuple[str | None, str]:
    """Pure hook decision: (stdin text, policy source or None) -> (emitted decision, reason).

    The emitted decision is ``deny``, ``ask``, or ``None`` (emit nothing). It is NEVER ``allow``
    (veto-only) and the function NEVER raises (fail-closed to ``ask``). Kept pure and I/O-free so
    the fail-open probe battery can attest it inside the signed proof.
    """
    if not policy_source:
        return None, "unconfigured: gate not installed; the harness governs"

    try:
        data = json.loads(stdin_text)
    except (json.JSONDecodeError, ValueError):
        return "ask", "gate received unparseable tool-call input; failing closed"

    try:
        policy = load_policy(policy_source)
    except Exception as exc:  # noqa: BLE001 - fail closed on ANY load failure
        return "ask", f"gate policy failed to load; failing closed: {exc}"

    try:
        request = tool_to_request(data.get("tool_name", ""), data.get("tool_input", {}))
        decision = decide(request, policy)
    except Exception as exc:  # noqa: BLE001 - non-mapping payload or any internal error
        return "ask", f"gate errored while deciding; failing closed: {exc}"

    if decision.verdict == "deny":
        return "deny", decision.reason
    if decision.verdict == "ask":
        return "ask", decision.reason
    # allow -> veto-only: emit nothing, the harness's own permission flow governs.
    return None, decision.reason


def resolve_bytes(stdin_bytes: bytes, policy_source: str | None) -> tuple[str | None, str]:
    """Pure hook decision over RAW stdin bytes. Decodes defensively so undecodable input can never
    crash the hook: invalid bytes survive the decode (surrogateescape) and then fail JSON parsing,
    which ``resolve`` turns into a fail-closed ASK. This is the entry the probe battery attests, so
    the signed proof covers the byte decode, not only the pure string path."""
    text = stdin_bytes.decode("utf-8", "surrogateescape")
    return resolve(text, policy_source)


def main(argv: list[str] | None = None) -> int:
    # Unconditionally fail-closed: ANY exception (a decode error, a broken read, anything at all)
    # becomes ASK, never a non-zero exit. A crashing PreToolUse hook is treated as a non-blocking
    # error by the harness and the tool runs, so a crash would itself be a fail-open; this guard
    # forecloses that.
    try:
        configured = os.environ.get("RAILWARD_POLICY")
        raw = sys.stdin.buffer.read() if configured else b""
        decision, reason = resolve_bytes(raw, configured)
        if decision is not None:
            _emit(decision, reason)
            # A cute reaction to stderr the moment the gate catches something. Never touches the
            # stdout JSON protocol, and is silenced with RAILWARD_NO_ART for logs and CI.
            if os.environ.get("RAILWARD_NO_ART") is None:
                art = _art.react(decision, reason)
                if art:
                    print(art, file=sys.stderr)
    except Exception:  # noqa: BLE001 - last-resort fail-closed; the hook must never crash
        _emit("ask", "gate crashed; failing closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
