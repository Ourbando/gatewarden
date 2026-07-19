"""Fail-open probe battery: hook inputs that must never let an action through by error.

The action adversary (``adversary.py``) proves the gate refuses dangerous ACTIONS. This battery
proves the surrounding hook cannot FAIL OPEN: a missing or broken policy, unparseable input, or
a non-mapping payload, or undecodable (non-UTF-8) bytes must resolve to a blocking decision (deny
or ask), and a safe action must never be widened to allow. Each probe runs the same raw-bytes
entry the live hook uses (``hook.resolve_bytes``) and records whether it failed open, so the
signed proof attests the byte decode, not only the pure string path. Expected result is zero
fail-opens; regress the hook (re-add an allow emission, drop a fail-closed guard, let it crash)
and a probe flips, so the signed proof goes red.

A probe with ``must_block`` True carries a payload the hook must not let proceed silently, so a
``None`` (silent) or ``allow`` decision is a fail-open. A probe with ``must_block`` False asserts
the veto-only property: any ``allow`` is a fail-open, but silence is correct.
"""
from __future__ import annotations

from .hook import resolve_bytes

_RM = b'{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}'

# A path that cannot exist on any machine, so these probes are deterministic across cwd and OS
# (the decision is what is recorded and hashed, never the OS-specific error string).
_NO_POLICY = "/railward/__no_such_policy__.yaml"

PROBES: list[dict] = [
    # A configured policy that will not load must ASK on a dangerous call, never crash, never allow.
    {"name": "broken-policy", "stdin": _RM, "policy": _NO_POLICY, "must_block": True},
    # Unparseable input fails closed to ASK before any policy is even consulted.
    {"name": "unparseable-input", "stdin": b"{ not json", "policy": _NO_POLICY, "must_block": True},
    # Undecodable non-UTF-8 bytes must not crash the read; they fail closed to ASK.
    {"name": "non-utf8-input", "stdin": b"\xff\xfe\x00 rm -rf /", "policy": _NO_POLICY, "must_block": True},
    # No policy configured: the gate is not installed and stays silent (invisible), never allow.
    {"name": "unconfigured-invisible", "stdin": _RM, "policy": None, "must_block": False},
]


def _failed_open(decision: str | None, must_block: bool) -> bool:
    if decision == "allow":
        return True                      # veto-only: allow always widens
    if must_block and decision not in ("deny", "ask"):
        return True                      # a dangerous input slipped through silently
    return False


def run_probes(probes: list[dict] | None = None) -> list[dict]:
    """Run every probe through the same raw-bytes entry the hook uses, sorted for determinism."""
    results = []
    for probe in sorted(probes if probes is not None else PROBES, key=lambda p: p["name"]):
        decision, _reason = resolve_bytes(probe["stdin"], probe["policy"])
        results.append(
            {
                "probe": probe["name"],
                "decision": decision if decision is not None else "silent",
                "failed_open": _failed_open(decision, probe["must_block"]),
            }
        )
    return results
