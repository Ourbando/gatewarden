import json

from railward import hook
from railward.hook import resolve


def test_tool_to_request_mapping():
    assert hook.tool_to_request("Bash", {"command": "ls"}) == {"action": "bash", "command": "ls"}
    assert hook.tool_to_request("Write", {"file_path": "a"}) == {"action": "write", "path": "a"}
    assert hook.tool_to_request("Read", {"file_path": "a"}) == {"action": "read", "path": "a"}
    other = hook.tool_to_request("WebFetch", {"url": "x"})
    assert other["action"] == "webfetch"


def _decision(stdin_obj):
    return resolve(json.dumps(stdin_obj), "examples/safe.yaml")[0]


def test_hook_denies_rm():
    assert _decision({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}) == "deny"


def test_hook_is_veto_only_on_safe():
    # A safe command is not auto-approved; the gate stays silent (veto-only, never widens).
    assert _decision({"tool_name": "Bash", "tool_input": {"command": "ls -la"}}) is None


def test_hook_asks_on_bad_input():
    # Unparseable input fails closed to ASK (surface to a human), never deny-brick or allow.
    assert resolve("{ not json", "examples/safe.yaml")[0] == "ask"
