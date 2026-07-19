"""Fail-closed / veto-only contract for the hook, tested on the pure resolvers.

``resolve`` (str) and ``resolve_bytes`` (raw stdin bytes) are the decision core that the live
hook and the signed proof's probe battery both call. A missing or broken policy, unparseable
input, a non-mapping payload, or undecodable non-UTF-8 bytes must all resolve to ASK: never a
crash (a harness runs the tool when a hook exits non-zero, which would be a fail-open) and never
a silent allow. And the gate is veto-only: a safe action is silent, never ``allow``.
"""
import json

from railward.hook import resolve, resolve_bytes

DANGEROUS = json.dumps({"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}})
SAFE = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls -la"}})


def test_missing_policy_asks():
    assert resolve(DANGEROUS, "/does/not/exist.yaml")[0] == "ask"


def test_broken_policy_asks(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("{ this is : not valid yaml : [")
    assert resolve(DANGEROUS, str(bad))[0] == "ask"


def test_unparseable_input_asks():
    assert resolve("{ not json", "examples/safe.yaml")[0] == "ask"


def test_non_mapping_payload_asks():
    assert resolve(json.dumps(["not", "a", "dict"]), "examples/safe.yaml")[0] == "ask"


def test_non_utf8_bytes_ask_never_crash():
    # The exact byte payload the review reproduced as a crash; must fail closed to ASK now.
    assert resolve_bytes(b"\xff\xfe\x00 rm -rf /", "examples/safe.yaml")[0] == "ask"


def test_unconfigured_is_silent():
    assert resolve(DANGEROUS, None)[0] is None
    assert resolve_bytes(DANGEROUS.encode(), None)[0] is None


def test_safe_op_is_veto_only_never_allow():
    assert resolve(SAFE, "examples/safe.yaml")[0] is None


def test_dangerous_denied():
    assert resolve(DANGEROUS, "examples/safe.yaml")[0] == "deny"


def test_resolve_never_returns_allow():
    for src in (None, "/nope.yaml", "examples/safe.yaml"):
        for stdin in (DANGEROUS, SAFE, "{ not json", json.dumps([1, 2])):
            assert resolve(stdin, src)[0] != "allow"
