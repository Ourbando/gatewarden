"""A policy with an invalid rule regex must be rejected at load, not silently skipped.

A deny rule whose regex does not compile used to be dropped at decision time, so the protection
it was meant to give silently vanished (a fail-open by typo). Loading such a policy must now
raise, which makes the hook fail closed to ASK rather than run the dangerous action.
"""
import pytest

from railward import load_policy
from railward.hook import resolve

_BAD = """
default: deny
rules:
  - id: block-rm
    effect: deny
    action: bash
    command: '[unclosed'
"""

_GOOD = """
default: deny
rules:
  - id: block-rm
    effect: deny
    action: bash
    command: 'rm'
"""


def test_invalid_regex_rejected_at_load():
    with pytest.raises(ValueError):
        load_policy(_BAD, text=True)


def test_valid_regex_loads_and_compiles():
    policy = load_policy(_GOOD, text=True)
    assert policy.rules[0].command_re is not None


_REDOS = """
default: deny
rules:
  - id: evil
    effect: deny
    action: bash
    command: '(a+)+$'
"""


def test_catastrophic_regex_rejected_at_load():
    # A ReDoS-prone rule regex must be refused at load so the gate cannot be hung (a hang is a
    # fail-open). The bundled example policies must still load.
    with pytest.raises(ValueError):
        load_policy(_REDOS, text=True)
    for example in ("examples/safe.yaml", "examples/strict.yaml"):
        assert load_policy(example).rules  # does not raise


def test_bad_policy_makes_hook_fail_closed(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(_BAD)
    # A configured policy that will not load must resolve to ASK, never allow the dangerous call.
    decision, _ = resolve('{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}', str(bad))
    assert decision == "ask"
