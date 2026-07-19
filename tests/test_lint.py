"""The linter passes a sound policy and catches a dead deny rule."""
from railward import adversary, lint, load_policy
from railward.cli import main

_SHADOWED = """
default: deny
rules:
  - id: allow-all-bash
    effect: allow
    action: bash
  - id: block-rm
    effect: deny
    action: bash
    command: 'rm'
"""


def test_safe_policy_lints_clean():
    assert lint.lint_policy(load_policy("examples/safe.yaml")) == []


def test_strict_policy_lints_clean_and_blocks_every_attack():
    policy = load_policy("examples/strict.yaml")
    assert lint.lint_policy(policy) == []
    leaked = [r["attack"] for r in adversary.run_attacks(policy) if r["leaked"]]
    assert leaked == [], f"strict.yaml leaked: {leaked}"


def test_dead_deny_detected():
    problems = lint.lint_policy(load_policy(_SHADOWED, text=True))
    assert any("block-rm" in p for p in problems)


def test_cli_lint_clean_exit_0():
    assert main(["lint", "--policy", "examples/safe.yaml"]) == 0


def test_cli_lint_dead_deny_exit_1(tmp_path):
    p = tmp_path / "shadowed.yaml"
    p.write_text(_SHADOWED)
    assert main(["lint", "--policy", str(p)]) == 1


def test_cli_lint_invalid_regex_exit_2(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("default: deny\nrules:\n  - id: x\n    effect: deny\n    action: bash\n    command: '[oops'\n")
    assert main(["lint", "--policy", str(p)]) == 2
