"""Static proof that the decision core is pure.

The gate's whole claim rests on ``decide`` being a deterministic function of its inputs: no
network, no filesystem, no clock, no randomness, no global mutable state. We do not merely assert
this in prose, we prove it by parsing the module and refusing anything that could break it. If a
future edit imports ``os`` or calls ``open`` in the decision path, this test goes red before the
proof or the docs can drift.
"""
from __future__ import annotations

import ast
from pathlib import Path

# Modules that would let the decision core reach the outside world or become non-deterministic.
FORBIDDEN_IMPORTS = {
    "os", "sys", "io", "socket", "subprocess", "shutil", "pathlib",
    "time", "datetime", "random", "secrets", "urllib", "http",
    "requests", "threading", "asyncio", "sqlite3", "logging",
}
# Builtins whose mere presence in the core would break purity or determinism.
FORBIDDEN_CALLS = {"open", "eval", "exec", "compile", "__import__", "input", "print"}

CORE = Path(__file__).resolve().parent.parent / "railward" / "decide.py"


def _tree() -> ast.Module:
    return ast.parse(CORE.read_text(encoding="utf-8"), filename=str(CORE))


def test_core_imports_are_pure() -> None:
    tree = _tree()
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    leaked = imported & FORBIDDEN_IMPORTS
    assert not leaked, f"decision core imports impure modules: {sorted(leaked)}"


def test_core_makes_no_impure_calls() -> None:
    tree = _tree()
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            called.add(node.func.id)
    leaked = called & FORBIDDEN_CALLS
    assert not leaked, f"decision core makes impure calls: {sorted(leaked)}"


def test_core_holds_no_module_level_mutable_state() -> None:
    # Module-level constants are fine; a mutable list/dict/set bound at module scope is a
    # hidden channel that could make decide() depend on prior calls.
    tree = _tree()
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, (ast.List, ast.Dict, ast.Set)):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            raise AssertionError(f"decision core holds mutable module state: {names}")


def test_decision_is_deterministic() -> None:
    # Behavioural companion to the static checks: identical inputs, identical output, twice.
    from railward.decide import decide
    from railward.policy import load_policy

    policy = load_policy("examples/safe.yaml")
    request = {"action": "bash", "command": "rm -rf /"}
    first = decide(request, policy)
    second = decide(request, policy)
    assert first == second
