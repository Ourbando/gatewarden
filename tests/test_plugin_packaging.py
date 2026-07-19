"""The Claude Code plugin packaging is valid and gates a real call end to end."""
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_manifest_and_hooks_shape():
    manifest = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
    assert manifest["name"] and manifest.get("hooks") != "./hooks/hooks.json"
    hooks = json.loads((ROOT / "hooks" / "hooks.json").read_text())
    entry = hooks["hooks"]["PreToolUse"][0]
    assert entry["matcher"] == "*"
    assert "pretooluse.py" in entry["hooks"][0]["command"]


def _run_entrypoint(stdin, env_extra):
    env = {**os.environ, "CLAUDE_PLUGIN_ROOT": str(ROOT), **env_extra}
    return subprocess.run(
        [sys.executable, str(ROOT / "hooks" / "pretooluse.py")],
        input=stdin, capture_output=True, text=True, env=env,
    )


def test_entrypoint_denies_dangerous():
    proc = _run_entrypoint(
        '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}',
        {"RAILWARD_POLICY": str(ROOT / "examples" / "safe.yaml")},
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_entrypoint_non_utf8_fails_closed():
    # Raw non-UTF-8 bytes on stdin must not crash the hook (exit 1 -> harness runs the tool).
    env = {**os.environ, "CLAUDE_PLUGIN_ROOT": str(ROOT),
           "RAILWARD_POLICY": str(ROOT / "examples" / "safe.yaml")}
    proc = subprocess.run(
        [sys.executable, str(ROOT / "hooks" / "pretooluse.py")],
        input=b"\xff\xfe\x00 rm -rf /", capture_output=True, env=env,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout.decode())["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_entrypoint_invisible_when_unconfigured():
    env = {k: v for k, v in os.environ.items() if k != "RAILWARD_POLICY"}
    env["CLAUDE_PLUGIN_ROOT"] = str(ROOT)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "hooks" / "pretooluse.py")],
        input='{"tool_name":"Bash","tool_input":{"command":"ls"}}',
        capture_output=True, text=True, env=env,
    )
    assert proc.returncode == 0
    assert proc.stdout.strip() == ""
