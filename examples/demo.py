"""A tiny demo agent. It proposes a mix of safe and dangerous actions; the gate decides.

    python examples/demo.py
"""
from __future__ import annotations

from railward import decide, load_policy

PROPOSED = [
    {"action": "bash", "command": "ls -la"},
    {"action": "read", "path": "README.md"},
    {"action": "write", "path": "work/out.txt"},
    {"action": "bash", "command": "rm -rf /"},
    {"action": "bash", "command": "echo ok; rm -rf /important"},
    {"action": "write", "path": "secrets/prod.env"},
    {"action": "write", "path": "work/../../etc/passwd"},
]


def main() -> None:
    policy = load_policy("examples/safe.yaml")
    for request in PROPOSED:
        d = decide(request, policy)
        label = request.get("command") or request.get("path")
        print(f"{d.verdict:<5} {request['action']:<5} {label:<28} # {d.reason}")


if __name__ == "__main__":
    main()
