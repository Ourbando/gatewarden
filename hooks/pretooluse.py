#!/usr/bin/env python3
"""Claude Code plugin entrypoint for the PreToolUse gate.

Adds the plugin root to ``sys.path`` so the bundled ``railward`` package imports without a separate
pip install, then delegates to the same fail-closed, veto-only resolver as ``python -m railward.hook``.
The gate is invisible until ``RAILWARD_POLICY`` names a policy file, so installing the plugin changes
no behavior on its own.
"""
import os
import sys

_root = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _root not in sys.path:
    sys.path.insert(0, _root)

from railward.hook import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
