"""Reactions: cute art the gate shows the moment it catches something, and a living portcullis
that draws a real proof result. Cosmetic only, never imported by the decision core, so the gate
stays a pure function. All output is deterministic (no RNG): the mascot is picked from the reason
text, so the same block always draws the same face.

Colour is auto-detected from the stream and can be forced off with ``NO_COLOR`` (or ``color=False``).
Set ``RAILWARD_NO_ART=1`` to silence the mascots entirely (for logs and CI).
"""
from __future__ import annotations

import os
import sys

# A little gate-keeper. It scowls on a deny and squints on an ask. Kept to three lines so it fits
# in a hook message without taking over the terminal.
_DENY_FACES = ("(>_<)", "(ò_ó)", "(x_x)", "(#_#)")  # single-width so the box always aligns
_ASK_FACE = "(o_O)"


def _mascot(face: str, label: str) -> list[str]:
    return [
        "  ╭───────╮",
        f"  │ {face:^5} │  {label}",
        "  ╰──╥─╥──╯",
    ]


def color_enabled(stream, explicit: bool | None = None) -> bool:
    if explicit is not None:
        return explicit
    if os.environ.get("NO_COLOR") is not None:
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def _paint(lines: list[str], code: str, on: bool) -> str:
    if not on:
        return "\n".join(lines)
    return "\n".join(f"\033[{code}m{ln}\033[0m" for ln in lines)


def react(verdict: str, reason: str, *, color: bool | None = None, stream=None) -> str:
    """Return the mascot reaction for a blocking verdict (deny or ask). Empty string otherwise."""
    stream = stream if stream is not None else sys.stderr
    on = color_enabled(stream, color)
    if verdict == "deny":
        face = _DENY_FACES[len(reason) % len(_DENY_FACES)]  # deterministic variety
        lines = _mascot(face, "DENIED")
        lines.append(f"     {reason}")
        return _paint(lines, "91", on)  # red
    if verdict == "ask":
        lines = _mascot(_ASK_FACE, "ASK A HUMAN")
        lines.append(f"     {reason}")
        return _paint(lines, "93", on)  # yellow
    return ""


def portcullis(total: int, leaked: int, *, color: bool | None = None, stream=None) -> str:
    """Draw the proof as a portcullis: one bar per attack, held bars intact, leaked bars broken.
    Bar count is the real attack count and broken bars are the real leaks, so the picture is a
    measurement of the proof, not decoration."""
    stream = stream if stream is not None else sys.stdout
    on = color_enabled(stream, color)
    held = total - leaked
    # The last `leaked` bars are drawn broken; which specific ones is cosmetic, the count is real.
    bars = "".join("│" if i < held else "╳" for i in range(total))
    label = f" {held}/{total} held "
    width = max(len(bars), len(label))
    bars = bars.ljust(width)
    top = "╔" + label.center(width, "═") + "╗"
    mid = "║" + bars + "║"
    bot = "╚" + "═" * width + "╝"
    if not on:
        return f"{top}\n{mid}\n{bot}"
    tone = "92" if leaked == 0 else "91"  # all-green when clean, red when holed
    return "\n".join(f"\033[{tone}m{ln}\033[0m" for ln in (top, mid, bot))
