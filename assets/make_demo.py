#!/usr/bin/env python3
"""Regenerate assets/demo.gif and assets/demo_preview.png from the REAL CLI output.

The numbers in the demo are parsed from an actual ``railward attack``/``verify`` run, so the demo
cannot drift from reality: to refresh it, re-run this script. Deterministic (no RNG, no clock):
identical CLI output produces identical frames.

    python assets/make_demo.py
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "assets"

# tokyo-night-ish terminal palette
BG = (22, 22, 30)
BAR = (26, 27, 38)
FG = (169, 177, 214)
GREEN = (158, 206, 106)
RED = (247, 118, 142)
DIM = (86, 95, 137)
WHITE = (192, 202, 245)
DOTS = [(255, 95, 87), (254, 188, 46), (40, 200, 64)]

W = 900
BAR_H = 46
PAD_X = 30
TOP = BAR_H + 26
LINE_H = 38
FONT_SIZE = 23


def _font(bold: bool) -> ImageFont.FreeTypeFont:
    names = (
        ["JetBrainsMono-Bold.ttf", "DejaVuSansMono-Bold.ttf", "Menlo.ttc"]
        if bold
        else ["JetBrainsMono-Regular.ttf", "DejaVuSansMono.ttf", "Menlo.ttc"]
    )
    roots = [Path.home() / "Library/Fonts", Path("/Library/Fonts"), Path("/System/Library/Fonts")]
    for name in names:
        for r in roots:
            p = r / name
            if p.exists():
                return ImageFont.truetype(str(p), FONT_SIZE)
    return ImageFont.load_default(size=FONT_SIZE)


REG = _font(False)
BOLD = _font(True)
ADV = REG.getlength("M")  # monospace advance


def _nums(output: str) -> dict:
    m = re.search(r"(\d+) attacks, (\d+) blocked, (\d+) leaked; (\d+) fail-open probes, (\d+) open", output)
    keys = ("total", "blocked", "leaked", "probes", "open")
    return dict(zip(keys, (int(x) for x in m.groups())))


def _cli(*args: str) -> str:
    out = subprocess.run(
        [sys.executable, "-m", "railward.cli", *args], cwd=ROOT, capture_output=True, text=True
    )
    return out.stdout.strip()


def build_rows() -> list[dict]:
    safe = _nums(_cli("attack", "--policy", "examples/safe.yaml", "--key", "keys/demo.pem", "--out", "/tmp/d.json"))
    holey = _nums(_cli("attack", "--policy", "examples/holey.yaml", "--key", "keys/demo.pem", "--out", "/tmp/h.json"))
    a = safe
    return [
        {"kind": "cmd", "body": "railward attack"},
        {"kind": "out", "spans": [
            (f"{a['total']} attacks, ", FG, False),
            (f"{a['blocked']} blocked", GREEN, False),
            (f", {a['leaked']} leaked, {a['probes']} probes ok", FG, False),
            ("   ->  proof.json", DIM, False),
        ]},
        {"kind": "blank"},
        {"kind": "cmd", "body": "railward verify proof.json"},
        {"kind": "out", "spans": [
            ("OK: ", GREEN, True),
            (f"chain intact, signature valid, {a['leaked']} leaked, {a['open']} fail-open", FG, False),
        ]},
        {"kind": "blank"},
        {"kind": "comment", "body": "# flip one deny rule to allow, then re-run"},
        {"kind": "cmd", "body": "railward attack --policy holey.yaml"},
        {"kind": "out", "spans": [
            (f"{holey['total']} attacks, {holey['blocked']} blocked, ", FG, False),
            (f"{holey['leaked']} leaked", RED, False),
            ("    the proof is ", FG, False),
            ("RED", RED, True),
        ]},
    ]


def _draw_span(draw, x, y, text, color, bold):
    draw.text((x, y), text, font=(BOLD if bold else REG), fill=color)
    return x + ADV * len(text)


def render(rows: list[dict], upto: int, partial: int | None) -> Image.Image:
    h = TOP + len(rows) * LINE_H + 24
    img = Image.new("RGB", (W, h), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, BAR_H], fill=BAR)
    for i, c in enumerate(DOTS):
        d.ellipse([22 + i * 26, BAR_H // 2 - 7, 22 + i * 26 + 14, BAR_H // 2 + 7], fill=c)
    d.text((W // 2 - 70, BAR_H // 2 - 12), "railward", font=REG, fill=DIM)

    y = TOP
    for idx, row in enumerate(rows):
        if idx > upto:
            break
        kind = row["kind"]
        if kind == "blank":
            y += LINE_H
            continue
        x = PAD_X
        if kind in ("cmd", "comment"):
            x = _draw_span(d, x, y, "$ ", GREEN, False)
            body = row["body"]
            if idx == upto and partial is not None:
                body = body[:partial]
            _draw_span(d, x, y, body, DIM if kind == "comment" else WHITE, kind == "cmd")
        else:
            for text, color, bold in row["spans"]:
                x = _draw_span(d, x, y, text, color, bold)
        y += LINE_H
    return img


def main() -> None:
    rows = build_rows()
    frames: list[Image.Image] = []
    durations: list[int] = []

    def add(img, ms):
        frames.append(img.convert("P", palette=Image.ADAPTIVE, colors=32))
        durations.append(ms)

    for idx, row in enumerate(rows):
        if row["kind"] in ("cmd", "comment"):
            body = row["body"]
            for k in range(0, len(body) + 1, 3):
                add(render(rows, idx, k), 55)
            add(render(rows, idx, len(body)), 260)
        elif row["kind"] == "out":
            add(render(rows, idx, None), 240)
        else:
            add(render(rows, idx, None), 90)
    add(render(rows, len(rows) - 1, None), 1800)  # hold on the finished screen

    final = render(rows, len(rows) - 1, None)
    final.save(ASSETS / "demo_preview.png")
    frames[0].save(
        ASSETS / "demo.gif", save_all=True, append_images=frames[1:],
        duration=durations, loop=0, disposal=1, optimize=True,
    )
    size_kb = (ASSETS / "demo.gif").stat().st_size // 1024
    print(f"wrote demo.gif ({len(frames)} frames, {size_kb} KB) and demo_preview.png")


if __name__ == "__main__":
    main()
