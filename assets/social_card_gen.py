"""Generate the railward social preview card (1280x640).

Terminal/dracula identity, matching docs/verify.html and the demo. Pure drawing, no external
images, no private markers. Rerun: python assets/social_card_gen.py
"""
from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640
BG = (40, 42, 54)        # #282a36 dracula
FG = (248, 248, 242)     # #f8f8f2
GREEN = (80, 249, 123)   # #50fa7b
CYAN = (139, 233, 253)   # #8be9fd
PURPLE = (189, 147, 249) # #bd93f9
COMMENT = (98, 114, 164) # #6272a4
LINE = (68, 71, 90)      # #44475a
MONO = "/System/Library/Fonts/Menlo.ttc"


def font(size, bold=False):
    return ImageFont.truetype(MONO, size, index=1 if bold else 0)


def text(d, xy, s, f, fill, anchor="la"):
    d.text(xy, s, font=f, fill=fill, anchor=anchor)


def chip(d, x, y, label, color):
    f = font(26, bold=True)
    tw = d.textbbox((0, 0), label, font=f)[2]
    pad = 18
    d.rounded_rectangle([x, y, x + tw + 2 * pad, y + 46], radius=8, fill=LINE)
    text(d, (x + pad, y + 23), label, f, color, anchor="lm")
    return x + tw + 2 * pad + 16


def main():
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    margin = 72
    # stamp box, top-right (the Ward VERIFIED seal, echoing the CLI); placed first, clear of text
    bw, bh = 250, 132
    bx, by = W - margin - bw, 48
    d.rounded_rectangle([bx, by, bx + bw, by + bh], radius=14, outline=GREEN, width=3)
    text(d, (bx + bw // 2, by + 52), "(^_^)", font(44, bold=True), GREEN, anchor="mm")
    text(d, (bx + bw // 2, by + 100), "VERIFIED", font(28, bold=True), GREEN, anchor="mm")

    # prompt line, top-left (short, clear of the box)
    text(d, (margin, 62), "$", font(26, bold=True), GREEN)
    text(d, (margin + 34, 62), "railward verify proof.json", font(26), COMMENT)

    # title
    text(d, (margin, 158), "railward", font(104, bold=True), FG)

    # tagline, two lines
    text(d, (margin, 300), "Most agent guardrails ask you to trust them.", font(36), FG)
    text(d, (margin, 346), "This one attacks itself and hands you the proof.", font(36), PURPLE)

    # chips row
    y = 434
    x = margin
    x = chip(d, x, y, "41/41 blocked", GREEN)
    x = chip(d, x, y, "signed proof", CYAN)
    x = chip(d, x, y, "offline", PURPLE)
    x = chip(d, x, y, "MIT", FG)

    # url, bottom
    text(d, (margin, H - 64), "github.com/Ourbando/railward", font(28), COMMENT)

    img.save("assets/social-card.png")
    print("wrote assets/social-card.png", img.size)


if __name__ == "__main__":
    main()
