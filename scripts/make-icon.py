#!/usr/bin/env python3
"""Generates the original Cairn app icon (1024px): stacked cairn stones at dusk.

Original artwork drawn procedurally with Pillow — no external assets, no logos.
Output: ios/Resources/Assets.xcassets/AppIcon.appiconset/{icon1024.png,Contents.json}

Usage: python3 scripts/make-icon.py   (run from repo root; needs Pillow)
"""
import json
import os

from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "ios", "Resources", "Assets.xcassets", "AppIcon.appiconset")
SIZE = 1024


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def rounded_stone(draw, cx, cy, w, h, color, highlight):
    box = [cx - w / 2, cy - h / 2, cx + w / 2, cy + h / 2]
    draw.rounded_rectangle(box, radius=h / 2.2, fill=color)
    # subtle top highlight
    hi_box = [box[0] + w * 0.12, box[1] + h * 0.12, box[2] - w * 0.12, box[1] + h * 0.42]
    draw.rounded_rectangle(hi_box, radius=h / 5, fill=highlight)


def main():
    img = Image.new("RGB", (SIZE, SIZE))
    d = ImageDraw.Draw(img)

    # dusk sky gradient
    top = (24, 32, 56)
    bottom = (52, 44, 74)
    for y in range(SIZE):
        d.line([(0, y), (SIZE, y)], fill=lerp(top, bottom, y / SIZE))

    # faint stars
    stars = [(112, 128, 3), (318, 88, 2), (524, 148, 2), (704, 96, 3), (868, 168, 2),
             (208, 232, 2), (610, 210, 2), (776, 262, 2), (392, 190, 2), (936, 300, 2)]
    for x, y, r in stars:
        d.ellipse([x - r, y - r, x + r, y + r], fill=(214, 222, 240))

    # ground
    ground_top = int(SIZE * 0.80)
    d.ellipse([SIZE * 0.05, ground_top, SIZE * 0.95, SIZE * 1.25], fill=(38, 34, 52))

    # stacked stones, bottom to top, slightly irregular widths
    cx = SIZE * 0.5
    stones = [
        (SIZE * 0.560, SIZE * 0.130, (94, 96, 118), (120, 122, 142)),
        (SIZE * 0.480, SIZE * 0.110, (110, 108, 126), (136, 134, 150)),
        (SIZE * 0.395, SIZE * 0.095, (126, 122, 138), (152, 148, 162)),
        (SIZE * 0.305, SIZE * 0.082, (142, 136, 150), (168, 162, 174)),
        (SIZE * 0.215, SIZE * 0.070, (158, 150, 162), (184, 176, 186)),
    ]
    y = SIZE * 0.885
    for w, h, base, hi in stones:
        y -= h * 0.92
        rounded_stone(d, cx, y, w, h, base, hi)
        y -= h * 0.10

    # small guiding cairn glow dot on the top stone
    d.ellipse([cx - 12, y - 12, cx + 12, y + 12], fill=(255, 214, 140))

    os.makedirs(OUT_DIR, exist_ok=True)
    out_png = os.path.join(OUT_DIR, "icon1024.png")
    img.save(out_png)
    with open(os.path.join(OUT_DIR, "Contents.json"), "w") as f:
        json.dump({
            "images": [
                {"filename": "icon1024.png", "idiom": "universal",
                 "platform": "ios", "size": "1024x1024"}
            ],
            "info": {"author": "xcode", "version": 1},
        }, f, indent=2)
    print(f"icon written to {out_png}")


if __name__ == "__main__":
    main()
