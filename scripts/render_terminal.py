#!/usr/bin/env python3
"""Render real command output as a terminal-style PNG (used for the lab screenshots).
Usage: render_terminal.py OUT.png TITLE < text"""
import sys
from PIL import Image, ImageDraw, ImageFont
out, title = sys.argv[1], sys.argv[2]
lines = sys.stdin.read().rstrip("\n").expandtabs(4).split("\n")
font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 15)
bold = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 14)
cw, lh, pad, bar = 9.1, 20, 18, 34
W = int(max(90, max(len(l) for l in lines)) * cw + 2 * pad)
H = bar + pad * 2 + lh * len(lines)
img = Image.new("RGB", (W, H), (30, 30, 30))
d = ImageDraw.Draw(img)
d.rectangle([0, 0, W, bar], fill=(58, 58, 60))
for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
    d.ellipse([14 + i * 20, 11, 26 + i * 20, 23], fill=c)
d.text((W // 2, bar // 2), title, font=bold, fill=(220, 220, 220), anchor="mm")
y = bar + pad
for l in lines:
    col = (120, 220, 120) if l.startswith("$ ") else (230, 230, 230)
    if "ERROR" in l: col = (255, 110, 110)
    d.text((pad, y), l, font=font, fill=col)
    y += lh
img.save(out)
