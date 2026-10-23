#!/usr/bin/env python3
"""Draw the five example-card logos into this directory.

Uses Pillow's built-in bitmap/FreeType default font (CC0 Aileron when FreeType is
available). Re-run from the repo root:

    python3 cards/examples/make_logos.py

The committed PNGs were produced by this script on Pillow 12.x. Pixel identity
depends on the FreeType build; if your Pillow lacks FreeType the glyphs differ
and the byte hashes will not match. Geometric shapes (monogram, star, heart,
paw, Wi-Fi arcs) are pure PIL drawing and stay identical across builds.
"""
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
OUT = Path(__file__).resolve().parent
W, H = 320, 100
def font(sz):
    return ImageFont.load_default(size=sz)
def base():
    im = Image.new("RGBA", (W, H), (0, 0, 0, 0)); return im, ImageDraw.Draw(im)
def text(d, x, s, col, sz=40):
    f = font(sz); bb = d.textbbox((0, 0), s, font=f)
    d.text((x, (H - (bb[3] - bb[1])) // 2 - bb[1]), s, font=f, fill=col)
# loyalty: orange circle with a star-ish diamond, "ECM"
im, d = base(); c = (200, 110, 30, 255)
d.ellipse((10, 10, 90, 90), fill=c)
d.polygon([(50, 22), (60, 45), (84, 50), (60, 55), (50, 78), (40, 55), (16, 50), (40, 45)], fill=(255, 255, 255, 255))
text(d, 110, "ECM", c, 48); im.save(OUT / "loyalty-logo.png")
# business: rounded square with initials "AE"
im, d = base(); c = (140, 190, 255, 255)
d.rounded_rectangle((10, 10, 90, 90), radius=18, fill=c)
f = font(40); bb = d.textbbox((0, 0), "AE", font=f)
d.text((50 - (bb[2] + bb[0]) // 2, 50 - (bb[3] + bb[1]) // 2), "AE", font=f, fill=(24, 32, 48, 255))
text(d, 110, "Studio", c, 44); im.save(OUT / "business-logo.png")
# wifi: three arcs and a dot, "Guest"
im, d = base(); c = (30, 100, 200, 255)
for r in (40, 28, 16):
    d.arc((50 - r, 75 - r, 50 + r, 75 + r), 225, 315, fill=c, width=7)
d.ellipse((44, 69, 56, 81), fill=c)
text(d, 110, "Guest", c, 48); im.save(OUT / "wifi-guest-logo.png")
# medical: green heart shape with white plus (not a red cross), "Info"
im, d = base(); c = (30, 120, 90, 255)
d.ellipse((12, 18, 52, 58), fill=c); d.ellipse((48, 18, 88, 58), fill=c)
d.polygon([(14, 45), (86, 45), (50, 88)], fill=c)
d.rectangle((44, 30, 56, 66), fill=(255, 255, 255, 255)); d.rectangle((32, 42, 68, 54), fill=(255, 255, 255, 255))
text(d, 110, "Info", c, 48); im.save(OUT / "medical-logo.png")
# pet: paw print from circles, "Pet"
im, d = base(); c = (150, 80, 40, 255)
d.ellipse((28, 48, 72, 88), fill=c)
for x, y in ((14, 32), (32, 14), (56, 14), (74, 32)):
    d.ellipse((x - 10, y, x + 10, y + 24), fill=c)
text(d, 110, "Pet", c, 48); im.save(OUT / "pet-logo.png")