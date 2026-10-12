"""Render an asciicast v2 file to an animated GIF (pyte terminal emulation + Pillow).

Usage: render_gif.py IN.cast OUT.gif. Uses the macOS Menlo and Apple Symbols fonts.
"""
import json, re, sys
import pyte
from PIL import Image, ImageDraw, ImageFont

CAST, OUT = sys.argv[1], sys.argv[2]
FPS_STEP = 0.1          # sample the emulated screen every 100 ms
FONT_PX = 15
PAD_X, PAD_TOP, PAD_BOT, BAR = 22, 14, 18, 38
BG, FG = (13, 17, 23), (201, 209, 217)
PAL = {
    "black": (72, 79, 88), "red": (255, 123, 114), "green": (86, 211, 100), "brown": (227, 179, 65),
    "blue": (121, 192, 255), "magenta": (210, 168, 255), "cyan": (86, 212, 221), "white": (240, 246, 252),
    "brightblack": (110, 118, 129), "brightred": (255, 161, 152), "brightgreen": (126, 231, 135),
    "brightbrown": (240, 200, 100), "brightblue": (165, 214, 255), "brightmagenta": (226, 197, 255),
    "brightcyan": (150, 230, 240), "brightwhite": (255, 255, 255),
}
reg = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", FONT_PX, index=0)
bold = ImageFont.truetype("/System/Library/Fonts/Menlo.ttc", FONT_PX, index=1)
sym = ImageFont.truetype("/System/Library/Fonts/Apple Symbols.ttf", FONT_PX)
CW = round(reg.getlength("M")); CH = FONT_PX + 6

lines = open(CAST).read().splitlines()
hdr = json.loads(lines[0]); events = [json.loads(l) for l in lines[1:]]
cols, rows = hdr["width"], hdr["height"]
W, H = PAD_X * 2 + cols * CW, BAR + PAD_TOP + rows * CH + PAD_BOT
screen = pyte.Screen(cols, rows); stream = pyte.Stream(screen)

def prep(d):  # pyte has no "dim"; map it to bright-black
    return re.sub(r"\x1b\[2m", "\x1b[90m", d)

def colour(c, default):
    if c == "default": return default
    if c in PAL: return PAL[c]
    if re.fullmatch(r"[0-9a-f]{6}", c): return tuple(int(c[i:i+2], 16) for i in (0, 2, 4))
    return default

def frame():
    im = Image.new("RGB", (W, H), BG); d = ImageDraw.Draw(im)
    d.rectangle([0, 0, W, BAR], fill=(22, 27, 34))
    for i, col in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([18 + i * 22, 13, 30 + i * 22, 25], fill=col)
    t = "bastyn"; d.text((W / 2 - reg.getlength(t) / 2, 10), t, font=reg, fill=(139, 148, 158))
    for y in range(rows):
        row = screen.buffer[y]
        for x in range(cols):
            ch = row[x]
            bg = colour(ch.bg, BG)
            px, py = PAD_X + x * CW, BAR + PAD_TOP + y * CH
            if bg != BG: d.rectangle([px, py, px + CW, py + CH], fill=bg)
            if ch.data.strip():
                f = sym if 0x2800 <= ord(ch.data) < 0x2900 else (bold if ch.bold else reg)
                d.text((px, py), ch.data, font=f, fill=colour(ch.fg, FG))
    if not screen.cursor.hidden:
        cx, cy = PAD_X + screen.cursor.x * CW, BAR + PAD_TOP + screen.cursor.y * CH
        d.rectangle([cx, cy + 2, cx + CW - 1, cy + CH - 2], fill=(201, 209, 217))
    return im

frames, durs, last_sig, t, i = [], [], None, 0.0, 0
end = events[-1][0]
while t <= end + 0.2:
    while i < len(events) and events[i][0] <= t:
        stream.feed(prep(events[i][2])); i += 1
    sig = (tuple(tuple((c.data, c.fg, c.bg, c.bold) for c in (screen.buffer[y][x] for x in range(cols))) for y in range(rows)),
           screen.cursor.x, screen.cursor.y, screen.cursor.hidden)
    if sig == last_sig and durs: durs[-1] += int(FPS_STEP * 1000)
    else: frames.append(frame()); durs.append(int(FPS_STEP * 1000)); last_sig = sig
    t += FPS_STEP
durs[-1] += 600
pal = [f.quantize(colors=64, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE) for f in frames]
pal[0].save(OUT, save_all=True, append_images=pal[1:], duration=durs, loop=0, optimize=True, disposal=1)
print(len(frames), "frames", sum(durs) / 1000, "s")
