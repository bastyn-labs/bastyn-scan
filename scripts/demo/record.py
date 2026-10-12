"""Record a scripted terminal session against the real bastyn binary into an asciicast v2 file.

Usage: record.py OUT.cast TARGETS_DIR
TARGETS_DIR must contain the folder built by make_target.sh. Needs bastyn on PATH and network access
(the dependency check queries a vulnerability database).

The session is: run `bastyn scan` on the folder, scroll back through the report the way a person
would, return to the bottom, and stop. The scroll-back is generated from the recorded
terminal contents, so every line on screen is real scan output.
"""
import fcntl
import json
import os
import pty
import random
import re
import select
import struct
import sys
import termios
import time

import pyte

COLS, ROWS = 110, 30
OUT = sys.argv[1]
CWD = os.path.expanduser(sys.argv[2])
SCAN = "bastyn scan advanced-hil-credit-pre-approval"
CHECKPOINTS = ["BAS-SKILL-002", "BAS-MCP-002", "BAS-CVE-001"]  # where the scroll-back pauses
ANSI = {"black": 30, "red": 31, "green": 32, "brown": 33, "blue": 34, "magenta": 35, "cyan": 36, "white": 37}

pid, fd = pty.fork()
if pid == 0:
    os.chdir(CWD)
    env = dict(os.environ, TERM="xterm-256color", PS1="\\[\\e[1;32m\\]❯\\[\\e[0m\\] ", LANG="en_US.UTF-8")
    os.execvpe("bash", ["bash", "--noprofile", "--norc", "-i"], env)
fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
events, t0 = [], time.time()
entered = []  # when Enter was pressed


def pump(duration):
    end = time.time() + duration
    while True:
        left = end - time.time()
        if left <= 0:
            return
        r, _, _ = select.select([fd], [], [], min(left, 0.02))
        if r:
            try:
                data = os.read(fd, 65536)
            except OSError:
                return
            if not data:
                return
            events.append([round(time.time() - t0, 4), "o", data.decode("utf-8", "replace")])


def wait_prompt(timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        pump(0.1)
        tail = "".join(e[2] for e in events[-3:])
        if re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", tail).rstrip().endswith("❯"):
            return
    raise SystemExit("no prompt")


def type_command(cmd):
    os.write(fd, b"\x0c")  # clear the screen
    pump(0.3)
    for ch in cmd:
        os.write(fd, ch.encode())
        pump(random.uniform(0.012, 0.025))
    pump(0.2)
    entered.append(time.time() - t0)
    os.write(fd, b"\r")


def sgr(ch):
    codes = ["0"]
    if ch.bold:
        codes.append("1")
    for value, base in ((ch.fg, 30), (ch.bg, 40)):
        if value == "default":
            continue
        if value in ANSI:
            codes.append(str(base + ANSI[value] - 30))
        elif value.startswith("bright") and value[6:] in ANSI:
            codes.append(str(base + 60 + ANSI[value[6:]] - 30))
        elif re.fullmatch(r"[0-9a-f]{6}", value):
            codes.append(f"{base + 8};2;{int(value[0:2], 16)};{int(value[2:4], 16)};{int(value[4:6], 16)}")
    return "\x1b[" + ";".join(codes) + "m"


def render_row(row):
    out, last = [], None
    cells = [row[x] for x in range(COLS)]
    while cells and cells[-1].data == " " and cells[-1].bg == "default":
        cells.pop()
    for ch in cells:
        style = sgr(ch)
        if style != last:
            out.append(style)
            last = style
        out.append(ch.data)
    return "".join(out) + "\x1b[0m"


def view(lines, start, cursor=None):
    rows = [render_row(lines[start + y]) for y in range(ROWS)]
    text = "\x1b[?25l\x1b[H" + "".join("\x1b[2K" + r + ("\r\n" if y < ROWS - 1 else "") for y, r in enumerate(rows))
    if cursor:
        text += f"\x1b[{cursor[1] + 1};{cursor[0] + 1}H\x1b[?25h"
    return text


def scroll_events(prefix, t_start):
    """Events that scroll the terminal view back through the report, starting at time t_start."""
    screen = pyte.HistoryScreen(COLS, ROWS, history=20000)
    stream = pyte.Stream(screen)
    for e in prefix:
        stream.feed(re.sub(r"\x1b\[2m", "\x1b[90m", e[2]))
    lines = list(screen.history.top) + [screen.buffer[y] for y in range(ROWS)]
    plain = ["".join(row[x].data for x in range(COLS)) for row in lines]
    bottom = len(lines) - ROWS
    stops = [min(bottom, max(0, next(i for i, p in enumerate(plain) if key in p) - 1)) for key in CHECKPOINTS]
    header = min(bottom, next(i for i, p in enumerate(plain) if p.startswith("Bastyn scan:")) - 1)
    out, t, pos = [], t_start, bottom

    def emit(start):
        out.append([round(t, 4), "o", view(lines, start)])

    def glide(target, frames=3, dt=0.06):
        """Scroll to `target` in a few quick steps."""
        nonlocal t, pos
        first = pos
        for i in range(1, frames + 1):
            pos = first + (target - first) * i // frames
            t += dt
            emit(pos)

    t += 0.4
    glide(header)  # jump back to the top of the report
    t += 1.6
    for stop in stops:
        glide(stop)
        t += 1.2
    glide(bottom)
    t += 0.1
    out.append([round(t, 4), "o", view(lines, bottom, cursor=(screen.cursor.x, screen.cursor.y))])
    return out, t


random.seed(3)
pump(0.8)
type_command(SCAN)
wait_prompt()
pump(0.3)
SPEEDUP = 2.0  # play the scan itself back faster than real time
for e in events:
    if e[0] > entered[0]:
        e[0] = round(entered[0] + (e[0] - entered[0]) / SPEEDUP, 4)
prefix_end = len(events)
scroll, _ = scroll_events(events[:prefix_end], events[-1][0])
final = events[:prefix_end] + scroll
first_key = next(e[0] for e in final if len(e[2]) == 1 and e[2].isprintable())
lead = max(0.0, first_key - 0.3)  # trim the idle time before the first keystroke
final = [[round(max(0.0, e[0] - lead), 4), e[1], e[2]] for e in final]
with open(OUT, "w") as f:
    f.write(json.dumps({"version": 2, "width": COLS, "height": ROWS, "timestamp": int(t0), "env": {"TERM": "xterm-256color"}}) + "\n")
    for e in final:
        f.write(json.dumps(e, ensure_ascii=False) + "\n")
print(len(final), "events", final[-1][0], "s")
