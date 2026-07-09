"""Live viewer for the GAN251 (2x2) smart cube.

Scans for the cube over Bluetooth LE, auto-detects its MAC address from the
advertisement, decrypts the notification stream, and renders the cube in a
tkinter window: a 3D view that follows the cube's gyro orientation in real
time, plus an unfolded 2D net. Drag the 3D view to adjust the orientation;
double-click it to reset.

Usage:
    python3 gan_viewer.py            # auto-detect MAC from the advertisement
    python3 gan_viewer.py AA:BB:CC:DD:EE:FF   # force a specific MAC

Protocol (V3-2 encryption, packet formats, gyro quaternion) ported from
https://github.com/MrFanfo/GAN22LAB
"""
import asyncio
import math
import sys
import tkinter as tk

from bleak import BleakScanner, BleakClient
from Crypto.Cipher import AES

NOTIFY_CHAR = "0000fff6-0000-1000-8000-00805f9b34fb"

# --- crypto: AES-128-CBC, key/IV = base material + reversed-MAC salt on the first 6 bytes ---
BASE_KEY = bytes([0x58,0x98,0x61,0xfc,0x1f,0xec,0xd7,0x60,0x9f,0x85,0xd3,0x62,0xbe,0x37,0x17,0x2c])
BASE_IV  = bytes([0x7f,0x61,0xd0,0x52,0x75,0xc1,0x39,0x52,0x08,0x2e,0x54,0x1d,0x8a,0x78,0x63,0x4d])


def derive_key_iv(mac: str) -> tuple[bytes, bytes]:
    salt = bytes(reversed([int(p, 16) for p in mac.split(":")]))
    key = bytearray(BASE_KEY)
    iv = bytearray(BASE_IV)
    for i in range(6):
        key[i] = (BASE_KEY[i] + salt[i]) % 0xFF
        iv[i] = (BASE_IV[i] + salt[i]) % 0xFF
    return bytes(key), bytes(iv)


def decrypt(raw: bytes, key: bytes, iv: bytes) -> bytes:
    # Two overlapping 16-byte CBC windows: decrypt the end-aligned one first.
    buf = bytearray(raw)
    if len(buf) > 16:
        buf[-16:] = AES.new(key, AES.MODE_CBC, iv).decrypt(bytes(buf[-16:]))
    buf[:16] = AES.new(key, AES.MODE_CBC, iv).decrypt(bytes(buf[:16]))
    return bytes(buf)


def mac_from_advertisement(manufacturer_data: dict) -> str | None:
    # GAN uses company IDs with low byte 0x01; the MAC is the last 6 of the
    # first 9 payload bytes, reversed.
    for cid, data in manufacturer_data.items():
        if (cid & 0xFF) == 0x01 and len(data) >= 6:
            return ":".join(f"{b:02X}" for b in reversed(data[:9][-6:]))
    return None


def read_bits(data: bytes, off: int, n: int) -> int:
    v = 0
    for i in range(n):
        v = (v << 1) | ((data[(off + i) // 8] >> (7 - (off + i) % 8)) & 1)
    return v


# --- quaternion helpers (x, y, z, w) ---
def qmul(a, b):
    ax, ay, az, aw = a
    bx, by, bz, bw = b
    return (aw*bx + ax*bw + ay*bz - az*by,
            aw*by - ax*bz + ay*bw + az*bx,
            aw*bz + ax*by - ay*bx + az*bw,
            aw*bw - ax*bx - ay*by - az*bz)


def qconj(q):
    return (-q[0], -q[1], -q[2], q[3])


def qnorm(q):
    n = math.sqrt(sum(c*c for c in q)) or 1.0
    return tuple(c / n for c in q)


def qaxis(axis, rad):
    s = math.sin(rad / 2)
    return (axis[0]*s, axis[1]*s, axis[2]*s, math.cos(rad / 2))


def qrot(v, q):
    p = qmul(qmul(q, (v[0], v[1], v[2], 0.0)), qconj(q))
    return (p[0], p[1], p[2])


def qslerp(a, b, t):
    dot = sum(x*y for x, y in zip(a, b))
    if dot < 0:  # take the short way around
        b = tuple(-c for c in b)
        dot = -dot
    if dot > 0.9995:
        return qnorm(tuple(x + t*(y - x) for x, y in zip(a, b)))
    th = math.acos(min(1.0, dot))
    sa, sb = math.sin((1-t)*th) / math.sin(th), math.sin(t*th) / math.sin(th)
    return qnorm(tuple(sa*x + sb*y for x, y in zip(a, b)))


HOME = qmul(qaxis((1, 0, 0), math.radians(-24)), qaxis((0, 1, 0), math.radians(34)))


def sign_mag(v, bits=16):
    return (1 - (v >> (bits - 1)) * 2) * (v & ((1 << (bits - 1)) - 1)) / ((1 << (bits - 1)) - 1)


# --- 2x2 cube model (corner permutation + orientation) ---
FACE_MASK = {0x02: "U", 0x20: "R", 0x08: "F", 0x01: "D", 0x10: "L", 0x04: "B"}
CORNER_COLORS = {0: "URF", 1: "UFL", 2: "ULB", 3: "UBR", 4: "DFR", 5: "DLF", 6: "DBL", 7: "DRB"}
CORNER_STICKERS = {  # corner position -> its three (face, sticker-index) slots
    0: [("U",3),("R",0),("F",1)], 1: [("U",2),("F",0),("L",1)],
    2: [("U",0),("L",0),("B",1)], 3: [("U",1),("B",0),("R",1)],
    4: [("D",1),("F",3),("R",2)], 5: [("D",0),("L",3),("F",2)],
    6: [("D",2),("B",3),("L",2)], 7: [("D",3),("R",3),("B",2)],
}
MOVE_DEFS = {  # clockwise quarter turn: 4-cycle of positions + orientation deltas
    "U": ([0,1,2,3],[0,0,0,0]), "R": ([0,3,7,4],[2,1,2,1]), "F": ([0,4,5,1],[1,2,1,2]),
    "D": ([4,7,6,5],[0,0,0,0]), "L": ([1,5,6,2],[1,2,1,2]), "B": ([2,6,7,3],[1,2,1,2]),
}


class Cube2x2:
    def __init__(self):
        self.cp = list(range(8))
        self.co = [0] * 8

    def apply(self, face: str, turns: int):
        cycle, delta = MOVE_DEFS[face]
        for _ in range(turns):
            a, b, c, d = cycle
            self.cp[a], self.cp[b], self.cp[c], self.cp[d] = self.cp[d], self.cp[a], self.cp[b], self.cp[c]
            self.co[a], self.co[b], self.co[c], self.co[d] = (
                (self.co[d] + delta[0]) % 3, (self.co[a] + delta[1]) % 3,
                (self.co[b] + delta[2]) % 3, (self.co[c] + delta[3]) % 3,
            )

    def facelets(self) -> dict:
        faces = {f: [f] * 4 for f in "URFDLB"}
        for pos in range(8):
            colors = CORNER_COLORS[self.cp[pos]]
            for si, (face, idx) in enumerate(CORNER_STICKERS[pos]):
                faces[face][idx] = colors[(si + 3 - self.co[pos] % 3) % 3]
        return faces

    def is_solved(self) -> bool:
        return self.cp == list(range(8)) and self.co == [0] * 8


# --- UI ---
COLORS = {"U": "#ffffff", "D": "#ffd500", "F": "#009b48", "B": "#0046ad", "R": "#b71234", "L": "#ff5800"}
FACE_POS = {"U": (1, 0), "L": (0, 1), "F": (1, 1), "R": (2, 1), "B": (3, 1), "D": (1, 2)}
S = 36  # 2D sticker size in px
V3D = 340  # 3D canvas size
LIGHT = qnorm((0.35, 0.5, 0.85, 0))[:3]  # light direction, roughly from the camera

# 3D face frames: outward normal, view-right axis, view-up axis. Sticker index
# 0..3 = top-left, top-right, bottom-left, bottom-right as seen from outside,
# matching the CORNER_STICKERS convention above.
FACE_FRAMES = {
    "U": ((0, 1, 0), (1, 0, 0), (0, 0, -1)),
    "D": ((0, -1, 0), (1, 0, 0), (0, 0, 1)),
    "F": ((0, 0, 1), (1, 0, 0), (0, 1, 0)),
    "B": ((0, 0, -1), (-1, 0, 0), (0, 1, 0)),
    "R": ((1, 0, 0), (0, 0, -1), (0, 1, 0)),
    "L": ((-1, 0, 0), (0, 0, 1), (0, 1, 0)),
}


def shade(hex_color: str, k: float) -> str:
    r, g, b = (int(hex_color[i:i+2], 16) for i in (1, 3, 5))
    return f"#{int(r*k):02x}{int(g*k):02x}{int(b*k):02x}"


def face_quads(face):
    """Full face quad + the four sticker quads, as 3D corner lists."""
    n, u, v = FACE_FRAMES[face]

    def pt(a, b):
        return tuple(n[i] + a * u[i] + b * v[i] for i in range(3))

    base = [pt(-1, 1), pt(1, 1), pt(1, -1), pt(-1, -1)]
    stickers = []
    g = 0.07  # sticker inset
    for i in range(4):
        u0 = -1 + (i % 2)      # left cells start at -1, right cells at 0
        v0 = 0 - (i // 2)      # top cells start at 0, bottom cells at -1
        stickers.append([pt(u0+g, v0+1-g), pt(u0+1-g, v0+1-g), pt(u0+1-g, v0+g), pt(u0+g, v0+g)])
    return base, stickers


FACE_GEOMETRY = {f: face_quads(f) for f in "URFDLB"}


class Viewer:
    def __init__(self):
        self.cube = Cube2x2()
        self.key = self.iv = None
        self.target = (0.0, 0.0, 0.0, 1.0)   # latest gyro quat (display space)
        self.shown = (0.0, 0.0, 0.0, 1.0)    # smoothed quat actually rendered
        self.basis = None                     # conjugate of target at connect
        self.offset = (0.0, 0.0, 0.0, 1.0)   # user drag adjustment
        self.drag_xy = None
        self.dirty = True

        self.root = tk.Tk()
        self.root.title("GAN 2x2")
        frame = tk.Frame(self.root, bg="#1e1e1e")
        frame.pack()
        self.c3d = tk.Canvas(frame, width=V3D, height=V3D, bg="#1e1e1e", highlightthickness=0)
        self.c3d.grid(row=0, column=0, padx=(10, 0))
        self.c3d.bind("<Button-1>", self.drag_start)
        self.c3d.bind("<B1-Motion>", self.drag_move)
        self.c3d.bind("<Double-Button-1>", self.drag_reset)
        self.c2d = tk.Canvas(frame, width=4*(2*S+8)+10, height=3*(2*S+8)+36, bg="#1e1e1e", highlightthickness=0)
        self.c2d.grid(row=0, column=1, padx=10)
        self.status = tk.Label(self.root, text="scanning…", fg="#ccc", bg="#1e1e1e", font=("Menlo", 12))
        self.status.pack(fill="x")

        self.rects = {}
        for face, (fx, fy) in FACE_POS.items():
            for i in range(4):
                x = 5 + fx*(2*S+8) + (i % 2)*S
                y = 22 + fy*(2*S+8) + (i // 2)*S
                self.rects[(face, i)] = self.c2d.create_rectangle(
                    x, y, x+S, y+S, fill="#555", outline="#1e1e1e", width=3)
        self.redraw2d()
        self.redraw3d()

    # --- drag to adjust / calibrate the 3D view ---
    def drag_start(self, e):
        self.drag_xy = (e.x, e.y)

    def drag_move(self, e):
        if self.drag_xy is None:
            return
        dx, dy = e.x - self.drag_xy[0], e.y - self.drag_xy[1]
        self.drag_xy = (e.x, e.y)
        k = 0.008  # radians per pixel
        self.offset = qnorm(qmul(qmul(qaxis((0, 1, 0), dx*k), qaxis((1, 0, 0), dy*k)), self.offset))
        self.dirty = True

    def drag_reset(self, _):
        self.offset = (0.0, 0.0, 0.0, 1.0)
        self.basis = qconj(self.target)
        self.dirty = True

    # --- drawing ---
    def redraw2d(self):
        for face, stickers in self.cube.facelets().items():
            for i, color in enumerate(stickers):
                self.c2d.itemconfig(self.rects[(face, i)], fill=COLORS[color])

    def display_quat(self):
        q = self.shown
        if self.basis:
            q = qmul(self.basis, q)
        return qnorm(qmul(self.offset, qmul(HOME, q)))

    def redraw3d(self):
        q = self.display_quat()
        CAM = 8.0  # camera distance; farther = less distortion

        def project(p):
            x, y, z = qrot(p, q)
            f = CAM / (CAM - z)
            return (V3D/2 + 80*f*x, V3D/2 - 80*f*y)

        facelets = self.cube.facelets()
        self.c3d.delete("cube")
        # Visible iff the face actually points toward the camera at (0,0,CAM):
        # dot(n, cam - n) > 0  ->  CAM*nz > 1. Draw back-to-front for safety.
        visible = []
        for face in "URFDLB":
            n = qrot(FACE_FRAMES[face][0], q)
            if CAM * n[2] > 1.0:
                visible.append((n[2], face, n))
        for _, face, n in sorted(visible):
            lum = 0.62 + 0.38 * max(0.0, n[0]*LIGHT[0] + n[1]*LIGHT[1] + n[2]*LIGHT[2])
            base, stickers = FACE_GEOMETRY[face]
            self.c3d.create_polygon(*[c for p in base for c in project(p)],
                                    fill="#0c0c0c", outline="#0c0c0c", tags="cube")
            for i, quad in enumerate(stickers):
                self.c3d.create_polygon(*[c for p in quad for c in project(p)],
                                        fill=shade(COLORS[facelets[face][i]], lum),
                                        outline="", tags="cube")

    # --- packets ---
    def on_packet(self, _, data: bytearray):
        d = decrypt(bytes(data), self.key, self.iv)
        pid = d[0]
        if pid == 0xEC and len(d) >= 12:  # gyro: sign-magnitude 16-bit wxyz
            w = sign_mag(read_bits(d, 16, 16))
            x = sign_mag(read_bits(d, 32, 16))
            y = sign_mag(read_bits(d, 48, 16))
            z = sign_mag(read_bits(d, 64, 16))
            self.target = qnorm((x, z, -y, w))  # remap cube frame -> display space
            if self.basis is None:
                self.basis = qconj(self.target)
                self.shown = self.target
            self.dirty = True
        elif pid == 0x01 and len(d) >= 11:  # live move
            face = FACE_MASK.get(d[8] & 0x3F)
            turns = {0: 1, 1: 3, 2: 2}.get((d[8] >> 6) & 3, 0)
            if face and turns:
                self.cube.apply(face, turns)
                suffix = {1: "", 2: "2", 3: "'"}[turns]
                solved = "  ✔ solved" if self.cube.is_solved() else ""
                self.status.config(text=f"move: {face}{suffix}{solved}")
                self.redraw2d()
                self.dirty = True
        elif pid == 0xED and len(d) >= 18:  # full state (authoritative, corrects drift)
            payload = d[4:min(2 + d[1], len(d) - 2)]
            first7 = [read_bits(payload, i*3, 3) for i in range(7)]
            cp = first7 + [next(v for v in range(8) if v not in first7)]
            co = [read_bits(payload, 21 + i*2, 2) % 3 for i in range(8)]
            if sorted(cp) == list(range(8)):
                self.cube.cp, self.cube.co = cp, co
                self.redraw2d()
                self.dirty = True
        elif pid == 0xEF and len(d) >= 4:  # battery
            self.root.title(f"GAN 2x2  🔋{d[2]}%")

    # --- main loop ---
    async def run(self, manual_mac: str | None):
        device = mac = None
        while device is None:
            self.status.config(text="scanning — turn a face to wake the cube…")
            self.root.update()
            for d, adv in (await BleakScanner.discover(timeout=4, return_adv=True)).values():
                if "gan" in (adv.local_name or d.name or "").lower():
                    device = d
                    mac = manual_mac or mac_from_advertisement(adv.manufacturer_data or {})
                    break
        if not mac:
            self.status.config(text="couldn't detect MAC — pass it as an argument")
            self.root.update()
            await asyncio.sleep(10)
            return
        self.key, self.iv = derive_key_iv(mac)
        self.status.config(text=f"connecting ({mac})…")
        self.root.update()
        async with BleakClient(device) as client:
            await client.start_notify(NOTIFY_CHAR, self.on_packet)
            self.status.config(text="connected — turn the cube!  drag 3D view to adjust · double-click to reset")
            while True:  # ~60 fps: ease the shown quat toward the gyro target
                gap = 1 - abs(sum(a*b for a, b in zip(self.shown, self.target)))
                if gap > 1e-6 or self.dirty:
                    self.shown = qslerp(self.shown, self.target, 0.35)
                    self.dirty = False
                    self.redraw3d()
                self.root.update()
                await asyncio.sleep(0.015)


if __name__ == "__main__":
    manual = sys.argv[1] if len(sys.argv) > 1 else None
    try:
        asyncio.run(Viewer().run(manual))
    except (tk.TclError, KeyboardInterrupt):
        pass  # window closed
