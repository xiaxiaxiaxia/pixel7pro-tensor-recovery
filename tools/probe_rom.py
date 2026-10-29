#!/usr/bin/env python3
"""
probe_rom.py — read-only probe for Google Tensor BootROM USB Download Mode
                 ("Pixel ROM Recovery", 18d1:4f00).

Safety boundary:
  * opens the CDC-ACM port, writes exactly one 0x0A handshake byte,
  * prints whatever the device emits,
  * never sends an image, command or address, never writes flash.

Usage:
  python3 probe_rom.py [--dev /dev/cu.usbmodemXXXX] [seconds]
"""
import argparse
import glob
import os
import select
import sys
import termios
import time


def find_port() -> str:
    for pat in ("/dev/cu.usbmodem*", "/dev/ttyACM*"):
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[0]
    return ""


def open_raw(path: str, baud: int = termios.B115200) -> int:
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    a = termios.tcgetattr(fd)
    a[0] = 0            # iflag
    a[1] = 0            # oflag
    a[3] = 0            # lflag
    a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    a[4] = baud         # ispeed (macOS)
    a[5] = baud         # ospeed (macOS)
    a[6][termios.VMIN] = 0
    a[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, a)
    termios.tcflush(fd, termios.TCIOFLUSH)
    return fd


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", default="", help="serial port (auto-detected if omitted)")
    ap.add_argument("seconds", nargs="?", type=float, default=8.0)
    args = ap.parse_args()

    dev = args.dev or find_port()
    if not dev or not os.path.exists(dev):
        print("[!] no CDC-ACM device found; pass --dev /dev/cu.usbmodemXXXX", file=sys.stderr)
        return 2

    fd = open_raw(dev)
    print(f"[*] opened {dev} @115200 8N1")
    print("[*] sending handshake byte 0x0A ('\\n') ...")
    os.write(fd, b"\n")

    buf = bytearray()
    deadline = time.time() + args.seconds
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.3)
        if not r:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            break
        if chunk:
            buf += chunk
            sys.stdout.write(chunk.decode("latin-1"))
            sys.stdout.flush()

    print(f"\n[*] {len(buf)} bytes received")
    for i, line in enumerate(l for l in bytes(buf).decode("latin-1").replace("\r", "\n").split("\n") if l.strip()):
        print(f"    [{i:02d}] {line!r}")

    os.close(fd)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
