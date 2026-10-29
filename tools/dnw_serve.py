#!/usr/bin/env python3
"""
dnw_serve.py — Tensor EUB/DNW ("Pixel ROM Recovery") 主机端实现

协议依据: JoshuaDoes/tensor-usbdl (Go) 的逆向结果
  * 串口 115200 8N1, 文本行协议, '\n' / '\r' 结尾
  * 设备主动:  eub:req:<id>:<NAME>   然后 'C'  ("clear to send")
  * 主机应答:  <image bytes> + uint16le(sum(bytes))
  * 失败时设备发: irom_booting_failure:<trace>  或  error:<sub>:<arg> / "<X> header fail"

本脚本只做一件事: 按照 Boot ROM 的请求，把官方 factory 包里的已签名子镜像喂回去。
它不修改、不伪造、不绕过任何签名或防回滚校验 —— 校验全部在设备侧完成。

用法:
  python3 dnw_serve.py --factory bootloader-cheetah-*.img --plan     # 只解析, 不碰设备
  python3 dnw_serve.py --factory bootloader-cheetah-*.img            # 实际喂图
"""
import argparse
import glob
import os
import select
import struct
import sys
import time
import termios

def find_port() -> str:
    """Auto-detect the BootROM CDC-ACM port."""
    for pat in ("/dev/cu.usbmodem*", "/dev/ttyACM*"):
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[0]
    return ""


DEV_DEFAULT = ""

# ---------------------------------------------------------------- FBPK 解析

FBPACK_MAGIC = 0x4B504246  # "FBPK"
HDR_FMT = "<IIII16s64sIIII"
HDR_LEN = struct.calcsize(HDR_FMT)      # 112
ENT_FMT = "<I36s40sQQII"
ENT_LEN = struct.calcsize(ENT_FMT)      # 104

ENT_PARTITION_TABLE = 0
ENT_PARTITION_DATA = 1
ENT_SIDELOAD_DATA = 2


def parse_fbpack(path):
    data = open(path, "rb").read()
    magic, version, header_size, entry_size, platform, pack_version, \
        slot_type, data_align, total_entries, total_size = struct.unpack_from(HDR_FMT, data, 0)

    if magic != FBPACK_MAGIC:
        raise SystemExit(f"[!] 不是 FBPK 容器: magic=0x{magic:08X}")
    print(f"[*] FBPK v{version}  header_size={header_size} entry_size={entry_size} "
          f"entries={total_entries} total_size={total_size}")
    plat_s = platform.rstrip(b"\x00").decode(errors="replace")
    pack_s = pack_version.rstrip(b"\x00").decode(errors="replace")
    print(f"    platform={plat_s!r} pack_version={pack_s!r} "
          f"slot_type={slot_type} data_align={data_align}")

    parts = {}
    off = header_size
    for i in range(total_entries):
        etype, name, product, offset, size, slotted, crc32 = struct.unpack_from(ENT_FMT, data, off)
        off += entry_size
        name = name.rstrip(b"\x00").decode(errors="replace")
        product = product.rstrip(b"\x00").decode(errors="replace")
        if etype == ENT_PARTITION_DATA:
            blob = data[offset:offset + size]
            parts[name] = blob
            print(f"    [{i:02d}] data  {name:<16} off=0x{offset:08X} size={size:>10} "
                  f"prod={product!r} crc32=0x{crc32:08X}")
        else:
            kind = {ENT_PARTITION_TABLE: "table", ENT_SIDELOAD_DATA: "sideload"}.get(etype, f"type{etype}")
            print(f"    [{i:02d}] {kind:<7} {name:<16} off=0x{offset:08X} size={size:>10}")
    return parts


# ---------------------------------------------------------------- 串口

def open_raw(path, baud=termios.B115200):
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    a = termios.tcgetattr(fd)
    a[0] = 0
    a[1] = 0
    a[3] = 0
    a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    a[4] = baud
    a[5] = baud
    a[6][termios.VMIN] = 0
    a[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, a)
    termios.tcflush(fd, termios.TCIOFLUSH)
    return fd


class Port:
    def __init__(self, fd, log):
        self.fd = fd
        self.log = log
        self.buf = bytearray()

    def write(self, b):
        mv = memoryview(b)
        sent = 0
        while sent < len(b):
            _, w, _ = select.select([], [self.fd], [], 5.0)
            if not w:
                raise TimeoutError("写超时")
            n = os.write(self.fd, mv[sent:sent + 65536])
            sent += n
        return sent

    def readline(self, timeout):
        """返回一行(不含终止符); 超时返回 None"""
        deadline = time.time() + timeout
        while True:
            i = self.buf.find(b"\n")
            j = self.buf.find(b"\r")
            cut = min([x for x in (i, j) if x >= 0], default=-1)
            if cut >= 0:
                line = bytes(self.buf[:cut])
                del self.buf[:cut + 1]
                if line:
                    return line
                continue
            remain = deadline - time.time()
            if remain <= 0:
                return None
            r, _, _ = select.select([self.fd], [], [], min(remain, 0.25))
            if not r:
                continue
            try:
                chunk = os.read(self.fd, 65536)
            except OSError:
                return None
            if chunk:
                self.buf += chunk


# ---------------------------------------------------------------- 主机端

def checksum16(b):
    return struct.pack("<H", sum(b) & 0xFFFF)


class Server:
    def __init__(self, parts, port, header=4096, plan_only=False, dpm_size=4096):
        self.parts = parts
        self.port = port
        self.header = header
        self.plan_only = plan_only
        self.request = None
        self.upload = False
        self.sent = []
        self.dpm = parts.get("dpm") or b"\x00" * dpm_size

    def image_for(self, name):
        """返回 (blob, 描述) 或 (None, None)"""
        p, h = self.parts, self.header
        table = {
            "BL1":  (p.get("bl1"), "bl1 完整"),
            "DPM":  (self.dpm, f"DPM {len(self.dpm)}B 零填充"),
            "EPBL": (p.get("pbl"), "pbl 完整"),
            "EPBB": (p.get("pbl", b"")[h:], "pbl 正文"),
            "BL2":  (p.get("bl2", b"")[:h], "bl2 头 4KB"),
            "BL2B": (p.get("bl2", b"")[h:], "bl2 正文"),
            "GSA1": (p.get("gsa"), "gsa 完整"),
            "ABL":  (p.get("abl", b"")[:h], "abl 头 4KB"),
            "ABLB": (p.get("abl", b"")[h:], "abl 正文"),
            "TZSW": (p.get("tzsw", b"")[:h], "tzsw 头 4KB"),
            "TZSB": (p.get("tzsw", b"")[h:], "tzsw 正文"),
            "LDFW": (p.get("ldfw", b"")[:h], "ldfw 头 4KB"),
            "LDFB": (p.get("ldfw", b"")[h:], "ldfw 正文"),
            "BL31": (p.get("bl31", b"")[:h], "bl31 头 4KB"),
            "BL3B": (p.get("bl31", b"")[h:], "bl31 正文"),
            "GCF":  (p.get("gcf", b"")[:h], "gcf 头 4KB"),
            "GCFB": (p.get("gcf", b"")[h:], "gcf 正文"),
            "GSAF": (p.get("gsaf"), "gsaf 完整"),
        }
        blob, desc = table.get(name, (None, None))
        if blob is not None and len(blob) == 0:
            blob = None
        return blob, desc

    def run(self, idle_timeout=25.0):
        port = self.port
        print(f"[*] 握手: 发送 0x0A")
        port.write(b"\n")
        last = time.time()
        while True:
            line = port.readline(1.0)
            if line is None:
                if time.time() - last > idle_timeout:
                    print(f"[!] {idle_timeout:.0f}s 无消息, 退出")
                    return 2
                continue
            last = time.time()
            txt = line.decode("latin-1")
            # 重复消息去重，避免刷屏
            if txt == getattr(self, "_last", None):
                self._dup = getattr(self, "_dup", 1) + 1
                if self._dup % 100 == 0:
                    print(f"<<< [重复 x{self._dup}] {txt!r}")
            else:
                self._last, self._dup = txt, 1
                print(f"<<< {txt!r}")

            if txt.startswith("eub:req:"):
                name = txt.split(":")[-1]
                self.request = name
                self.upload = True

            elif txt.startswith("eub:ack"):
                print("    (ack)")
                self.upload = True

            elif txt.startswith("eub:nak"):
                print("    [!] 设备拒收 (nak)")

            elif txt == "C":
                if not self.upload:
                    print("    (未在可上传状态, 忽略 C)")
                    continue
                self.upload = False
                blob, desc = self.image_for(self.request)
                if blob is None:
                    print(f"    [!] 没有可用于 {self.request} 的镜像")
                    return 3
                t0 = time.time()
                if self.plan_only:
                    print(f"    [plan] {self.request} <- {desc} ({len(blob)} bytes)")
                    continue
                # DNW 帧: ESC "DNW" + uint32le(len+10) + data + uint16le(sum)
                frame = b"\x1bDNW" + struct.pack("<I", len(blob) + 10) + blob + checksum16(blob)
                port.write(frame)
                dt = time.time() - t0
                rate = len(blob) / dt if dt > 0 else 0
                print(f"    >>> 已发送 {self.request} ({desc}) {len(blob)} bytes "
                      f"in {dt:.2f}s ({rate/1024:.0f} KiB/s)")
                self.sent.append(self.request)

            elif txt.startswith("exynos_usb_booting"):
                print(f"    (设备标识: {txt.split(':', 1)[-1]})")

            elif txt.startswith("irom_booting_failure"):
                print("    [XX] BootROM 报告引导失败:")
                for seg in txt.split(":", 2)[-1].split("\x00"):
                    if seg.strip():
                        print(f"         {seg}")
                return 4

            elif "header fail" in txt or txt.startswith("error"):
                print(f"    [XX] 设备报错: {txt}")
                return 5

            elif txt.startswith("\x00") or txt == "\x00":
                continue
            else:
                print(f"    (未处理: {txt!r})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--factory", required=True, help="bootloader-*.img (FBPK v2)")
    ap.add_argument("--dev", default=DEV_DEFAULT)
    ap.add_argument("--plan", action="store_true", help="只解析/演练, 不与设备通信")
    ap.add_argument("--idle-timeout", type=float, default=25.0)
    ap.add_argument("--dpm-size", type=int, default=4096)
    a = ap.parse_args()

    parts = parse_fbpack(a.factory)
    print(f"[*] 解析出 {len(parts)} 个分区数据: {sorted(parts)}")

    if a.plan:
        s = Server(parts, None, plan_only=True, dpm_size=a.dpm_size)
        for name in ["BL1", "DPM", "EPBL", "EPBB", "BL2", "BL2B", "GSA1", "ABL", "ABLB",
                     "TZSW", "TZSB", "LDFW", "LDFB", "BL31", "BL3B", "GCF", "GCFB", "GSAF"]:
            blob, desc = s.image_for(name)
            print(f"    {name:<5} -> {desc or '缺失'}  {len(blob) if blob else 0} bytes")
        return 0

    dev = a.dev or find_port()
    if not dev:
        raise SystemExit("[!] no CDC-ACM device found; pass --dev /dev/cu.usbmodemXXXX")
    fd = open_raw(dev)
    print(f"[*] 已打开 {dev}")
    srv = Server(parts, Port(fd, None), dpm_size=a.dpm_size)
    try:
        return srv.run(a.idle_timeout)
    finally:
        os.close(fd)
        print(f"[*] 本次已发送: {srv.sent}")


if __name__ == "__main__":
    raise SystemExit(main())
