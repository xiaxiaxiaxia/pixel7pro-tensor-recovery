# Pixel 7 Pro (Tensor G2) — Unbrick Log & Boot-Chain Security Audit

Recovery record of a hard-bricked **Pixel 7 Pro (`cheetah`, SoC `gs201`)** that was stuck in
`18d1:4f00 "Pixel ROM Recovery"` (Tensor BootROM USB Download Mode) after a bootloader
downgrade tripped **anti-rollback (ARB)**. It was brought back and flashed to the latest
official build **`CP3A.261005.002.A1` (Android 17, October 2026)**.

> **No exploit, no signature bypass, no fuse tampering.** Every image used was Google-signed
> and verified on-device. The host was only a courier.

---

## TL;DR — what actually fixed it

1. **Get into `BL1-first` mode.** Hold **Power + Vol-Up + Vol-Down** while plugging USB in,
   keep holding for **≥15 s after plug-in**, then **release all buttons**.
   (Still holding → the chain restarts from BL1 every 5–10 s.)
2. **Use the re-signed recovery chain**, not the factory images. The factory `bl1.img` has
   header byte `0x410 = 0x00` (USB-bootable bit clear) and is rejected; the recovery BL1 has
   `0x410 = 0x01`.
3. Serve it with `tensor-usbdl`:
   `./tensor-usbdl -i recovery-pack/sources/gs201`
4. Expected chain:
   `BL1 → DPM → EPBL → BL2 → BL2B → GSA1 → ABL → ABLB → TZSW → TZSB → LDFW → LDFB → BL31 → BL3B → disconnect`
5. Once in fastboot: `fastboot flash bootloader …` **first** (14 MB, turns the fragile
   RAM bootloader into a persistent one), then `sh flash-all.sh` from the official package.

Full details: [`docs/en/`](docs/en/) · [`docs/zh/`](docs/zh/)

---

## The reported problem (before any work)

The starting symptom set, as reported:

1. **Bootloader unreachable.** `fastboot devices` and `adb devices` were both empty. The phone
   only enumerated as `18d1:4f00 "Pixel ROM Recovery"` — the Tensor BootROM USB download mode —
   and the screen stayed black. No fastboot, no recovery.
2. **Official flashing path unusable.** `flash-all.sh` needs a working bootloader; there was none.
3. **Unlock status `-1`, flashing refused.** After bringing the chain up with `tensor-usbdl`, the
   unlock state was reported as `-1` and flash operations were rejected.

### What `-1` actually means

`-1` (`0xFFFFFFFF`) is the **"unknown / not initialised" sentinel**, not a lock state. It is what
ABL returns when the unlock-state query to **Titan M2 / GSA** cannot complete — the typical
situation for a RAM-resident, partially initialised recovery bootloader that has not finished
talking to the security chip.

It does **not** mean "locked", and it does **not** mean the device is permanently unlockable.
Reading it as "locked" is what makes people conclude the phone is unrecoverable.

In this session:

| Context | `fastboot getvar unlocked` |
|---|---|
| Recovery bootloader in RAM (`cloudripper-1.0-8910487`) | `yes` |
| Official bootloader from flash (`cloudripper-17.0-15902555`) | `yes` |

So the unlock state was intact all along; what was broken was the **boot chain**, and what made
flashing "refused" was not the lock but the missing/failed bootloader context.

Full original prompt (redacted) is archived at [`docs/original-request.md`](docs/original-request.md).

---

## Why it bricked

Anti-rollback versions live in **OTP eFuses** on the SoC: monotonic, not erasable, not
rewritable. After a downgrade to a bootloader below the fused value, BootROM refuses to
continue and falls back to its USB download mode. This cannot be undone in software — only
images with a version **≥ the fuse value** will load.

Google's own factory-image page documents the failure mode (older bootloader left in the
inactive slot, seamless-update fallback boots it, device becomes unbootable).

---

## Repository layout

```
.
├── README.md
├── docs/
│   ├── original-request.md                     # the prompt that started this (redacted)
│   ├── en/pixel7pro-recovery-and-audit-en.md   # full log + audit (English)
│   └── zh/pixel7pro-recovery-and-audit-zh.md   # full log + audit (Chinese)
├── tools/
│   ├── probe_rom.py    # read-only: sends one 0x0A, prints device output
│   └── dnw_serve.py    # FBPK v2 parser + DNW/EUB host implementation
└── logs/
    ├── boot-chain-success.log   # sanitised excerpt of the working chain
    └── flash-all.log            # sanitised excerpt of the successful flash
```

> Binaries (factory images, bootloader packs, recovery chain) are **not** included — see
> [Legal](#legal--disclaimer).

---

## Protocol cheat sheet

Text layer, `\n`/`\r` terminated, 115200 8N1 over CDC-ACM:

| Direction | Message | Meaning |
|---|---|---|
| dev→host | `exynos_usb_booting:<id>` | SoC/model id (`id[1:5]` = `9855` → Pixel 7 series) |
| dev→host | `eub:req:<id>:<NAME>` | request image `<NAME>` |
| dev→host | `C` | clear to send |
| dev→host | `eub:ack:<id>:<NAME>` | received |
| dev→host | `eub:nak:<id>:<NAME>` | refused |
| dev→host | `irom_booting_failure:<trace>` | boot failure + trace |
| host→dev | DNW frame | see below |

Host → device frame (little-endian):

```
1B 44 4E 57 | uint32 LE(len + 10) | image bytes | uint16 LE(sum)
ESC "DNW"        length field          payload       checksum
```

The upstream tool sends a constant `0xFFFF` checksum, so the field is evidently not validated.

## FBPK v2 container (as observed)

```
Header 112 B packed LE:
  u32 magic=0x4B504246 "FBPK", u32 version=2, u32 header_size=112, u32 entry_size=104,
  16s platform ("gs201"), 64s pack_version, u32 slot_type, u32 data_align,
  u32 total_entries, u32 total_size

Entry 104 B packed LE:
  u32 type (0=table, 1=data, 2=sideload), 36s name, 40s product,
  u64 offset, u64 size, u32 slotted, u32 crc32
```

---

## Security notes

The audit conclusion is deliberately boring: **the boot chain did its job.**

- Forging images: blocked by RSA-4096 signatures (key in Google HSM).
- Downgrading past ARB: blocked by OTP fuses compared in hardware.
- Writing arbitrary addresses over DNW: no such command exists.
- Abusing `unlock status = -1`: unlock state is guarded by Titan M2.

What the audit *did* find are engineering-level weaknesses:

| ID | Finding | Severity |
|---|---|---|
| F-01 | BootROM is not robust to malformed frames; garbage input puts it in a persistent NAK state that even a `stop` frame cannot clear — only a power cycle recovers | Low (physical access) |
| F-02 | On macOS the CDC-ACM reader loses track of subsequent requests; the process must be killed and restarted to continue | Medium (maintainability) |
| F-03 | The `Pixel ROM Recovery` channel is undocumented with no official self-service tool | Process risk |
| F-04 | ARB is a one-way door; a single downgrade can force the factory channel | Design trade-off |

Supply chain: the recovery chain came from a community-distributed release. Device-side
verification passing is indirect proof it is Google-signed, but pulling "signed boot images"
from unofficial channels is a high-value attack surface. **Always re-flash the bootloader from
the official factory package afterwards** and check `fastboot getvar version-bootloader`.

---

## Legal & disclaimer

- Performed on a personally owned device, for repair purposes.
- **No proprietary binaries are redistributed here.** Factory images, bootloader packs and the
  recovery chain are Google's; download them from official sources and respect their terms.
- The scripts are provided as-is, no warranty. Writing to a bootloader can hard-brick a device.
- Nothing here is intended to bypass ownership, licensing or security controls on devices you
  do not own.

## Credits

- [JoshuaDoes/tensor-usbdl](https://github.com/JoshuaDoes/tensor-usbdl) — the tool and the
  bundled `gs201` recovery chain.
- XDA thread *"unbrick a Pixel 7 Pro from a Hardbrick on Pixel ROM Recovery"*.
- The telegra.ph walkthroughs by *panha* and *kazan_alx*, and the `asamofal` restart trick.

## License

Suggested: **CC BY 4.0** for the documents, **MIT** for the scripts. Add a `LICENSE` file if you
want it to be explicit on GitHub.

---

<details>
<summary>中文摘要（点击展开）</summary>

一台 Pixel 7 Pro 因 bootloader 降级触发 **anti-rollback**，卡在 `18d1:4f00 Pixel ROM Recovery`
（Tensor BootROM USB 下载模式）。最终用 Google 官方签名的 recovery 引导链恢复，并刷入
`CP3A.261005.002.A1`（Android 17，2026-10）。

**关键三点：**

1. **三键进入 BL1-first 模式**：电源 + 音量加 + 音量减，插线时保持，插上后继续按住 ≥15 秒，
   然后**全部松开**（不松会导致链路每 5–10 秒从 BL1 重启）。
2. **必须用 re-signed 的 BL1**：factory 的 `bl1.img` 头部 `0x410 = 0x00`（USB-bootable 位未置），
   BootROM 拒绝；恢复包里的是 `0x410 = 0x01`。
3. **先刷 bootloader 再刷系统**：14 MB 的 bootloader 写入能把设备从"RAM 临时引导"变成
   "flash 官方引导"，此后任何失败都可重试。

**关于"bootloader 进不去 + 解锁状态 -1"：**

- 当时 `fastboot devices` / `adb devices` 全空，只有 `18d1:4f00 Pixel ROM Recovery`——因为设备根本
  没在跑 bootloader，而是停在 BootROM 的 USB 下载模式，所以"进不去 bootloader"是必然结果。
- `-1` 不是"锁死"，而是 ABL 查询 Titan M2/GSA 失败时返回的**未知值**（0xFFFFFFFF）。在 RAM 里跑
  的临时引导（`cloudripper-1.0-8910487`）尚未完成与安全芯片的握手，就会出现这个值。
- 本次实测：临时引导和官方引导下 `fastboot getvar unlocked` 都是 `yes`。**锁状态一直是好的，坏的是引导链。**

**安全结论**：全程未使用任何漏洞、未绕过签名、未改熔丝。所谓"降级锁"是 OTP 熔丝，
物理不可回写；能救回设备的是"官方签名镜像 + 正确时序"，不是破解。

完整中文文档见 [`docs/zh/`](docs/zh/)。

</details>
