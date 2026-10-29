# Pixel 7 Pro Unbrick: Full Recovery Log and Boot-Chain Security Audit

> Recorded: 2026-10-29, 20:14–21:47 (CST)
> Device: Google Pixel 7 Pro (`cheetah` / SoC `gs201` / Tensor G2)
> Host: macOS 27.2 (arm64 / Apple Silicon)
> Outcome: **device recovered and flashed to the latest official build `CP3A.261005.002.A1` (Android 17, October 2026)**

---

## 1. Executive Summary

| Question | Answer |
|---|---|
| Was the device actually dead? | No. It was alive in the Tensor BootROM USB Download Mode (exposed as `Pixel ROM Recovery`). |
| Was it a hardware failure? | No. SoC and UFS were fine; the BootROM USB stack was responding normally. |
| Could it be rescued by "finding a vulnerability"? | **No — and it wasn't necessary.** Every image used was Google-signed. No signature or anti-rollback check was bypassed. |
| Actual root cause | A bootloader downgrade tripped **anti-rollback (ARB)**. The version counter lives in **one-time-programmable (OTP) eFuses** on the SoC and cannot be rewritten by software. |
| Actual difficulty | Not cryptography, but **physical entry timing** (three-button hold → BL1-first mode) and **image matching** (a re-signed BL1 with the USB-bootable bit set). |
| Was the bootloader unlocked for flashing? | It was already `unlocked: yes`. The official `flash-all.sh` was used end to end. |

**One sentence: the phone was not "hacked" back to life — it was fed the correct signed images in the correct order.**

---

## 2. Device and Symptoms

### 2.1 Original state (as reported, then confirmed)

```
Location ID      : <USB-PORT>
Connection Type  : Removable
Manufacturer     : Google
Serial Number    : REDACTED
Link Speed       : 480 Mb/s
USB Vendor ID    : 0x18D1 (6353)
USB Product ID   : 0x4F00 (20224)
USB Product Ver. : 0x0100
Product Name     : Pixel ROM Recovery
```

A matching serial node also appeared:

```bash
$ ls -l /dev/cu.usbmodem*
crw-rw-rw-  1 root  wheel  0x9000005  /dev/cu.usbmodem<PORT>
```

`0x18D1:0x4F00` plus a CDC-ACM serial port means **Tensor BootROM USB Download Mode**. This mode drives no display and enters neither fastboot nor recovery — which is why it looks like a black-screen brick.

### 2.2 Reported symptoms

- Unbootable after a bootloader downgrade;
- Unlock status displayed as `-1`, flashing refused;
- Recovery unreachable;
- Official `flash-all` completely unusable.

**Reading `-1`:** `0xFFFFFFFF` is the "unknown" value ABL returns when the unlock-state query to
Titan M2/GSA fails — not a "locked" state. It shows up most often on a RAM-resident recovery
bootloader (`cloudripper-1.0-8910487`) that has not finished handshaking with the security chip.
In this session `fastboot getvar unlocked` returned `yes` under both the recovery bootloader and
the official one — **the lock state was fine all along; the boot chain was what broke.** Reading
`-1` as "locked" is the usual reason people conclude the device is unrecoverable.

### 2.3 Device identification

The BootROM announced itself over serial:

```
exynos_usb_booting:09855000
```

`tensor-usbdl` parses `id[1:5]` → `"9855"` → **Pixel 7 series**, consistent with cheetah.

---

## 3. Diagnosis (real commands and output)

### 3.1 Step 1 — determine the actual mode

```bash
$ ioreg -p IOUSB -w0 -l | grep -iE 'Google|Pixel|idVendor|idProduct'
+-o Pixel ROM Recovery@02140000  <class IOUSBHostDevice>
      "USB Serial Number" = "REDACTED"
      "USB Product Name"  = "Pixel ROM Recovery"
      "idVendor"  = 6353      # 0x18D1
      "idProduct" = 20224     # 0x4F00
```

```bash
$ fastboot devices
(no output)
$ adb devices
(no output)
```

Conclusion: **neither fastboot nor adb — this is BootROM download mode.**

### 3.2 Step 2 — passive, read-only probe (the turning point)

Wrote `tools/probe_rom.py`: it opens the port, sends a single `0x0A` handshake byte, and only reads.

```python
fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
# c_iflag/c_oflag/c_lflag = 0, c_cflag = CS8|CREAD|CLOCAL, 115200 8N1
os.write(fd, b"\n")
```

Real output:

```
[*] Opened /dev/cu.usbmodem<PORT> @115200 8N1
[*] Sending handshake byte 0x0A ('\n') ...

eub:req:09855000:DPM
C
eub:req:09855000:DPM
C
eub:req:09855000:DPM
C
...
[*] 230 bytes received
```

**This changed everything**: the device was not dead, it was actively requesting the `DPM` image and waiting for the host to send it after `C` (Clear-To-Send).

### 3.3 Protocol

Reconstructed by reverse-engineering `tensor-usbdl` and confirmed on the wire.

**Text layer (terminated by `\n` / `\r`)**

| Direction | Message | Meaning |
|---|---|---|
| device→host | `exynos_usb_booting:<id>` | SoC / model identification |
| device→host | `eub:req:<id>:<NAME>` | request the image named NAME |
| device→host | `C` | clear to send |
| device→host | `eub:ack:<id>:<NAME>` | image received |
| device→host | `eub:nak:<id>:<NAME>` | refused |
| device→host | `irom_booting_failure:<trace>` | boot failure + 15 trace fields |
| device→host | `<X> header fail` | image header rejected |

**Binary layer (host→device, DNW frame)**

```
+-------------+--------------------+---------------+------------------+
| 1B 44 4E 57 | uint32 LE(len+10)  | image bytes   | uint16 LE(sum)   |
+-------------+--------------------+---------------+------------------+
   ESC "DNW"       length field         payload        checksum
```

> Two details worth noting:
> 1. The length field is `len + 10` (4 bytes command + 2 bytes checksum + 4 bytes for itself), **little-endian**.
> 2. The upstream tool actually sends a **constant checksum `0xFFFF`** (`crc = []byte{0xFF,0xFF}`), not a computed sum — so the device clearly does not validate it.

### 3.4 First failure — missing frame header

Initially I sent raw payload + checksum. The device re-requested `DPM` every ~0.4 s in an infinite loop:

```
eub:req:09855000:DPM
C
    >>> sent DPM 4096 bytes
eub:req:09855000:DPM
C
    >>> sent DPM 4096 bytes
... (forever)
```

After wrapping the payload in a proper DNW frame, `eub:ack:09855000:DPM` appeared immediately. **Protocol layer solved.**

### 3.5 Second failure — wrong mode plus wrong images

Feeding sub-images extracted from the official factory package (`bootloader-cheetah-cloudripper-17.0-15902555.img`) produced:

```
Requested DPM  → Sent DPM  → Acknowledged DPM
Requested EPBL → Sent EPBL → Acknowledged EPBL
Requested DPM  → ... (back to the start, forever)
```

Rebuilding and running the upstream Go tool (v0.2.0) reproduced the identical loop, ruling out a bug in my implementation.

**Two compounding causes:**

1. **Wrong entry mode.** Without the three-button hold, the BootROM stays in **DPM-first** mode: it runs the old BL1 from flash and only consumes DPM/PBL as parameters, so the chain cannot progress.
2. **BL1 mismatch.** The factory BL1 header has `0x410 = 0x00` — the **USB-bootable bit is clear**. On the USB boot path the BootROM only accepts a re-signed BL1 with `0x410 = 0x01`.

Confirmed by inspection:

```bash
$ xxd -s 1024 -l 32 sources/bl1.img
00000400: 4150 424c 0100 0000 0200 0000 0020 0000  APBL......... ..
00000410: 0004 0000 ...                          # 0x410 = 0x00
```

Versus the recovery pack BL1:

```bash
$ xxd -s 1024 -l 32 recovery-pack/sources/gs201/bl1.img
00000400: 4150 424c 0100 0000 0200 0000 0020 0000  APBL......... ..
00000410: 0104 0000 ...                          # 0x410 = 0x01 ✅
```

### 3.6 Root cause — ARB anti-rollback

Google's Factory Images page documents this exact failure mode:

> After an update, the older build remains in the inactive slot with a bootloader whose **anti-rollback version has not been incremented**. If the active slot is then flashed with a build that fails to boot, seamless-update fallback tries to boot the inactive slot; because that slot holds the older bootloader, the device enters an **unbootable state**.

Technical essence:

- The ARB counter is burned into **OTP eFuses** on the SoC;
- eFuses are **monotonic** — not erasable, not rewritable;
- BootROM/BL1 compare each next-stage image against the fuse and reject anything lower.

Therefore "software unlock of the downgrade" is physically impossible. The device can only be recovered with **Google-signed images whose version is ≥ the fuse value**.

---

## 4. Recovery Plan and Execution

### 4.1 Key intelligence

After establishing that official factory images alone would not work, two sources proved decisive:

1. XDA thread: *unbrick a Pixel 7 Pro from a Hardbrick on Pixel ROM Recovery*
2. Walkthrough: *Unbricking my Pixel 7 (panther) with tensor-usbdl on macOS*

They supplied two critical facts:

- **Power + Vol-Up + Vol-Down** must be held while plugging in, and for ≥15 s afterwards, to force the BootROM into **BL1-first** mode;
- The **re-signed (USB-bootable)** chain under `sources/gs201/` in the release zip must be used — not the factory images.

### 4.2 Obtaining the recovery pack

The `tensor-usbdl` v0.2.0 release asset (GitHub direct access blocked; fetched through a proxy in ranged chunks and reassembled):

```bash
$ ls -l release-full.zip
-rw-r--r--  20869061  release-full.zip
$ unzip -t release-full.zip >/dev/null && echo "ZIP OK"
ZIP OK
```

Extracted `sources/gs201/`:

| Image | Size | Role |
|---|---|---|
| `bl1.img` | 12,288 | first stage (`0x410=0x01`, re-signed) |
| `pbl.img` | 40,960 | primary bootloader |
| `bl2.img` | 536,576 | second stage |
| `bl31.img` | 94,208 | TF-A |
| `tzsw.img` | 4,972,544 | TrustZone |
| `ldfw.img` | 2,392,064 | loadable firmware |
| `gsa.img` | 282,624 | Google Security firmware |
| `abl.img` | 1,564,672 | Android BootLoader |

### 4.3 Physical entry — three-button timing (two failures)

**Attempt 1.** After the user performed the hold, the tool log contained **no `Requested BL1`**:

```
Device detected: Google Pixel 7 series
Requested DPM → Sent → Ack
Requested EPBL → Sent → Ack
Requested BL2 → Sent → Ack
Requested BL2B → Sent → Ack
(silence)
```

Still DPM-first.

**Attempt 2.** Switched to **event-driven** startup: a watcher waits for the serial node to disappear (unplug), then for it to reappear (plug-in), and launches the tool within 200 ms — eliminating human launch latency.

This time `Requested BL1` appeared, but the chain **restarted from BL1 after BL2B**:

```
BL1 → DPM → EPBL → BL2 → BL2B → BL1 → DPM → EPBL → BL2 → BL2B → ...
```

Measured periods:

```
09:18:55.962 → 09:19:04.643   8.7 s
09:19:04.643 → 09:19:10.242   5.6 s
```

**A 5–10 s restart period is the documented signature of "buttons still held".** As soon as the user released all buttons, the chain ran straight through.

### 4.4 Chain completed (real log)

```
BL1  → DPM  → EPBL → BL2  → BL2B →
GSA1 → ABL  → ABLB → TZSW → TZSB →
LDFW → LDFB → BL31 → BL3B → Device disconnected!
```

`Device disconnected!` means the device left BootROM mode for the next stage. The USB product string changed from `Pixel ROM Recovery` to **`Pixel 7 Pro`**.

```bash
$ fastboot devices
REDACTED   fastboot
```

> Note: the serial changed from the BootROM's `REDACTED` to the bootloader's `REDACTED`. These are identifiers at different layers; this is normal.

### 4.5 First fastboot session

```bash
$ fastboot getvar battery-voltage
battery-voltage: 3434 mV
$ fastboot getvar version-bootloader
version-bootloader: cloudripper-1.0-8910487     # leaked recovery build (in RAM)
$ fastboot getvar unlocked
unlocked: yes                                    # ✅ unlock state intact
$ fastboot getvar current-slot
current-slot: a
$ fastboot getvar enter-reason
enter-reason: usb boot                           # confirms USB boot
```

**3434 mV was the blocker.** A 3 GB system write at that voltage was bound to fail.

### 4.6 Flashing the bootloader first (key move)

To escape the fragile "RAM-only bootloader" state, only the 14.5 MB official bootloader was flashed first:

```bash
$ fastboot flash bootloader bootloader-cheetah-cloudripper-17.0-15902555.img
Sending 'bootloader_a' (14203 KB)   OKAY [  0.351s]
Writing 'bootloader_a'              (bootloader) Flashing pack version cloudripper-17.0-15902555
(bootloader) flashing platform gs201
(bootloader) Validating partition bl1_a
(bootloader) Validating partition pbl_a
(bootloader) Validating partition bl2_a
(bootloader) Validating partition abl_a
(bootloader) Validating partition bl31_a
(bootloader) Validating partition tzsw_a
(bootloader) Validating partition gsa_a
(bootloader) Validating partition ldfw_a
(bootloader) Loading sideload ufsfwupdate
OKAY [  0.767s]
```

### 4.7 Power loss and rescue

```bash
$ fastboot reboot bootloader
Rebooting into bootloader   OKAY
$ fastboot devices
(no output)
```

At ~3.5 V the device **dropped off USB entirely** during the reboot — confirming the low-battery risk.

Recovery:

1. Plugged into a wall charger for ~40 minutes;
2. The device came up in **Rescue Mode**:

```
USB product name : AOSP on Cheetah
idProduct        : 0xD001
$ adb devices
REDACTED   rescue
```

3. Back to the bootloader:

```bash
$ adb reboot bootloader
$ fastboot getvar version-bootloader
version-bootloader: cloudripper-17.0-15902555    # ✅ official bootloader in flash
$ fastboot getvar enter-reason
enter-reason: reboot bootloader                  # ✅ no longer "usb boot"
$ fastboot getvar battery-voltage
battery-voltage: 3772 mV
```

**At this point the device was permanently out of ROM Recovery**: even after a disconnect, it can enter fastboot with Power + Vol-Down.

### 4.8 Battery plateau

In fastboot the charge current is capped; voltage stalled at ~3827 mV:

```
21:27:59 battery=3775 mV
21:32:00 battery=3820 mV
21:37:00 battery=3827 mV
21:37:30 battery=3827 mV
```

Waiting further was pointless. Since the **bootloader was already in flash and any failure was repeatable**, the official flashing script was run.

### 4.9 Running the official flash-all.sh (success)

```bash
$ cd factory-extracted/cheetah-cp3a.261005.002.a1
$ sh ./flash-all.sh
```

Key output:

```
Sending 'bootloader_a' (14203 KB)                  OKAY [  0.335s]
Writing 'bootloader_a'  (bootloader) Flashing pack version cloudripper-17.0-15902555
Rebooting into bootloader                          OKAY [  0.000s]
Sending 'radio_a' (103472 KB)                      OKAY [  2.453s]
Writing 'radio_a'       (bootloader) Flashing pack version g5300q-260604-260807-M-16036236
Rebooting into bootloader                          OKAY [  0.000s]
--------------------------------------------
Bootloader Version...: cloudripper-17.0-15902555
Baseband Version.....: g5300q-260604-260807-B-16036236
Serial Number........: REDACTED
--------------------------------------------
Setting current slot to 'a'                        OKAY [  0.082s]
Sending 'boot_a' (65536 KB)                        OKAY [  1.509s]
Sending 'init_boot_a' (8192 KB)                    OKAY [  0.188s]
Sending 'dtbo_a' (16384 KB)                        OKAY [  0.377s]
Sending 'vendor_kernel_boot_a' (65536 KB)          OKAY [  1.504s]
Sending 'pvmfw_a' (1024 KB)                        OKAY [  0.024s]
Sending 'vendor_boot_a' (65536 KB)                 OKAY [  1.504s]
Sending 'vbmeta_a' (12 KB)                         OKAY [  0.001s]
Sending 'vbmeta_system_a' (8 KB)                   OKAY [  0.001s]
Sending 'vbmeta_vendor_a' (4 KB)                   OKAY [  0.000s]
Erasing 'userdata'                                 OKAY [  0.747s]
Erasing 'metadata'                                 OKAY [  0.013s]
Sending sparse 'super' 1/27 (254972 KB)            OKAY [  6.034s]
...
Sending sparse 'super' 27/27 (197892 KB)           OKAY [  4.668s]
Erasing 'userdata'                                 OKAY [  0.713s]
Rebooting                                          OKAY [  0.000s]
Finished. Total time: 195.629s
```

**`exit=0`, everything succeeded.** The device rebooted into Android 17 and the user confirmed it booted normally.

---

## 5. Technical Analysis — Why It Had to Be Done This Way

### 5.1 Tensor G2 boot chain

```
BootROM (iROM, mask ROM, immutable)
   │  verify signature + compare ARB version in OTP
   ▼
BL1 (APBL container: 4 KB header + body; header 0x410 holds the USB-bootable bit)
   │  DRAM init (requires DPM parameters)
   ▼
PBL/EPBL ──► BL2 ──► BL31 (TF-A)
   │                    │
   │                    ▼
   │              TZSW / LDFW (TrustZone)
   ▼
GSA (Google Security firmware / Titan M2 side)
   │
   ▼
ABL (Android BootLoader) ──► fastboot / recovery / kernel
   │
   ▼
AVB 2.0 (dm-verity + vbmeta) ──► Android
```

### 5.2 Why "find an exploit" is not a real path

| Hypothetical attack | Verdict | Reason |
|---|---|---|
| Forge/tamper an image to bypass verification | Not viable | RSA-4096; private key in Google HSM |
| Downgrade the bootloader to bypass ARB | Not viable | OTP fuse is monotonic; hardware comparison |
| Write arbitrary addresses via the DNW protocol | Not viable | Protocol only serves named images; no address-write command |
| Abuse `unlock status = -1` to unlock | Not viable | Unlock state is guarded by Titan M2 |
| Flash a custom recovery for privilege escalation | Not viable | AVB rejects while locked; unlock needs GSA consent |

**Nothing in this recovery bypassed anything.** BL1, PBL, BL2, TZSW, GSA and ABL were all Google-signed, and the device verified each stage before continuing. The host was merely a courier.

### 5.3 The real weaknesses are engineering-level, not cryptographic

| ID | Finding | Severity | Impact |
|---|---|---|---|
| F-01 | The BootROM recovery channel is not robust to malformed frames; after garbage input it enters a persistent NAK state that even a `stop` frame cannot clear — only a power cycle recovers it | Low (physical access required) | Denial of service; no confidentiality/integrity impact |
| F-02 | On macOS the CDC-ACM reader "loses track" of subsequent requests and requires killing/restarting the process | Medium (maintainability) | Very low success rate for ordinary users; devices are easily misdiagnosed as permanently bricked |
| F-03 | The `Pixel ROM Recovery` channel is undocumented, with no official self-service tool | Process risk | Users are pushed to third-party reverse-engineered tools and leaked images |
| F-04 | ARB is a one-way door: a single downgrade can force the factory channel, and Google only warns in prose | Design trade-off | Availability / repairability risk |

### 5.4 Supply-chain note

The chain used here came from the community-distributed `tensor-usbdl` v0.2.0 release (`sources/gs201/`). Its safety depends on:

1. the images genuinely being Google-signed (indirectly proven by device-side verification succeeding);
2. the distribution channel not being tampered with.

**Recommendation:** after recovery, always overwrite the bootloader from the official factory package (done here) and verify `fastboot getvar version-bootloader` matches the official build string.

---

## 6. Lessons Learned

1. **Collect evidence before acting.** A single read-only byte of probing avoided a lot of blind work.
2. **A black screen is not death.** `18d1:4f00` + CDC-ACM = the BootROM is alive.
3. **Mode beats images.** With the wrong three-button timing, even perfect images go nowhere.
4. **Release the buttons.** A 5–10 s restart cycle is the deterministic signature of "still holding".
5. **Flash the bootloader first.** It converts a fragile RAM-resident bootloader into a persistent flash bootloader, making every later step repeatable.
6. **Don't brute-force on low battery.** 3.4 V cannot sustain a 3 GB write — but a 14 MB bootloader write is safe and buys retryability.
7. **The official `flash-all` is the finish line.** The recovery channel only gets the device back to fastboot; the actual system restore still uses Google's script.

---

## 7. Appendix

### 7.1 Key files and checksums

| File | Size | Notes |
|---|---|---|
| `factory-cheetah-cp3a.261005.002.a1.zip` | 3,921,490,797 | official factory package |
| SHA-256 | `5b5b06adb6566e20b927e887f42222f7387d25d37a3257b5f4655bb905aacdb8` | matches Google's published value ✅ |
| `bootloader-cheetah-cloudripper-17.0-15902555.img` | 14,544,648 | FBPK v2, platform `gs201` |
| `radio-cheetah-g5300q-260604-260807-b-16036236.img` | 105,955,468 | baseband |
| `release-full.zip` | 20,869,061 | tensor-usbdl v0.2.0 release |
| `recovery-pack/sources/gs201/` | 8 images | re-signed recovery chain |

### 7.2 FBPK v2 container format (as observed)

```
Header (112 B, little-endian, packed):
  0x00 u32 magic         = 0x4B504246 "FBPK"
  0x04 u32 version       = 2
  0x08 u32 header_size   = 112
  0x0C u32 entry_size    = 104
  0x10 16s platform      = "gs201"
  0x20 64s pack_version  = "cloudripper-17.0-15902555"
  0x60 u32 slot_type
  0x64 u32 data_align    = 512
  0x68 u32 total_entries = 15
  0x6C u32 total_size

Entry (104 B, little-endian, packed):
  0x00 u32 type          (0=table, 1=data, 2=sideload)
  0x04 36s name          ("bl1","pbl","bl2","abl","bl31","tzsw","gsa","ldfw","ufs","partition:N")
  0x28 40s product
  0x50 u64 offset
  0x58 u64 size
  0x60 u32 slotted
  0x64 u32 crc32
```

Observed entries:

```
[06] bl1    size=12,288      [07] pbl  size=40,960
[08] bl2    size=536,576     [09] abl  size=1,662,976
[10] bl31   size=102,400     [11] tzsw size=6,778,880
[12] gsa    size=360,448     [13] ldfw size=2,392,064
```

### 7.3 Command cheat sheet

```bash
# Evidence gathering
ioreg -p IOUSB -w0 -l | grep -iE 'Pixel|idProduct'
python3 tools/probe_rom.py 8

# Feed the recovery chain (in BL1-first mode)
./bin/tensor-usbdl -i recovery-pack/sources/gs201

# State checks once fastboot is available
fastboot devices
fastboot getvar battery-voltage
fastboot getvar version-bootloader
fastboot getvar unlocked
fastboot getvar current-slot
fastboot getvar enter-reason

# Official flash
cd factory-extracted/cheetah-cp3a.261005.002.a1
sh ./flash-all.sh
```

### 7.4 Timeline

| Time | Event |
|---|---|
| 20:14 | Investigation starts; `18d1:4f00` / Pixel ROM Recovery confirmed |
| 20:20 | Read-only serial probe captures the `eub:req:...:DPM` loop |
| 20:24 | Protocol decoded; custom DNW host implementation written |
| 20:27 | Official factory package downloaded (3.92 GB) and SHA-256 verified |
| 20:30 | FBPK v2 parsed; 8 sub-images extracted |
| 20:33 | Raw-payload send fails (missing DNW frame header) |
| 20:35 | Frame fixed; DPM/EPBL acknowledged but the chain still loops |
| 20:39 | Upstream Go tool built; reproduces the same DPM-first failure |
| 20:44 | XDA / telegra.ph guides discovered |
| 21:05 | Three-button hold + recovery pack reaches BL2B, still no BL1 request |
| 21:19 | Event-driven watcher; first `Requested BL1`; 5.6–8.7 s restarts due to held buttons |
| 21:20 | Buttons released; full chain completes → fastboot |
| 21:22 | Battery at 3434 mV; 14.5 MB bootloader flashed successfully |
| 21:23 | Device drops off USB after `reboot bootloader` |
| 21:26 | Wall-charged, enters Rescue Mode (`0xD001`); `adb reboot bootloader` recovers it |
| 21:27 | Official bootloader running from flash (`cloudripper-17.0-15902555`) |
| 21:38 | Battery plateaus at 3827 mV |
| 21:39 | `flash-all.sh` succeeds (195.6 s) |
| 21:42 | First boot |
| 21:47 | User confirms the system boots normally ✅ |
