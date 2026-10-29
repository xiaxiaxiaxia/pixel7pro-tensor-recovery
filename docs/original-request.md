# Original Request (archived)

> The prompt that started this investigation, archived verbatim for context.
> **Redactions:** the USB serial number and the USB port location ID have been replaced
> with `REDACTED` / `<USB-PORT>`. Everything else is unchanged.

---

我现在连接的谷歌设备 pixel 7 pro，因为 bootloader 降级锁现在无法启动了，只能通过
https://github.com/JoshuaDoes/tensor-usbdl 这个开源项目引导到 bootloader，并且解锁状态提示 -1，
无法进行刷机，也无法进入 recovery，无法使用现在官方给到的刷机方式，我需要你使用安全审计相关的知识，
找到硬件或者软件的漏洞，恢复这个设备并且输出漏洞报告，需要偏低层的知识恢复这个设备，当前设备已连接，
我需要你不使用网络入侵的违法手段，修复这个设备，刷入现在官方最新的系统，这个操作需要看下能否找到设备
底层的芯片或者安全系统漏洞，祝你好运，连接设备提示内容如下：

```
Pixel ROM Recovery：

  位置ID：        <USB-PORT>
  连接类型：      Removable
  生产企业：      Google
  序列号：        REDACTED
  链接速度：      480 Mb/s
  USB供应商ID：   0x18d1
  USB产品ID：     0x4f00
  USB产品版本：   0x0100
  已分配电源：    2.5 W (500 mA)

/global
```

---

## English rendering

> My Google Pixel 7 Pro won't boot after a bootloader downgrade lock. It can only be brought
> up through the open-source project <https://github.com/JoshuaDoes/tensor-usbdl>, and the
> unlock status shows `-1`, so flashing is refused. I can't enter recovery either, and none of
> the official flashing methods work. I need you to use security-audit knowledge to find a
> hardware or software vulnerability, recover the device and produce a vulnerability report —
> this needs low-level knowledge. The device is connected right now. I do not want any illegal
> network-intrusion methods; just repair the device and flash the current official latest
> system. See whether a vulnerability can be found in the device's low-level chip or security
> system. Good luck. The device reports:

---

## How each point was resolved

| Original statement | What it turned out to mean | Resolution |
|---|---|---|
| "bootloader downgrade lock, won't boot" | Anti-rollback (ARB) tripped; ARB counter lives in OTP eFuses and is monotonic | Only images with version ≥ fuse value can load |
| "can only boot via tensor-usbdl" | Device sits in BootROM USB Download Mode (`18d1:4f00`), not in fastboot | Correct for this state — it *is* the only entry point |
| "unlock status shows −1, flashing refused" | `−1` is the "unknown" sentinel returned when the unlock query cannot reach Titan M2/GSA, typical of a partially initialised RAM bootloader — not a lock state | After flashing the official bootloader and booting it from flash, `fastboot getvar unlocked` returned `yes` |
| "can't enter recovery" | Recovery is unreachable while the boot chain is broken | Recovery/boot chain restored by serving the signed chain |
| "none of the official flashing methods work" | `flash-all` needs a working bootloader/fastboot | `flash-all.sh` succeeded once fastboot was back |
| "find a hardware/software vulnerability" | The boot chain has no usable bypass: signature + OTP enforcement are sound | No exploit used or needed; the audit reports engineering-level findings instead |
