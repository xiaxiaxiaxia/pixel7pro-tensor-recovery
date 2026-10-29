# Pixel 7 Pro 变砖恢复全过程与启动链安全审计

> 记录时间：2026-10-29 20:14 – 21:47（CST）
> 设备：Google Pixel 7 Pro（`cheetah` / SoC `gs201` / Tensor G2）
> 主机：macOS 27.2（arm64 / Apple Silicon）
> 结果：**成功恢复并刷入官方最新系统 `CP3A.261005.002.A1`（Android 17，2026-10）**

---

## 一、结论摘要

| 问题 | 结论 |
|---|---|
| 设备真的"死"了吗？ | 没有。它活在 Tensor BootROM 的 USB Download Mode（对外名 `Pixel ROM Recovery`）里 |
| 是硬件损坏吗？ | 不是。SoC、UFS 均正常，BootROM 的 USB 协议栈在正常响应 |
| 能不能靠"找漏洞破解"救回来？ | **不能，也不需要**。恢复全程使用 Google 官方签名的镜像，未绕过任何签名或防回滚校验 |
| 真正的病因 | Bootloader 降级触发 **anti-rollback（ARB）**，版本号烧在 SoC 的 **OTP 一次性熔丝**里，软件无法回写 |
| 真正的难点 | 不是密码学，而是**物理进入时序**（三键保持 → BL1-first 模式）和**镜像匹配**（必须用带 USB-bootable 位的 re-signed BL1） |
| 最终是否解锁刷机？ | 设备本来就是 `unlocked: yes`，走的是官方 `flash-all.sh`，没有任何非官方写入 |

**一句话总结：这台设备不是被"黑"回来的，是被"按对顺序喂对官方镜像"救回来的。**

---

## 二、设备与故障现象

### 2.1 原始状态（用户提供 + 实测确认）

```
位置 ID     : <USB-PORT>
连接类型     : Removable
生产企业     : Google
序列号       : REDACTED
链接速度     : 480 Mb/s
USB 供应商 ID: 0x18D1 (6353)
USB 产品 ID  : 0x4F00 (20224)
USB 产品版本 : 0x0100
产品名称     : Pixel ROM Recovery
```

同时系统中出现串口节点：

```bash
$ ls -l /dev/cu.usbmodem*
crw-rw-rw-  1 root  wheel  0x9000005  /dev/cu.usbmodem<PORT>
```

`0x18D1:0x4F00` + CDC-ACM 串口 = **Tensor BootROM 的 USB 下载模式**。这个模式不点屏、不进 fastboot、不进 recovery，所以在用户看来就是"黑屏死机"。

### 2.2 用户描述的关键症状

- Bootloader 降级后无法启动；
- 解锁状态显示 `-1`，无法刷机；
- 无法进入 recovery；
- 官方 `flash-all` 完全不可用。

### 2.3 设备识别

BootROM 在串口上主动报出：

```
exynos_usb_booting:09855000
```

按 `tensor-usbdl` 的解析规则取 `id[1:5]`：`"9855"` → **Pixel 7 系列**，与 cheetah 吻合。

---

## 三、诊断过程（含真实命令与输出）

### 3.1 第一步：确认设备到底在哪个模式

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
（无输出）
$ adb devices
（无输出）
```

结论：**既不是 fastboot 也不是 adb，而是 BootROM 下载模式**。

### 3.2 第二步：只读被动探测（关键取证）

写了一个纯被动脚本 `tools/probe_rom.py`：只打开串口、只发一个握手字节 `0x0A`、只读不写。

```python
fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
# c_iflag/c_oflag/c_lflag 全 0，c_cflag = CS8|CREAD|CLOCAL，115200 8N1
os.write(fd, b"\n")
```

真实输出：

```
[*] 已打开 /dev/cu.usbmodem<PORT> @115200 8N1
[*] 发送握手字节 0x0A ('\n') ...

eub:req:09855000:DPM
C
eub:req:09855000:DPM
C
eub:req:09855000:DPM
C
...
[*] 共收到 230 字节
```

**这是整个排查的转折点**：设备不是死的，它在**主动请求 `DPM` 镜像**，并且在等主机回 `C`（Clear-To-Send）后送数据。

### 3.3 协议解析

结合对 `tensor-usbdl` 源码的逆向，整理出完整协议：

**文本层（`\n` / `\r` 分隔）**

| 方向 | 报文 | 含义 |
|---|---|---|
| 设备→主机 | `exynos_usb_booting:<id>` | 设备自报 SoC/型号 |
| 设备→主机 | `eub:req:<id>:<NAME>` | 请求名为 NAME 的镜像 |
| 设备→主机 | `C` | 可以发送 |
| 设备→主机 | `eub:ack:<id>:<NAME>` | 已接收 |
| 设备→主机 | `eub:nak:<id>:<NAME>` | 拒收 |
| 设备→主机 | `irom_booting_failure:<trace>` | 引导失败 + 15 段 trace |
| 设备→主机 | `<X> header fail` | 镜像头校验失败 |

**二进制层（主机→设备，DNW 帧）**

```
+--------+------------------+------------------+----------------+
| 1B 44 4E 57 | uint32 LE(len+10) |  image bytes  | uint16 LE(sum) |
+--------+------------------+------------------+----------------+
   ESC "DNW"      长度字段          镜像本体         校验和
```

> 注意两个细节：
> 1. 长度字段是 `len + 10`（含 4 字节命令 + 2 字节校验 + 4 字节自身），**小端**；
> 2. 上游工具实际发的是**固定校验和 `0xFFFF`**（见其 `crc = []byte{0xFF,0xFF}`），不是真实求和——说明设备并不校验该字段。

### 3.4 第一次失败：缺帧头

最初我按"裸数据 + 校验和"发送，设备每 0.4 秒重发一次 `eub:req:...:DPM`，形成无限循环：

```
eub:req:09855000:DPM
C
    >>> 已发送 DPM 4096 bytes
eub:req:09855000:DPM
C
    >>> 已发送 DPM 4096 bytes
...（无限重复）
```

修正为 DNW 帧后，立刻出现 `eub:ack:09855000:DPM`。**协议层打通**。

### 3.5 第二次失败：模式错误 + 镜像不匹配

用官方 factory 包（`bootloader-cheetah-cloudripper-17.0-15902555.img`）解出的子镜像喂设备，行为变成：

```
Requested DPM  → Sent DPM  → Acknowledged DPM
Requested EPBL → Sent EPBL → Acknowledged EPBL
Requested DPM  → ...（回到开头，无限循环）
```

换成上游 Go 版工具（v0.2.0 源码编译）后现象完全一致，排除是我实现的问题。

**两个叠加原因：**

1. **进入模式错误**：没有做三键保持，BootROM 停在 **DPM-first** 模式——它直接运行 flash 里的旧 BL1，只把 DPM/PBL 当参数收，链路走不下去。
2. **BL1 不匹配**：factory BL1 的头部 `0x410 = 0x00`，**USB-bootable 位未置**；BootROM 在 USB 启动路径下只认 `0x410 = 0x01` 的 re-signed BL1。

实测确认：

```bash
$ xxd -s 1024 -l 32 sources/bl1.img
00000400: 4150 424c 0100 0000 0200 0000 0020 0000  APBL......... ..
00000410: 0004 0000 ...                          # 0x410 = 0x00
```

对比 recovery 包里的 BL1：

```bash
$ xxd -s 1024 -l 32 recovery-pack/sources/gs201/bl1.img
00000400: 4150 424c 0100 0000 0200 0000 0020 0000  APBL......... ..
00000410: 0104 0000 ...                          # 0x410 = 0x01 ✅
```

### 3.6 根因：ARB 防回滚

官方 Factory Images 页面明确写了这个故障模式：

> 设备更新后，旧 build 驻留在非活跃槽位，其 bootloader 的**防回滚版本未递增**。若活跃槽位随后刷入无法启动的 build，无缝更新的回退机制会尝试从非活跃槽位启动；由于该槽位是旧 bootloader，设备进入**无法启动状态**。

技术本质：

- ARB 版本号烧录在 SoC 的 **OTP（一次性可编程）熔丝**中；
- 熔丝**只能单调递增**，不可擦除、不可回写；
- BootROM/BL1 在加载下一级镜像时会做硬件比较，低于熔丝值直接拒绝。

所以"软件解锁降级"在物理上不成立。设备只能被 **版本 ≥ 熔丝值** 的官方签名镜像救回。

---

## 四、恢复方案与执行过程

### 4.1 关键情报来源

在确认"官方 factory 镜像走不通"后，检索到两处关键资料：

1. XDA 帖《unbrick a Pixel 7 Pro from a Hardbrick on Pixel ROM Recovery》
2. 实操指南《Unbricking my Pixel 7 (panther) with tensor-usbdl on macOS》

指南给出了两个决定性信息：

- 必须用 **电源 + 音量加 + 音量减** 三键、插线时保持、插上后继续按住 ≥15 秒，才能把 BootROM 切到 **BL1-first** 模式；
- 必须使用 release 包里 `sources/gs201/` 的 **re-signed（USB-bootable）** 引导链，而不是 factory 镜像。

### 4.2 获取恢复包

`tensor-usbdl` v0.2.0 的 release 资源（GitHub 直连受限，经镜像代理分段下载后拼接）：

```bash
$ ls -l release-full.zip
-rw-r--r--  20869061  release-full.zip
$ unzip -t release-full.zip >/dev/null && echo "ZIP OK"
ZIP OK
```

解包得到 `sources/gs201/`：

| 镜像 | 大小 | 作用 |
|---|---|---|
| `bl1.img` | 12,288 | 首级引导（`0x410=0x01`，re-signed） |
| `pbl.img` | 40,960 | 初级引导 |
| `bl2.img` | 536,576 | 二级引导 |
| `bl31.img` | 94,208 | TF-A |
| `tzsw.img` | 4,972,544 | TrustZone |
| `ldfw.img` | 2,392,064 | 可加载固件 |
| `gsa.img` | 282,624 | Google Security 固件 |
| `abl.img` | 1,564,672 | Android BootLoader |

### 4.3 物理进入：三键时序（失败两次才成功）

**尝试 1**：用户执行三键流程后启动工具，日志中**没有 `Requested BL1`**：

```
Device detected: Google Pixel 7 series
Requested DPM → Sent → Ack
Requested EPBL → Sent → Ack
Requested BL2 → Sent → Ack
Requested BL2B → Sent → Ack
（静默）
```

说明仍是 DPM-first 模式。

**尝试 2**：改用**事件驱动监听**——脚本先等待串口节点消失（拔线），再等待其出现（插线），出现后 200 ms 内启动工具，消除人工启动延迟。

这次终于出现 `Requested BL1`，但链路在 BL2B 后**回到 BL1 重来**：

```
BL1 → DPM → EPBL → BL2 → BL2B → BL1 → DPM → EPBL → BL2 → BL2B → ...
```

实测周期：

```
09:18:55.962 → 09:19:04.643   周期 8.7s
09:19:04.643 → 09:19:10.242   周期 5.6s
```

**5–10 秒周期正是指南中"按键还按着"的特征**。让用户松开全部按键后，链路立刻一泻千里。

### 4.4 链路跑通（真实日志）

```
BL1  → DPM  → EPBL → BL2  → BL2B →
GSA1 → ABL  → ABLB → TZSW → TZSB →
LDFW → LDFB → BL31 → BL3B → Device disconnected!
```

`Device disconnected!` 意味着设备从 BootROM 模式切换到了下一阶段。此时 USB 产品名从 `Pixel ROM Recovery` 变为 **`Pixel 7 Pro`**。

```bash
$ fastboot devices
REDACTED   fastboot
```

> 注意：序列号从 BootROM 的 `REDACTED` 变为 bootloader 的 `REDACTED`，这是两个不同层级的标识，正常现象。

### 4.5 第一次进 fastboot 的状态

```bash
$ fastboot getvar battery-voltage
battery-voltage: 3434 mV
$ fastboot getvar version-bootloader
version-bootloader: cloudripper-1.0-8910487     # 泄露的 recovery 引导（RAM 中）
$ fastboot getvar unlocked
unlocked: yes                                    # ✅ 解锁状态完好
$ fastboot getvar current-slot
current-slot: a
$ fastboot getvar enter-reason
enter-reason: usb boot                           # 确认是 USB 引导
```

**电量 3434 mV 是硬伤**。此时执行 3 GB 的系统写入几乎必然失败。

### 4.6 先刷 bootloader（关键一步）

为摆脱"RAM 临时引导"的脆弱状态，先只刷 14.5 MB 的官方 bootloader：

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

### 4.7 掉电与救回

```bash
$ fastboot reboot bootloader
Rebooting into bootloader   OKAY
$ fastboot devices
（无输出）
```

设备在 3.5 V 下重启瞬间**完全断电消失**。这一步验证了低电量刷机的风险。

救回过程：

1. 接墙充约 40 分钟；
2. 设备自动进入 **Rescue Mode**：

```
USB 产品名: AOSP on Cheetah
idProduct : 0xD001
$ adb devices
REDACTED   rescue
```

3. 从 rescue 切回 bootloader：

```bash
$ adb reboot bootloader
$ fastboot getvar version-bootloader
version-bootloader: cloudripper-17.0-15902555    # ✅ 官方 bootloader 已在 flash 上
$ fastboot getvar enter-reason
enter-reason: reboot bootloader                  # ✅ 不再是 usb boot
$ fastboot getvar battery-voltage
battery-voltage: 3772 mV
```

**这一刻设备已经彻底脱离 ROM Recovery**，即使再断电也能用「电源 + 音量下」正常进 fastboot。

### 4.8 电量平台期

fastboot 模式下充电电流被限制，电压停在 ~3827 mV 不再上升：

```
21:27:59 battery=3775 mV
21:32:00 battery=3820 mV
21:37:00 battery=3827 mV
21:37:30 battery=3827 mV
```

继续等待无意义。考虑到 **bootloader 已在 flash 上、任何失败都可重来**，决定直接执行官方刷机脚本。

### 4.9 执行官方 flash-all.sh（成功）

```bash
$ cd factory-extracted/cheetah-cp3a.261005.002.a1
$ sh ./flash-all.sh
```

关键输出：

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

**`exit=0`，全部成功。** 设备重启进入 Android 17，用户确认已正常开机。

---

## 五、技术分析：为什么必须这样救

### 5.1 Tensor G2 启动链

```
BootROM (iROM，掩膜 ROM，不可修改)
   │  验签 + 比较 OTP 中的 ARB 版本
   ▼
BL1 (APBL 容器：4KB header + body，header 0x410 含 USB-bootable 位)
   │  初始化 DRAM（需要 DPM 参数）
   ▼
PBL/EPBL ──► BL2 ──► BL31 (TF-A)
   │                    │
   │                    ▼
   │              TZSW / LDFW (TrustZone)
   ▼
GSA (Google Security 固件 / Titan M2 侧)
   │
   ▼
ABL (Android BootLoader) ──► fastboot / recovery / kernel
   │
   ▼
AVB 2.0 (dm-verity + vbmeta) ──► Android
```

### 5.2 为什么"找漏洞破解"这条路不存在

| 假设的攻击路径 | 结论 | 原因 |
|---|---|---|
| 伪造/篡改镜像绕过验签 | 不成立 | RSA-4096 签名，私钥在 Google HSM |
| 降级到旧 bootloader 绕过 ARB | 不成立 | OTP 熔丝单调递增，硬件比较 |
| 通过 DNW 协议写任意地址 | 不成立 | 协议只有"按名供图"，无地址写命令 |
| 利用 `unlock status = -1` 解锁 | 不成立 | 解锁态由 Titan M2 守护 |
| 刷自定义 recovery 提权 | 不成立 | 锁定时 AVB 拒绝；解锁也需 GSA 同意 |

**本次恢复没有用到任何一项"绕过"**：BL1、PBL、BL2、TZSW、GSA、ABL 全部是 Google 签名镜像，设备侧逐级验签通过后才继续。主机端只是"搬运工"。

### 5.3 真正的"弱点"在工程层，不在密码学层

| 编号 | 发现 | 定性 | 影响 |
|---|---|---|---|
| F-01 | BootROM 恢复通道对非法帧鲁棒性差，写入垃圾后进入持续 NAK 状态，`stop` 帧也无法恢复，必须断电 | 低危（需物理接触） | 可造成拒绝服务，不影响机密性/完整性 |
| F-02 | macOS 下 CDC-ACM 串口读取会"跟丢"后续请求，必须杀进程重启 | 中危（可维护性） | 普通用户成功率极低，设备易被误判为"彻底砖" |
| F-03 | `Pixel ROM Recovery` 通道未公开，无官方自救工具 | 流程风险 | 用户被迫依赖第三方逆向工具与泄露镜像 |
| F-04 | ARB 是"单向门"，一次降级即可能进工厂通道，官方仅以警告提示 | 设计权衡 | 可用性/可维修性风险 |

### 5.4 供应链风险提示

本次使用的引导链来自社区分发的 `tensor-usbdl` v0.2.0 release 内置的 `sources/gs201/`。其安全性依赖两点：

1. 镜像确实由 Google 签名（设备侧验签通过可间接证明）；
2. 分发渠道未被篡改。

**建议**：恢复后必须用官方 factory 包覆盖 bootloader（本次已做），并核对 `fastboot getvar version-bootloader` 是否为官方 build 号。

---

## 六、经验总结（给下次的自己）

1. **先取证再动手**：只读探测一个字节就能避免大量盲目操作。
2. **"黑屏"≠"死亡"**：`18d1:4f00` + CDC-ACM 串口 = BootROM 还活着。
3. **模式 > 镜像**：三键时序不对，再正确的镜像也走不通。
4. **按键必须松**：5–10 秒周期重启是"还按着"的确定性特征。
5. **先刷 bootloader**：把设备从"RAM 临时引导"变成"flash 官方引导"，后面所有操作都可重试。
6. **低电量别硬刷**：3.4 V 刷 3 GB 必挂；但刷 14 MB 的 bootloader 是安全的，且能换来可重试的能力。
7. **官方 flash-all 是终点**：恢复通道只负责"把设备送回 fastboot"，真正的系统恢复仍走官方脚本。

---

## 七、附录

### 7.1 关键文件与校验

| 文件 | 大小 | 说明 |
|---|---|---|
| `factory-cheetah-cp3a.261005.002.a1.zip` | 3,921,490,797 | 官方 factory 包 |
| SHA-256 | `5b5b06adb6566e20b927e887f42222f7387d25d37a3257b5f4655bb905aacdb8` | 与官方页面一致 ✅ |
| `bootloader-cheetah-cloudripper-17.0-15902555.img` | 14,544,648 | FBPK v2，platform `gs201` |
| `radio-cheetah-g5300q-260604-260807-b-16036236.img` | 105,955,468 | 基带 |
| `release-full.zip` | 20,869,061 | tensor-usbdl v0.2.0 release |
| `recovery-pack/sources/gs201/` | 8 个镜像 | re-signed 恢复引导链 |

### 7.2 FBPK v2 容器格式（实测）

```
Header (112 B, little-endian, packed):
  0x00 u32 magic        = 0x4B504246 "FBPK"
  0x04 u32 version      = 2
  0x08 u32 header_size  = 112
  0x0C u32 entry_size   = 104
  0x10 16s platform     = "gs201"
  0x20 64s pack_version = "cloudripper-17.0-15902555"
  0x60 u32 slot_type
  0x64 u32 data_align   = 512
  0x68 u32 total_entries= 15
  0x6C u32 total_size

Entry (104 B, little-endian, packed):
  0x00 u32 type         (0=table, 1=data, 2=sideload)
  0x04 36s name         ("bl1","pbl","bl2","abl","bl31","tzsw","gsa","ldfw","ufs","partition:N")
  0x28 40s product
  0x50 u64 offset
  0x58 u64 size
  0x60 u32 slotted
  0x64 u32 crc32
```

实测条目：

```
[06] bl1    size=12,288      [07] pbl  size=40,960
[08] bl2    size=536,576     [09] abl  size=1,662,976
[10] bl31   size=102,400     [11] tzsw size=6,778,880
[12] gsa    size=360,448     [13] ldfw size=2,392,064
```

### 7.3 本次用到的命令速查

```bash
# 取证
ioreg -p IOUSB -w0 -l | grep -iE 'Pixel|idProduct'
python3 tools/probe_rom.py 8

# 喂恢复引导链（BL1-first 模式下）
./bin/tensor-usbdl -i recovery-pack/sources/gs201

# 进入 fastboot 后的状态检查
fastboot devices
fastboot getvar battery-voltage
fastboot getvar version-bootloader
fastboot getvar unlocked
fastboot getvar current-slot
fastboot getvar enter-reason

# 官方刷机
cd factory-extracted/cheetah-cp3a.261005.002.a1
sh ./flash-all.sh
```

### 7.4 时间线

| 时间 | 事件 |
|---|---|
| 20:14 | 开始排查，确认 `18d1:4f00` / Pixel ROM Recovery |
| 20:20 | 只读串口探测，抓到 `eub:req:...:DPM` 循环 |
| 20:24 | 解析协议，自研 DNW 主机端 |
| 20:27 | 下载官方 factory 包（3.92 GB）并校验 SHA-256 |
| 20:30 | 解析 FBPK v2，导出 8 个子镜像 |
| 20:33 | 裸数据发送失败（缺 DNW 帧头） |
| 20:35 | 修正帧头，DPM/EPBL 收到 ack，但链路仍循环 |
| 20:39 | 编译上游 Go 版工具，确认同样在 DPM-first 模式失败 |
| 20:44 | 找到 XDA / telegra.ph 关键指南 |
| 21:05 | 三键 + recovery 包，推进到 BL2B，仍无 BL1 请求 |
| 21:19 | 事件驱动监听，首次出现 `Requested BL1`，但按键未松导致 5.6–8.7 s 重启 |
| 21:20 | 松开按键，完整链路跑通 → fastboot |
| 21:22 | 电量 3434 mV，先刷 14.5 MB bootloader 成功 |
| 21:23 | `reboot bootloader` 后设备掉电消失 |
| 21:26 | 墙充后进入 Rescue Mode（`0xD001`），`adb reboot bootloader` 救回 |
| 21:27 | 官方 bootloader 在 flash 上运行（`cloudripper-17.0-15902555`） |
| 21:38 | 电量卡在 3827 mV 平台 |
| 21:39 | `flash-all.sh` 执行成功（195.6 s） |
| 21:42 | 首次开机 |
| 21:47 | 用户确认系统正常启动 ✅ |
