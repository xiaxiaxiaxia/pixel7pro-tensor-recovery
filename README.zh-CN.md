# Pixel 7 Pro（Tensor G2）变砖恢复记录与启动链安全审计

[English](README.md) · **简体中文**

一台 **Pixel 7 Pro（`cheetah`，SoC `gs201`）** 因 bootloader 降级触发 **anti-rollback（ARB）**，
卡在 `18d1:4f00 "Pixel ROM Recovery"`（Tensor BootROM USB 下载模式）。最终成功恢复，并刷入官方最新版
**`CP3A.261005.002.A1`（Android 17，2026-10）**。

> **没有用漏洞、没有绕过签名、没有改熔丝。** 全程使用的都是 Google 签名的镜像，
> 校验全部在设备侧完成，主机只是"搬运工"。

---

## TL;DR —— 到底什么修好了它

1. **进入 `BL1-first` 模式**：插线时按住 **电源 + 音量加 + 音量减**，插上后**继续按住 ≥15 秒**，
   然后**松开全部按键**。（不松 → 链路每 5–10 秒从 BL1 重启。）
2. **必须用 re-signed 的恢复引导链**，而不是 factory 镜像。factory 的 `bl1.img` 头部
   `0x410 = 0x00`（USB-bootable 位未置），会被 BootROM 拒绝；恢复包里的是 `0x410 = 0x01`。
3. 用 `tensor-usbdl` 供图：
   `./tensor-usbdl -i recovery-pack/sources/gs201`
4. 预期链路：
   `BL1 → DPM → EPBL → BL2 → BL2B → GSA1 → ABL → ABLB → TZSW → TZSB → LDFW → LDFB → BL31 → BL3B → 断开`
5. 进入 fastboot 后：**先** `fastboot flash bootloader …`（14 MB，把脆弱的 RAM 临时引导换成持久引导），
   再执行官方包里的 `sh flash-all.sh`。

完整细节：[`docs/zh/`](docs/zh/) · [`docs/en/`](docs/en/)

---

## 原始故障（动手之前）

最初报告的症状，共三条：

1. **完全进不去 bootloader。** `fastboot devices` 和 `adb devices` 都是空的，设备只以
   `18d1:4f00 "Pixel ROM Recovery"` 枚举出来——这是 Tensor BootROM 的 USB 下载模式，屏幕全黑。
   既没有 fastboot，也没有 recovery。
2. **官方刷机路径不可用。** `flash-all.sh` 依赖一个能工作的 bootloader，而当时根本没有。
3. **解锁状态 `-1`，刷机被拒。** 用 `tensor-usbdl` 把链路拉起来之后，解锁状态报 `-1`，刷写操作被拒绝。

### `-1` 到底是什么

`-1`（`0xFFFFFFFF`）是**"未知 / 未初始化"的哨兵值**，不是锁定状态。它是 ABL 向
**Titan M2 / GSA** 查询解锁状态失败时的返回值——典型场景就是 RAM 里跑着、还没和安全芯片
完成握手的临时恢复引导。

它**不表示"已锁定"**，也**不表示设备永久不可解锁**。把它读成"锁定"，正是很多人误判
"设备彻底砖了"的根源。

本次实测：

| 上下文 | `fastboot getvar unlocked` |
|---|---|
| RAM 中的恢复引导（`cloudripper-1.0-8910487`） | `yes` |
| flash 中的官方引导（`cloudripper-17.0-15902555`） | `yes` |

也就是说，**锁状态一直是好的**；坏的是**引导链**。刷机被拒的原因不是锁，而是缺失/失败的
bootloader 上下文。

最初那段提示词（已脱敏）存档在 [`docs/original-request.md`](docs/original-request.md)。

---

## 为什么会变砖

防回滚版本号存放在 SoC 的 **OTP 熔丝**里：单调递增、不可擦除、不可回写。一旦降级到低于熔丝值的
bootloader，BootROM 就拒绝继续，回落到它的 USB 下载模式。这在软件层无法逆转——只有版本号
**≥ 熔丝值** 的镜像才能被加载。

Google 自己的 factory images 页面就记录了这个故障模式（旧 bootloader 留在非活跃槽位，
无缝更新回退时启动它，设备进入无法启动状态）。

---

## 仓库结构

```
.
├── README.md                                   # 英文版
├── README.zh-CN.md                             # 简体中文（本文件）
├── docs/
│   ├── original-request.md                     # 最初提示词（已脱敏）
│   ├── en/pixel7pro-recovery-and-audit-en.md   # 完整记录 + 审计（英文）
│   └── zh/pixel7pro-recovery-and-audit-zh.md   # 完整记录 + 审计（中文）
├── tools/
│   ├── probe_rom.py    # 只读取证：发一个 0x0A，打印设备输出
│   └── dnw_serve.py    # FBPK v2 解析器 + DNW/EUB 主机端实现
└── logs/
    ├── boot-chain-success.log   # 成功链路的脱敏摘录
    └── flash-all.log            # 成功刷机的脱敏摘录
```

> 二进制文件（factory 镜像、bootloader 包、恢复引导链）**不在仓库中**——见
> [法律与免责声明](#法律与免责声明)。

---

## 协议速查

文本层，以 `\n` / `\r` 分隔，CDC-ACM 上 115200 8N1：

| 方向 | 报文 | 含义 |
|---|---|---|
| 设备→主机 | `exynos_usb_booting:<id>` | SoC/型号标识（`id[1:5]` = `9855` → Pixel 7 系列） |
| 设备→主机 | `eub:req:<id>:<NAME>` | 请求名为 `<NAME>` 的镜像 |
| 设备→主机 | `C` | 可以发送 |
| 设备→主机 | `eub:ack:<id>:<NAME>` | 已接收 |
| 设备→主机 | `eub:nak:<id>:<NAME>` | 拒收 |
| 设备→主机 | `irom_booting_failure:<trace>` | 引导失败 + trace |
| 主机→设备 | DNW 帧 | 见下 |

主机 → 设备帧（小端）：

```
1B 44 4E 57 | uint32 LE(len + 10) | image bytes | uint16 LE(sum)
ESC "DNW"        长度字段            镜像本体        校验和
```

上游工具实际发的是固定 `0xFFFF` 校验和，说明该字段并未被校验。

## FBPK v2 容器（实测布局）

```
Header 112 字节，packed 小端：
  u32 magic=0x4B504246 "FBPK", u32 version=2, u32 header_size=112, u32 entry_size=104,
  16s platform ("gs201"), 64s pack_version, u32 slot_type, u32 data_align,
  u32 total_entries, u32 total_size

Entry 104 字节，packed 小端：
  u32 type (0=table, 1=data, 2=sideload), 36s name, 40s product,
  u64 offset, u64 size, u32 slotted, u32 crc32
```

---

## 安全说明

审计结论刻意"无聊"：**启动链把该做的事做好了。**

- 伪造镜像：被 RSA-4096 签名挡住（私钥在 Google HSM）。
- 降级越过 ARB：被硬件比较的 OTP 熔丝挡住。
- 通过 DNW 写任意地址：协议里根本没有这种命令。
- 滥用 `unlock status = -1`：解锁态由 Titan M2 守护。

审计**真正**发现的是工程层的弱点：

| 编号 | 发现 | 严重性 |
|---|---|---|
| F-01 | BootROM 对畸形帧鲁棒性差；写入垃圾数据后进入持续 NAK 状态，连 `stop` 帧都无法清除，只能断电恢复 | 低（需物理接触） |
| F-02 | macOS 下 CDC-ACM 读取会跟丢后续请求，必须杀进程重启才能继续 | 中（可维护性） |
| F-03 | `Pixel ROM Recovery` 通道未公开，没有官方自助工具 | 流程风险 |
| F-04 | ARB 是单向门，一次降级就可能被迫走工厂通道 | 设计权衡 |

供应链方面：本次的恢复引导链来自社区分发的 release。设备侧验签通过可以间接证明它由 Google 签名，
但"从非官方渠道获取签名引导镜像"本身就是高价值攻击面。**恢复后务必用官方 factory 包重新刷写
bootloader**，并核对 `fastboot getvar version-bootloader`。

---

## 法律与免责声明

- 操作在个人自有设备上进行，目的是维修。
- **本仓库不再分发任何专有二进制文件。** factory 镜像、bootloader 包、恢复引导链均属 Google，
  请从官方渠道获取并遵守其条款。
- 脚本按"原样"提供，不附带任何担保。向 bootloader 写入可能把设备彻底变砖。
- 本仓库不意图规避所有权、授权或安全控制；请勿用于你并不拥有的设备。

## 致谢

- [JoshuaDoes/tensor-usbdl](https://github.com/JoshuaDoes/tensor-usbdl) —— 工具与内置的
  `gs201` 恢复引导链。
- XDA 帖 *"unbrick a Pixel 7 Pro from a Hardbrick on Pixel ROM Recovery"*。
- *panha* 与 *kazan_alx* 的 telegra.ph 实操指南，以及 `asamofal` 的重启技巧。

## 许可

建议：文档采用 **CC BY 4.0**，脚本采用 **MIT**。如果希望在 GitHub 上明确显示，请补充 `LICENSE` 文件。
