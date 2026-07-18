# Hook 检测子系统 深度逆向专题

目标库：`libtersafe.so`（腾讯 ACE / TP TenProtect mobile SDK，`GCLOUD_VERSION_TP_7.7.049.57576`，ARM64，`com.tencent.tmgp.dfm` 三角洲行动）
BuildID/SHA1：`d70d7926094ae39a46745c12ddcc1877641f82e8`

分析边界：仅静态逆向 / 防御性取证，用于理解该反外挂模块如何**检测** hook。**不提供任何绕过、致盲、无痕 hook 或规避方法。**

---

## 0. 一句话结论

libtersafe 的 hook 检测是**多探测器 + 云端可下发特征**的组合，注册进一张「命名扫描项」表，由 `/proc/self/maps` 扫描器统一驱动。核心 5 条：

1. **`elf_hook_scan`** — inline/trampoline hook 检测：把内存代码段与磁盘 ELF 原始映像**逐页 memcmp + CRC 比对**，差异即认定被改码。
2. **`opcode_scan`** — 操作码扫描：在代码区搜可疑跳转/断点操作码（trampoline `br/blr`、`brk/hlt` 等）。
3. **`ts2_got`** — GOT/PLT 完整性：校验导入表跳转目标是否落在预期模块范围内（检测 GOT/PLT 重定向 hook）。
4. **代码段自校验 `sub_28DE4C`** — `txt_seg_crc`，逐页内存 vs 磁盘 diff（详见 `anti_tamper_crc.md §2.1`）。
5. **`gp4_pagemap`** — **影子页/双重映射 hook 检测**：读 `/proc/self/pagemap` 物理帧号(PFN)，穿透「只读视图干净、取指走另一物理页」的物理层 hook（见 §4.5）。
6. **`various_opcode` / `crash_various_opcode` / `opcode_crash`** — 反调试/反篡改的崩溃诱饵操作码。

命中后经 `name=%s|feature=%s|cert_crc=…` 组包，由 `0x434F3C` 派发、走 GetReportData 上报。

---

## 1. 命名扫描项注册表

各检测器名字是加密串，运行时解密后**注册进一张 map**（插入函数 `sub_222228`）。注册点集中在 `0x27fcd0` / `0x28028c` 一带，形如：

```text
decrypt("elf_hook_scan")  -> sub_222228(map, name, handler)   @0x28028c
decrypt("frida_scan")     -> sub_222228(...)                  @0x280174
decrypt("trusted_scanner")-> sub_222228(...)                  @0x27fff4
decrypt("opcode_scan")    -> sub_222228(...)                  @0x28e558
...
```

已确认注册的扫描项（解密串 + stub）：

| 扫描项名 | 密文@ | stub | 作用 |
|---|---|---|---|
| `elf_hook_scan` | `0x28028c` | `0x4e9dac` | ★ inline/trampoline hook 检测 |
| `opcode_scan` | `0x28e558` | `0x4e79c4` | ★ 可疑操作码扫描 |
| `opcode_crash` | `0x28e508` | `0x4e84fc` | 崩溃诱饵操作码 |
| `ts2_got` | `0x25574c` | `0x4e9930` | ★ GOT/PLT 完整性 |
| `various_opcode` | `0x220984` | `0x4e82c0` | 操作码变体检测 |
| `various_opcode_objvm` | `0x2209e8` | `0x4eaf98` | objVM 版操作码检测 |
| `crash_various_opcode` | `0x2a9b20` | `0x4e95d0` | 崩溃诱饵变体 |
| `frida_scan` | `0x280174` | `0x4eab20` | Frida 注入检测 |
| `trusted_scanner` | `0x27fff4` | `0x4e9c8c` | 受信扫描器标识 |
| `scan_by_detect` | `0x2a57b0` | `0x4e7784` | 通用探测扫描 |
| `attest_scan_objvm` | `0x220a4c` | `0x4e7d24` | 证明/attestation 扫描 |
| `scan_loop2` | `0x20f618` | `0x4ead58` | 扫描主循环 2 |
| `hook` | `0x231a24` | `0x4eb658` | hook 结果字段/标签 |

> 关键 handler 地址（`elf_hook_scan` 解密串的调用点）：`0x2310e8, 0x247a58, 0x248568, 0x2679c0, 0x27fcd0, 0x28028c, 0x280a4c, 0x280ef8, 0x28be08, 0x28bec0, 0x2951b0, 0x2b5ff0`。

---

## 2. 驱动器：`/proc/self/maps` 扫描器 `sub_3E06D0`

所有代码类探测都由 `sub_3E06D0` 统一喂数据：
- 打开 `/proc/self/maps`（隐藏串 XOR `0x18` 还原），逐行解析；
- 只取 `r-xp`（可执行代码段）与 `r--p`（只读段）区间；
- 对每个模块区间调用注册好的探测器（elf_hook_scan / opcode_scan / ts2_got …）；
- 命中结果交 `sub_434F3C` 汇聚上报。

配套用 `dl_iterate_phdr`（唯一调用者 `0x50ae74`）+ `dladdr` 枚举模块段、定位磁盘路径。

---

## 3. `elf_hook_scan` —— inline / trampoline hook 检测

**原理：内存代码 vs 磁盘 ELF 原像逐页比对。** 真正比对落在代码段自校验 `sub_28DE4C @ 0x28de4c`（见 `anti_tamper_crc.md §2.1`）：

```text
sub_28DE4C(a1=扫描描述符, a2=上报ctx, a3=模块名, a4=内存bias, a5=文件偏移)
  ├─ 守卫 *(ctx+0x3ac) 已禁用则跳过
  ├─ 模块白名单：仅校验自身 mrpcs_lib
  ├─ open+lseek 磁盘 so 到对应偏移
  └─ 逐页循环：
       read(fd, buf, page)                 ← 磁盘原页
       sub_48924C(内存页, page, crc)        ← 内存页 crc32_cont 累加
       sub_4A4658(内存页, 磁盘页, page)      ← memcmp 内存 vs 磁盘
       差异页 → sub_28E2E4 登记 bin_patch/skip（串 "!skip:0x%08x, bin_patch_cnt:%d"）
       篡改页 >20(v57>0x13) 中止；每 50 页 usleep(10ms)
  收尾：sub_28E490 上报(总页/篡改页)
        *(ctx+0x84)=~crc  → txt_seg_crc
        *(ctx+0x84 附近)= 篡改率≥10% 置可疑
```

配套字节比较原语 `sub_4A4774`（`ldrb`/`cmp` 字节循环）用于把可疑区间字节与预期模式比对；SDK 自身合法 inline patch 会被记为 `skip` 免误报。

**能抓到什么**：任何对已加载 `.text` 的 inline hook（前 4~16 字节被改成 `ldr x16,#..; br x16` 之类 trampoline）都会让内存页 ≠ 磁盘页 → memcmp 命中 → 记 bin_patch → 上报 `txt_seg_crc` 异常。

---

## 4. `opcode_scan` —— 可疑操作码扫描

注册于 `0x28e558`（紧邻代码段自校验 `0x28de4c` 之后，同属 `0x28xxxx` 完整性簇）。在代码区按操作码模式搜索：
- trampoline 特征（间接跳转 `br/blr xN`、`ldr xN,[pc]; br xN` 常量池跳转）；
- 断点/陷阱操作码（`brk #imm`、`hlt`）——软件断点/部分 hook 框架会写入；
- `various_opcode` / `various_opcode_objvm` 是它的变体，覆盖不同指令形态与 objVM（内置 mini-VM）保护下的代码。

`opcode_crash` / `crash_various_opcode` 是**主动防御**：在关键路径埋崩溃诱饵操作码，被单步/改写时触发异常，兼作反调试。

### 4.1 `opcode_scan` 触发条件深挖（逐指令 + 混淆说明）

`opcode_scan` 检测例程集中在 `0x26943c` / `0x269520`（decrypt(`opcode_scan`,stub `0x4e79c4`) 后进入）。**该例程做了控制流平坦化 + 不透明谓词混淆**（大量 `orr wX,wY,#n; eor wX,..` 互相抵消的垃圾常量、`mov/movk` 拼常量作为分发状态），因此**逐位的操作码掩码表被刻意隐藏**，无法纯静态完整还原（诚实标注）。但确认到的具体触发机制如下：

**A. ptrace 自检 / 寄存器校验（confirmed）**
`0x50e6c0` = **`ptrace` PLT**（GOT `0x51d008` → `R_AARCH64_JUMP_SLOT ptrace@LIBC`）。例程用：
```c
// 0x2694ac
ptrace(0x4204 /*PTRACE_GETREGSET*/, pid, 1 /*NT_PRSTATUS 通用寄存器*/, &iov);
if ((reg & 0xffff0000)!=0xBEEF0000 || (reg & 0xffff)!=0x00AD) fail;  // 哨兵 0xBEEF00AD
// 0x269560 / 0x2695b8
ptrace(0x4205 /*PTRACE_SETREGSET*/, pid, 1,      &iov);
ptrace(0x4205 /*PTRACE_SETREGSET*/, pid, 0x404 /*NT_ARM_SYSTEM_CALL*/, &iov2);
```
- 用 `PTRACE_GETREGSET/SETREGSET` 读写目标寄存器，并核对一个**哨兵值 `0xBEEF00AD`** 是否能被正确读回——**若已有调试器/ptracer 占用了 ptrace 通道，这一步会失败** → 判定被调试/被 hook。
- `SETREGSET(NT_ARM_SYSTEM_CALL=0x404)` 可改写目标 syscall 号，配合 `crash_various_opcode` 让目标执行到崩溃/受控点。

**B. 崩溃诱饵动作（confirmed）**
命中后走 `0x269520`：再次 `ptrace(0x4205,…)` 写回寄存器，失败即 `mov w0,#-1` 返回错误标志，交上层上报/崩溃（`opcode_crash`）。

**C. 代码区操作码匹配（design-level，掩码被混淆）**
`opcode_scan` 由 `/proc/self/maps` 扫描器 `sub_3E06D0` 驱动，对 `r-xp` 区逐条取 32-bit 指令字做 `(insn & mask)==pattern` 匹配。它命中的**操作码类别**（据设计意图 + 邻接 crash 项 + 常规反外挂实现）：
- inline hook / trampoline：`br/blr xN`（`0xD61F0000/0xD63F0000` 系）、`ldr x16,#imm; br x16` 常量池跳转、指向模块外的 `b/bl`；
- 陷阱指令：`brk #imm`（`0xD4200000` 系）、`hlt`；
- 被改写/异常的指令序列（自改码、脱壳跳板）。
> 精确掩码/pattern 表因平坦化+不透明谓词隐藏，需运行时或反混淆才能逐条确认——本项标 **unconfirmed**。

**D. 云端可下发新特征（confirmed，来自 §7）**
`feature_rcv_start|name|crc|size` 通道能**热更 opcode 特征**，所以「一直触发」也可能是服务端新下发了一条匹配你环境的特征，而非本地固定规则。

### 触发条件总表（为什么会「一直触发」）
| # | 触发条件 | 证据 | 置信度 |
|---|---|---|---|
| 1 | 进程被调试 / 有 ptracer（ptrace 通道被占） | `ptrace GETREGSET` + 哨兵 `0xBEEF00AD` 校验失败 | confirmed |
| 2 | 硬件断点 / 寄存器被改（读回寄存器不符） | `GETREGSET(NT_PRSTATUS)` 值校验 | strong |
| 3 | `r-xp` 里有 inline hook/trampoline 操作码 | maps 扫描 + 操作码匹配 | strong（掩码 unconfirmed） |
| 4 | 代码里有 `brk/hlt` 软件断点 | opcode_scan/opcode_crash 语义 | strong |
| 5 | 服务端新下发的 opcode 特征匹配到你的代码 | `feature_rcv_*` 热更通道 | confirmed |
| 6 | 自改码 / JIT / 脱壳跳板被误判 | 只认模式不认意图 | inference |

**排查建议（诊断，非绕过）**：先确认环境里是否挂着调试器/Frida/HW 断点（触发条件 1/2/4）；再看命中上报的 `name=%s|feature=%s` 指出的是本地固定项还是云端 `feature`（触发条件 5）；若是自有模块被误报，定位引入上述指令形态的第三方库（触发条件 3/6）。

---

## 4.5 影子页 / 双重映射 hook 检测（`pagemap`）—— **有**

**结论：有专门的影子页 hook 检测，走 `/proc/self/pagemap` 读物理帧号（PFN）比对。**

「影子页 hook」= 攻击者把可执行页做**双重映射**：`.text` 的只读视图仍是干净字节，但 CPU 实际取指走另一份物理页（被改过）。这样 §3 的「内存 vs 磁盘 memcmp」读到的是干净视图，抓不到。libtersafe 用 pagemap 从**物理层**穿透这一招。

**证据（解密串）：**
| 串 | 密文@ | 作用 |
|---|---|---|
| `pagemap` | `0x267054` | 打开 `/proc/self/pagemap` |
| `gp4_pagemap` | `0x266aa0` | pagemap 检测项主体 |
| `gp4_pagemap_wb` | `0x265068` | pagemap 检测开关/白名单（writeback） |
| `gp4_pagemap_ig` | `0x2664b8` | pagemap 忽略/例外列表（ignore） |
| `/proc/self/map_files` | `0x27d5bc` | 枚举实际文件背靠映射 |
| `/proc/self/maps` | `0x27d220` | 区间枚举 |

**检测函数链（逐指令佐证）：**
```text
0x266aa0  gp4_pagemap 主体
  ├─ decrypt("gp4_pagemap") 注册/取配置
  ├─ 0x2657b8  打开+映射 /proc/self/pagemap
  │      └─ mmap/read 页表项（每虚拟页 8 字节）
  ├─ 0x2671dc  逐页比对
  │      ├─ 取虚拟页 → pagemap 偏移 = (vaddr>>12)*8
  │      ├─ 读 8 字节 → 提取 PFN(bit0..54) / present(bit63)
  │      ├─ 0x2dad88 取 ctx（记录/守卫）
  │      └─ 0x4a4774 字节模式比较（配合内存视图）
  └─ 命中 → 计入 hook 结果上报
```

**判定逻辑（strong inference）：**
- 对同一可执行区间，比较「只读视图对应的物理帧」与「实际取指视图/期望帧」；两者 PFN 不一致 → 双重映射/影子页 hook。
- 也检查页的 present/swap 位与是否 file-backed（配 `/proc/self/map_files` 的 inode/路径），异常匿名可执行页即可疑。
- `gp4_pagemap_wb` / `gp4_pagemap_ig` 是云端可调的**开关 + 例外名单**（避免对系统合法双映射误报，如 `librknnhal_bridge`、ART JIT 等）。

**意义**：这正是针对「§3 mem-vs-disk 抓不到的影子页/物理层 hook」的补强——从页表物理帧号入手，`elf_hook_scan`(虚拟视图) + `gp4_pagemap`(物理帧) 双管齐下。

> 相关但不同：`dual_app` / `dual_uid_%d` / `dual_app_files` / `dual_uid_not_same`（`0x2679c0` 一带）是**多开/分身 App 检测**（比对 uid/文件），不是影子页；两者只是都用 `/proc/self/*` 且名字带 dual，注意区分。

---

## 5. `ts2_got` —— GOT / PLT 完整性

注册于 `0x25574c`，检测函数在 `0x255004` 一带，引用导入跳转表 `0x52dd30`：
- 遍历 GOT/PLT 条目（`ldr x8,[x26,w8,uxtw#3]` 按索引取表项）；
- 校验每个跳转目标是否落在**预期模块的合法地址范围**内；
- 目标被改写指向外部 trampoline（典型 PLT/GOT hook、`libhoudini`/`substrate` 重定向）即命中。

这是对付「不改 `.text`、只改导入表指针」那类 hook 的专门探测——`elf_hook_scan` 的 mem-vs-disk 对 GOT（`.data` 可写）不适用，故独立一条。

---

## 6. 命中结果组包 + 上报

命中项经 `sub_434F3C` 汇聚，按下列模板组包（键值 `|` 分隔），交 GetReportData v1-v4 → 宿主 `tss_sdk_send_data_to_svr` 回调上传：

```text
name=%s|feature=%s|cert_md5=%s|fake_cert=%d
name=%s|feature=%s|cert_crc=0X%08X|size=%u|install_t=%lu|is_custom=%d
name=%s|feature=%s|size=%d|mtime=%d|cert_md5_crc=0x%08x
cert_md5=%s|apk_hash_1=0x%08x|apk_hash_2=0x%08x|txt_seg_crc=0x%08x
```

`txt_seg_crc` 即 §3 代码段 CRC，服务端二次比对判 inline hook / .text patch。

---

## 7. 云端可下发的检测特征（feature_rcv）

hook 检测不是全写死，云端可通过 MRPCS 追加/更新特征（与 VMRPCS 同一下发通道）：

```text
func=feature_rcv_start|name=%s|crc=%d|size=%d
func=feature_rcv_append|feature_ptr=%s|buf=%s
func=feature_rcv_end|feature_ptr=%s|append_suc=%d
custom_feature_%d / custom_feature_cnt / cloud_feature.xml / feature_ptr
```

即：服务端下发一段带 `crc`/`size` 的特征块 → SDK 分片接收(`start/append/end`)、校验 CRC → 加入扫描项 → 供 `elf_hook_scan`/`opcode_scan` 等使用。这让新出现的 hook/作弊框架特征无需更新 so 即可热更。

---

## 8. 反调试 / 反注入邻接项（同一注册表）

hook 检测与下列同表注册、共用 `/proc/self/maps` 驱动与上报：
- **Frida**：`frida_scan`、`frida-agent-32/64.so`、`libfrida-gadget.so`、`frida-server`、`FRIDA_AGENT_1.0`、`pool-frida`
- **Hook 框架**：`libsubstrate`、`libsandhook.edxp.so`、`anti_substrate`、`anti_xposed`、`zygisk`、`libzygisk_loader.so`、`LuckyPatcher`(`com.dimonvideo.luckypatcher`)
- **调试**：`ptrace`、`Debug.isDebuggerConnected`、`/proc/self/status`、`/proc/self/maps`、`/proc/self/map_files`、`/proc/self/fd`
- **Root/模拟器/云手机/多开**：见 `FULL_REPORT.md` 反检测节

> 注：未发现 `perf_event_open` / 调试寄存器(`DBGBVR`) 字面串——即该 SDK **不直接扫硬件断点寄存器**；但硬件断点若配合任何 inline patch，仍会被 §3/§4 的代码段 CRC/opcode 扫描命中，且独立扫描线程不经被 hook 的入口。

---

## 9. 关键地址速查

| 地址 | 作用 |
|---|---|
| `sub_222228` | 扫描项注册（map 插入） |
| `0x27fcd0 / 0x28028c` | elf_hook_scan 等探测器注册点 |
| `0x280a4c / 0x280ef8 / 0x2679c0` | elf_hook_scan 相关扫描例程 |
| `sub_28DE4C @0x28de4c` | ★ 代码段 mem-vs-disk 逐页 diff（inline hook 主检测） |
| `sub_48924C` | crc32_cont（内存页 CRC 续算） |
| `sub_4A4658` | memcmp 内存页 vs 磁盘页 |
| `sub_4A4774` | 字节模式比较原语 |
| `sub_28E2E4` | bin_patch/skip 登记 |
| `sub_28E490` | 篡改页上报组包 |
| `0x28e558` | opcode_scan 注册/入口 |
| `0x266aa0 / 0x2657b8 / 0x2671dc` | ★ gp4_pagemap 影子页检测（读 `/proc/self/pagemap` PFN 比对） |
| `0x255004 / 0x25574c` | ts2_got GOT/PLT 校验（表 `0x52dd30`） |
| `sub_3E06D0` | `/proc/self/maps` 扫描驱动 |
| `sub_434F3C` | 命中派发/上报 |
| `0x50ae74` | dl_iterate_phdr 调用者 |
| `ctx+0x84` | txt_seg_crc 结果 |
| `ctx+0x3ac` | 校验守卫标志 |

---

## 10. 置信度说明

- **Confirmed**：注册表结构、各检测项名与解密 stub、`sub_28DE4C` 逐页 mem-vs-disk diff、`sub_4A4774` 字节比较、`/proc/self/maps` 驱动、上报模板、feature_rcv 下发协议。
- **Strong inference**：`ts2_got` 为 GOT/PLT 目标范围校验（据表 `0x52dd30` 索引访问 + 名称语义）；`opcode_scan` 具体操作码集合（据名称 + 邻接 crash 诱饵）。
- **Unconfirmed**：`opcode_scan` 匹配的确切操作码位模式、`ts2_got` 合法范围表的完整字段、每个云端 `feature` 二进制 schema——需运行时 dump 或更多样本。
