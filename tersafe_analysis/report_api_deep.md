# 上报数据接口 `GetReportData` v1/v2/v3/v4 深度逆向

目标库：`libtersafe.so`（腾讯 ACE / TP `GCLOUD_VERSION_TP_7.7.049.57576`，ARM64，`com.tencent.tmgp.dfm`）
分析边界：纯静态逆向 / 取证，理解上报数据接口的结构与版本差异。不提供任何绕过、致盲或篡改方法。

---

## 0. 一句话结论

`TssSDKGetReportData` 有 **4 个并行版本（v1 / v2 / v3 / v4）**。每个版本都是「**公开薄壳 `TssSDKGetReportDataN` → 转发到内部实现 `tss_get_report_dataN` → 通过中央 `tss_sdk_ioctl(cmd,…)` 用不同命令号取一块【已打包/加密的待上报数据】**」。版本差异 = **ioctl 命令号与步骤数不同**（协议演进）：v1 走旧的直接缓冲区，v2 单命令，v3 三命令组合，v4 双命令。所有函数都被**控制流平坦化 + 不透明谓词 + 常量混淆**保护。

---

## 1. 导出清单（来自 `.dynsym`，`@@TERSAFE`）

| 版本 | 公开 API（TssSDK*） | 大小 | 内部实现（tss_*） | 大小 |
|---|---|---|---|---|
| v1 | `TssSDKGetReportData` `0x1ce214` / `TssSDKDelReportData` `0x1ce780` | 1388/1264 | `tss_get_report_data` `0x1b9660` / `tss_del_report_data` `0x1b8dd8` | 680/272 |
| v2 | `TssSDKGetReportData2` `0x1d01ac` | 108 | `tss_get_report_data2` `0x1bece0` | 1524 |
| v3 | `TssSDKGetReportData3` `0x1d0218` / `TssSDKDelReportData3` `0x1d0284` | 108/1008 | `tss_get_report_data3` `0x1c4b20` / `tss_del_report_data3` `0x1c53e0` | 2240/148 |
| v4 | `TssSDKGetReportData4` `0x1d0674` / `TssSDKDelReportData4` `0x1d0c2c` | 1464/1008 | `tss_get_report_data4` `0x1c5474` / `tss_del_report_data4` `0x1c584c` | 984/1456 |

配套：`tss_enable_get_report_data 0x1b8ee8`（总开关）、`TssSDKOnRecvData 0x1cec70`、`TssSDKOnRecvSignature 0x1d101c`。
调试残留串：`hello getreportdata3`（`0x92dec`）——佐证 v3 是开发期重点扩展的一版。

---

## 2. 两层转发结构

**公开壳 → 内部实现**（经 PLT/GOT 跳转，已核对重定位）：
- `TssSDKGetReportData2 (0x1d01ac)` → PLT `0x50e0e0` → GOT `0x51cd18` → **`tss_get_report_data2 (0x1bece0)`**
- `TssSDKGetReportData3 (0x1d0218)` → PLT `0x50e1f0` → GOT `0x51cda0` → **`tss_get_report_data3 (0x1c4b20)`**
- v1/v4 公开壳同理转发到 `tss_get_report_data`/`tss_get_report_data4`（GOT `0x51ccb8` / `0x51cdb0`）。

公开壳里那一堆 `mov/movk/cmp/csel` 是**不透明谓词垃圾代码**（恒真/恒假分支 + 查表 `br x8`），实际只做一次尾调转发。

**内部实现 → 中央 ioctl**：内部 `tss_get_report_dataN` 通过 PLT `0x50e090` 调 **`tss_sdk_ioctl (0x1bce54)`**（其下层再落到 `tp2_sdk_ioctl 0x1c000c`）。`tss_sdk_ioctl` 从全局句柄表 `0x55e8e0` 取已注册的处理器对象，虚调其 `+0x18` 方法完成命令分发。即上报数据的存取是**以 ioctl 命令实现**的。

---

## 3. 各版本 ioctl 命令号（逐指令确认）

| 内部函数 | tss_sdk_ioctl 命令序列 | 说明 |
|---|---|---|
| `tss_get_report_data` (v1) | **无直接 ioctl** | 旧路径：经 `0x1f80ac` 读全局缓冲区 `0x55eb10`/`0x55eb00`，直接取本地上报队列 |
| `tss_get_report_data2` (v2) | `cmd=1` | 单命令；先在全局 `0x55e842/0x55e84a` 布置参数块，`arg3=0x84` |
| `tss_get_report_data3` (v3) | `cmd=0x67, 0x32, 0x25` | **三步**组合命令（协议最全的一版） |
| `tss_get_report_data4` (v4) | `cmd=0x6a, 0x3b` | 双命令 |
| `tss_del_report_data4` (v4) | `cmd=0x3c` | 删除对应上报项 |

调用约定（从寄存器布置看）：`tss_sdk_ioctl(w0=cmd, x1=in, x2=out, w3=flag/len, x4=extra)`。例如 v2：
```asm
mov  w0, #1            ; cmd
mov  x1, xzr           ; in = NULL
add  x2, x8, #0x84a    ; out 指向全局参数块
mov  w3, #0x84         ; flag/len = 0x84
ldur x4, [x29,#-0x18]  ; extra = 输出指针
bl   tss_sdk_ioctl
```

**版本差异本质**：不是算法完全不同，而是**同一 ioctl 通道上的不同命令号/步骤数**——协议随 SDK 迭代新增字段与步骤（v1 旧缓冲区 → v2 单命令 → v3 三步 → v4 双命令 + 独立 del）。

---

## 4. 公共辅助（内部实现共用）

- `0x4e56d8`：报文/缓冲构造器（`sub 0x120` 大栈 + `stp q0,q1` SIMD 批量写），把字段拼进输出缓冲。
- `0x4e5ed8`：逐字节 `cmp #0x7f` 的字符串校验/编码（ASCII/UTF-8 合法性或长度探测）。
- `0x4e524c`：懒加载单例（guard `0x577c88`），提供上报所需的共享对象。
- v1 专用 `0x1f80ac`：全局上报缓冲区 `0x55eb00/0x55eb10` 的懒初始化 getter。

结合前述分析，取到的数据是**已按 `func=WB_*|k=v|…` 组包并加密**的 blob（base64 表 `0xe265c`、MD5/SHA-256 IV `0x99d20`/`0x9a1a0`、默认对称 key `abcd1234`）。

---

## 5. 与整体上报闭环的关系

```
各扫描模块产出特征串 (IsRoot=..|IsEmu=..|cert_md5=..|txt_seg_crc=..|内存扫描命中)
        │  组包 func=WB_*|k=v|…  + base64 + MD5/SHA256 + 默认key abcd1234
        ▼
tss_get_report_dataN → tss_sdk_ioctl(cmd) → 句柄表 0x55e8e0 → 取【已加密待上报 blob】
        │  （宿主轮询公开 TssSDKGetReportDataN 取走）
        ▼
宿主注册的回调 tss_sdk_send_data_to_svr(%p) 上传到 cschannel 服务器
        ▼
服务端回 TssSDKOnRecvData / TssSDKOnRecvSignature（签名二次核验、防重放）
        ▼
TssSDKDelReportDataN(cmd 0x3c…) 确认后从队列删除
```

`tss_enable_get_report_data (0x1b8ee8)` 是这整条取数通道的开关。

---

## 6. 混淆特征（本身即结论）

上报接口是全库**混淆最重**的部分之一：
- **控制流平坦化**：用状态变量（如 v4 的 `w25`）经 `cmp/b.ge` 二叉树分发到各基本块，打乱线性顺序。
- **不透明谓词**：大量 `mov/movk`+`cmp`+`csel`/`b.ne` 恒定分支，制造假路径。
- **常量混淆**：命令号/索引常经 `movk`+`eor`+`csel` 计算得出，静态不易直读（但可复原，见 §3）。
- **间接跳转**：`ldr x8,[base, idx*8]; br x8` 查表跳转，隐藏真实控制流。

这解释了公开壳虽小却塞满垃圾指令、内部函数体积虚高的现象。

---

## 7. 解混淆：`tss_sdk_ioctl` 的最终调用落点

把 `tss_sdk_ioctl (0x1bce54)` 的控制流平坦化/不透明谓词剥掉后，真实逻辑只有三步：

```c
int tss_sdk_ioctl(int cmd, void* in, void* out, long flag, long extra) {
    ctx = sub_2dad88();                 // 取 TLS/全局上下文
    if (ctx[0x3ac] != 0) { /* 守卫早退（0x1bce88 那段 ldr/ret 是垃圾块） */ }

    // ① 有注册处理器 → 虚调
    h = *(void**)0x55e8e8;              // 注册的引擎对象
    if (*(void**)0x55e8e0 && (*h_vtbl_slot0x18) && h) {
        vtbl = *(void**)h;
        return (*(fn*)(vtbl + 0x18))(h, cmd, in, out, flag, extra);  // br x6
    }

    // ② 无注册处理器 → 内置跳转表兜底
    if ((unsigned)(cmd-1) <= 0x57) {                 // 仅 cmd∈[1,0x58]
        target = 0x1bcf48 + (int32)tbl_0x90ec0[cmd-1];
        goto *target;
    }
    goto default_0x1bd694;               // 越界 → 默认/空
}
```

**最终落点有两条：**

**(A) 注册引擎对象的虚函数 `vtable+0x18`（v3/v4 走这条）**
- 引擎对象在 `JNI_OnLoad` 初始化时创建（`0x1d45f0` 一带）：分配 **0x1538 字节**的 `TssSdk` 类对象（`0x4e8854`=分配器），存到全局 `[0x55e900]`，再注册进 `[0x55e8e8]`（store @`0x1d4934`）、`[0x55e8e0]`（store @`0x1d493c`）。类名由相邻符号 `_ZN6TssSdk16sdt_report_errorEv` 佐证 = **`TssSdk`**。
- ioctl 分发就是 `TssSdk::<vtable+0x18>(this, cmd, …)` 的虚调（`br x6`，尾调）。该虚槽在构造时绑定，**是所有 report/命令的真正总入口**。
- v3 的 `cmd=0x67(103)`、v4 的 `cmd=0x6a(106)` 都 **> 0x58**，不在内置表内 → **只能经这条虚调路径**处理。

**(B) 内置跳转表 `0x90ec0`（v1/v2 的 cmd 落这里，作为未注册时兜底）**
`target = 0x1bcf48 + (int32)*(0x90ec0 + (cmd-1)*4)`，已复原：

| cmd | 版本 | 处理块 | 该块内最终调用（部分） |
|---|---|---|---|
| `0x01` | v2 | `0x1bcf58` | `…→0x22d7c0`（取上报队列项） |
| `0x25` | v3 | `0x1bd1a4` | `0x4e8970 / 0x4a14cc / 0x4eaf98` |
| `0x3b` | v4 | `0x1bd33c` | `0x4c7120 / 0x4c73b0` |
| `0x3c` | v4-del | `0x1bd5a0` | `0x222e90 / 0x223d34` |
| `0x32` | v3 | `0x1bd694` | = 默认/空块（与越界同址） |

**结论**：GetReportData 全家的“最终调用”统一收敛到 **`TssSdk` 引擎单例（`[0x55e900]`/注册于 `[0x55e8e8]`）的 `vtable+0x18` 虚函数**；仅当该引擎未注册时，`cmd 1..0x58` 才回退到 `0x90ec0` 内置跳转表的对应块。混淆手法（平坦化 + 不透明谓词 + `movk/eor/csel` 常量计算 + `br` 查表）已全部剥离并复原命令号与落点。

---

## 8. 置信度 / 未决

- ioctl 命令号（1 / 0x67 / 0x32 / 0x25 / 0x6a / 0x3b / 0x3c）为**直接反汇编确认**。
- 各命令号对应的服务端语义（具体取哪张表/哪段队列）需 `tss_sdk_ioctl` 句柄表 `0x55e8e0` 的运行时对象或更多数据流跟踪才能定名。
- `abcd1234` 为硬编码默认 key（25 处解出）；真实会话 key 是否由初始化/服务端下发覆盖，需动态确认。
- 加密具体算法（AES/TEA/自研）被控制流平坦化掩盖，仅确认「默认 key + 查表分发的块加密 + base64/MD5/SHA256」。
