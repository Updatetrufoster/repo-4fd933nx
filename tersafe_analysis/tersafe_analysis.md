# libtersafe.so 深度逆向分析报告

文件: `dfenxiwanjianlibtersafe.so`
SHA1 BuildID: `d70d7926094ae39a46745c12ddcc1877641f82e8`
大小: 5,598,144 字节 (5.3 MB)

## 1. 基本结论

这是 **腾讯 ACE（Anti-Cheat Expert / 反外挂专家）移动端 SDK**，即腾讯 **TP（TenProtect）mobile** 的核心 native 库，SONAME = `libtersafe.so`。

- 架构: **ELF64 AArch64 (ARM64)**，动态库，已 strip。
- 依赖: `liblog.so`, `libc.so`, `libm.so`, `libdl.so`。
- 版本: 字符串 `GCLOUD_VERSION_TP_7.7.049.57576`（腾讯 GCloud 集成，TP 版本 7.7.049）。
- 编译路径（残留）: `/Users/bkdevops/tpmobile/workspace/p-c5c18c767fca4537af3d80bab10cc86d/china/mvm/source/VM/Memory/BopMemoryOperation.cpp`
  - `bkdevops` = 腾讯蓝盾 CI；`tpmobile` = TP 移动端；`china` = 国内版；`mvm` = 内置 mini-VM。
- 目标游戏（内置包名白名单，含当前游戏）: `com.tencent.tmgp.dfm` / `com.proxima.dfm`（**三角洲行动 Delta Force Mobile**，下载文件名 `ano_dfh.zip` 中的 `dfh` 即 Delta Force Hangzhou/行动），以及 `pubgmhd`(和平精英)、`sgame`(王者荣耀)、`cf`(穿越火线)、`dnf` 等。

## 2. 导出接口（70 个导出函数，版本号 @@TERSAFE）

分为几组 API：

- **TSS SDK（新 API）**: `TssSDKInit/InitEx`, `TssSDKSetUserInfo(WithLicense)`, `TssSDKIoctl`, `TssSDKGetReportData/2/3/4`, `TssSDKDelReportData*`, `TssSDKOnRecvData/Signature`, `TssSDKOnPause/OnResume`, `TssSDKRegistInfoListener`。
- **tss_sdk_*（内部 C API）**: `tss_sdk_init`, `tss_sdk_ioctl`, `tss_sdk_encryptpacket/decryptpacket`, `tss_sdk_ischeatpacket`, `tss_sdk_setgamestatus`, `tss_sdk_gen_session_data`, `tss_sdk_set_token`, `tss_recv_sec_signature` 等。
- **tp2_*（TP2 兼容层）**: `tp2_sdk_init(_ex)`, `tp2_sdk_ioctl`, `tp2_setoptions`, `tp2_setuserinfo(withlicense)`, `tp2_setgamestatus`, `tp2_getver`。
- **JNI**: `JNI_OnLoad`, `tss_jni_cmd`, `TssJavaMethod_SendCmd`。
- 数据/浮点混淆辅助: `tss_sdt_float2uint`, `tss_sdt_double2uint64` 等（反内存篡改的数值“加固”封装）。
- 导出对象: `g_AllTssExportFunc`（函数表，供 `GetTssExportFunc2` 返回）。

`JNI_OnLoad @ 0x1d62c4`。启动时通过 `.init_array`（64 个构造函数）运行大量初始化/反调试布置。

## 3. 内置组件（静态链接进来的“大件”）

- **MVM / AVM — 自研内存虚拟机**: `AVM::BopMemoryOperation::PmemRead/PmemWrite(paddr_t,...)`, `mvm_bk_proc`, `mvm_bk_task`。
  用于执行**云端下发的“扫描脚本”**（`Scan script`, `Invalid scan script at entry %d`, `wild scan`, `ScanCast`, `ms_scan_start`）——外挂特征以字节码脚本形式下发，在 VM 里解释执行，避免规则硬编码。
- **libjpeg**（大量 JPEG/量化表字符串）: 疑似用于截图取证 / 图像水印上报。
- **libunwind**（`.eh_frame` 展开、`scan_eh_tab`）: 崩溃/栈回溯。
- **TinyXML**（`TiXmlDocument`）: 配置解析。
- inline-hook 引擎: `ms_hook_opcode`, `ms_set_inlie_hook`, `set_inline_hook_error`, `inline_hook_opcode_dismatch`。

## 4. 反外挂 / 反调试 / 反环境检测能力（由字符串解密后确认）

- **反 Frida**: `frida_scan`, `anti_frida`, `libfrida-gadget.so`, `frida-agent-32/64.so`, `frida_agent_main`, `FRIDA_AGENT_1.0`, `/data/local/tmp/re.frida.server`, `/system/bin/frida-server`, `/data/local/tmp/12re.34frida.56server78`（拆分混淆）。
- **反 Root / Hook 框架**: `anti_root`, `gp4_no_root`, `mem_trap_no_root`, `libsubstrate`, `anti_substrate`, `anti_xposed`, `zygisk`, `com.speedsoftware.rootexplorer`。
- **反模拟器**: `IsEmulator2`, `ScanEmulator`, `antiemulator`, `BlueStacksX86`, `TencentX86`, `TencentAoYYB`, `Nox/NOX/nox_tp`, `Win11X86`, `builtin_emu`, `builtin_ourplay`, `vm_debug.img`。
- **反调试**: `ptrace`, `android/os/Debug.isDebuggerConnected`, `/proc/self/status`, `debugger=%s`, `/proc/self/maps`, `/proc/self/map_files`, `/proc/self/fd`, `/proc/%u/task/%u`, inotify 监控 (`/proc/sys/fs/inotify/*`)。
- **反多开/虚拟框架**: `name=com.xunrui.duokai_box|cls_name=...`, `com.app.hider.master.pro.cn`, `com.cph.*`（云手机/CPH 检测：`ro.com.cph.cloud_app_engine`, `ro.com.cph.mac_address` 等）。
- 上报: `IsRoot=%d|RootReason=%s|IsNeedReqApkList=%d|`, `report_apk`, `daemon_report`, `TotalMem:%d;FreeSpaceTDM:%d`。

## 5. 字符串加密算法（已完全逆向 + 可解密）

所有敏感字符串（服务器地址、检测特征、类名）都被加密，存放在只读数据池 **DATA @ 0xfbbb0**，运行时按 offset 解密并缓存到 **.bss @ 0x568fc4**。

- 每个字符串有一个**独立解密 stub**（本库共 101 个），签名一致：`bl 0x4e4a30`(取 DATA 基址) + `bl 0x4e4a44`(取输出缓冲基址 0x568fc4)，差异仅在于一个**每串常量**（如 `0x29 / 0x5b / 0x45 …`，寄存器 w15）。
- 调用形式: `mov w0,#<offset>; bl <stub>`，返回解密后的 C 字符串。
- 算法（等价 Python）:
  ```
  key = DATA[off]                 # 运行密钥种子
  length = DATA[off+1] ^ key
  for i in range(length):
      plain[i] = DATA[off+2+i] ^ (key & 0xff)
      key = ((key + i) ^ CONST) + 1     # CONST = 每串常量(w15)
  ```
  （末尾另有一段基于 0xff 的校验/终止处理。）

我用 **Unicorn 引擎**加载镜像、逐个调用 stub，成功批量解密 **2085 条**字符串（见附件 `decrypted.txt`）。

## 6. “解密地址 mrpcs” —— MRPCS 模块与其服务器地址

### 6.1 MRPCS 是什么
`MRPCS` 是本库的一个子模块（日志 tag `MRPCS_ANDROID`），负责**云端反外挂数据/扫描脚本的下载—扫描—上报**闭环，典型三线程：
- `mrpcs_download_data_thread`（下载）
- `mrpcs_scan_thread`（扫描，跑在上面的 MVM 里）
- `mrpcs_send_data_thread`（上报）
- 校验: `mrpcs_data_crc_error`, `mrpcs_data_len_error`, `mrpcs_single_data_not_match`, `mrpcs_common_data_not_match`。
- JNI 桥接命令: `OpenMrpcsBridge` / `MrpcsBridgeCmd` / `CloseMrpcsBridge`。
- 相关键名: `mrpcs`, `mrpcs1`, `mrpcs.data`, `down_mrpcs`（下载动作，位于函数 `0x4c69e0` 附近）。

### 6.2 MRPCS/ACE 使用的地址（解密结果）

**下载 / CDN 地址（mrpcs 下载数据用）:**
| 地址 | 说明 |
|---|---|
| `down.anticheatexpert.com` | 主下载 CDN |
| `dl.putdl.com` | 备用下载 CDN |
| `dl.timedl.com` | 备用下载 CDN |

**完整下载 URL（硬编码样例）:**
```
https://down.anticheatexpert.com/iedsafe/Client/android/8899/71C1E6D7/donot_delete_me
```
URL 模板:
```
%s://%s/iedsafe/Client/%s
https://%s/gamesafe/mobile/%s/%08X
gamesafe/mobile/ano_dfh.zip          # 三角洲行动的反外挂数据包
```

**通信 / 频道服务器（cs_host，`game_host` 列表）:**
| 域名/IP | |
|---|---|
| `nj.cschannel.anticheatexpert.com` | 频道服务器(南京) |
| `tyf.cschannel.anticheatexpert.com` | 频道服务器 |
| `acekeeper.anticheatexpert.com` | ACE keeper 服务 |
| IP 直连备份 | `180.109.156.92`, `36.155.240.19`, `153.3.50.229`, `119.45.69.203`, `14.22.9.201`, `120.232.27.62`, `157.148.45.163`, `106.55.209.88`, `139.186.105.110/225/126/94`, `42.81.179.246`, `111.30.185.235`, `220.194.120.73`, `109.244.170.205` |

**本地/回环相关:** `127.0.0.1`, `10.0.2.2`(模拟器网关), `172.16.x.x`；网关探测 `ip route get 8.8.8.8`。

### 6.3 上报协议（WB_Sync 系列）
```
func=WB_SyncGs2Host|game_id=%d|cdn_host=%s|cs_host=%s|cs_ip=
func=WB_SyncOpenID|open_id=%s|game_id=%d|locale=%d
func=WB_SyncOpenIDEx / WB_SyncWinIP / WB_GetTPShellVersion / WB_GetReportStr
```
配置键: `cdn_host`, `game_host`, `is_update_cdn_ok`, `CDNHost:`, `SetChannelHost:`。

## 7. JNI / Java 层交互
Java 侧类（解密自 native）:
- `com/tencent/tp/TssJavaMethod`
- `com/tencent/tp/MainThreadDispatcher2`
- `com/tencent/tp/TouchListenerProxy`（`()Lcom/tencent/tp/TouchListenerProxy;`，触摸事件监控，反自动点击/宏）
- `com/tencent/gcloud/plugin/PluginUtils`

## 8. 一句话总结
`libtersafe.so` = 腾讯 ACE/TP 7.7 反外挂 SDK（本包用于三角洲行动）。它内置一个 mini-VM 跑云端下发的扫描脚本，配套 inline-hook、反调试/反 Frida/反 Root/反模拟器/反多开，全部敏感字符串用“每串独立 stub + 变常量 XOR 流”加密。**MRPCS 模块**是其“云端规则下载→VM 扫描→加密上报”的核心，服务器域名为 `*.anticheatexpert.com`（下载 `down.anticheatexpert.com`、频道 `*.cschannel.anticheatexpert.com`、`acekeeper.anticheatexpert.com`），并附带十余个 IP 直连兜底。
