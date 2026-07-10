# libtersafe.so 完整逆向分析报告（合订本）

> 目标文件: `dfenxiwanjianlibtersafe.so`
> 类型: 腾讯 ACE（Anti-Cheat Expert）/ TP（TenProtect）mobile 反外挂 SDK 核心 native 库
> 本文汇总本次全部逆向内容：识别 → ELF 结构 → 导出 API → 内置组件 → 字符串加密与解密 → 反检测能力 → MRPCS 与服务器 → 日志 → 防篡改(CRC/Hash/证书) → CRC 变体 → JNI → 附录/关键地址速查。

---

## 0. 摘要（TL;DR）

`libtersafe.so` 是**腾讯 ACE/TP 移动反外挂 SDK v7.7.049.57576**（GCloud 集成），本包用于游戏 **三角洲行动（`com.tencent.tmgp.dfm`）**。它：

1. 对外暴露 **70 个导出函数**（TSS SDK / tss_sdk_* / tp2_* 兼容层 / JNI）。
2. 内置**自研内存虚拟机 MVM/AVM**，解释执行**云端下发的字节码扫描脚本**（外挂特征不硬编码，云端可热更）。
3. 反 **Frida / Root / Xposed·Substrate·Zygisk / 模拟器 / 云手机 / 多开 / 调试(ptrace)**。
4. 所有敏感字符串用**“每串独立解密 stub + 变常量 XOR 流”**加密——本次已用 Unicorn **批量解密 2085 条**。
5. **MRPCS** 子模块负责“云端规则**下载 → VM 扫描 → 加密上报**”闭环，服务器域名 `*.anticheatexpert.com` + 十余个 IP 兜底。
6. **防篡改**三合一：代码段 CRC 自校验 + APK/文件 CRC + 证书 MD5/SHA-256 比对，结果打包上报服务端。

---

## 1. 文件识别与基本信息

| 项 | 值 |
|---|---|
| SONAME | `libtersafe.so` |
| 架构 | ELF64 **AArch64 (ARM64)**，DYN 共享库，已 strip |
| 大小 | 5,598,144 字节 (5.3 MB) |
| GNU BuildID(SHA1) | `d70d7926094ae39a46745c12ddcc1877641f82e8` |
| 依赖(NEEDED) | `liblog.so`, `libc.so`, `libm.so`, `libdl.so` |
| 版本串 | `GCLOUD_VERSION_TP_7.7.049.57576`（GCloud 集成，TP 7.7.049） |
| 编译路径残留 | `/Users/bkdevops/tpmobile/workspace/p-c5c18c.../china/mvm/source/VM/Memory/BopMemoryOperation.cpp` |

编译路径含义：`bkdevops`=腾讯蓝盾 CI；`tpmobile`=TP 移动端；`china`=国内版；`mvm`=内置 mini-VM。

**目标/白名单游戏包名**（内置）：`com.tencent.tmgp.dfm` / `com.proxima.dfm`（三角洲行动，反外挂包 `ano_dfh.zip` 的 `dfh`），以及 `pubgmhd`(和平精英)、`sgame`(王者荣耀)、`cf`(穿越火线)、`dnf` 等。

---

## 2. ELF 段布局（vaddr == file offset，1:1 映射）

| 段 | VA | 大小 | 说明 |
|---|---|---|---|
| `.rodata` | `0x90ec0` | `0x7b274` | 只读数据；含加密字符串池、CRC/zlib 表、libjpeg/密码学常量 |
| `.text` | `0x1b6af0` | `0x3574b0` | 全部代码（反汇编 875,820 条指令） |
| `.plt` | `0x50dfa0` | `0xf90` | 导入桩（`__android_log_print`@`0x50eaf0` 等） |
| `.data.rel.ro` | `0x512f30` | `0x8f88` | 需重定位常量 |
| `.fini_array` | `0x51beb8` | `0x10` | 2 个析构 |
| `.init_array` | `0x51bec8` | `0x200` | **64 个构造函数**（加载即跑，布置反调试/初始化） |
| `.got/.got.plt` | `0x51c2b8` | — | 全局偏移表 |
| `.data` | `0x521500` | `0x3cea0` | 可写数据 |
| `.bss` | `0x55e3a0` | `0x1a458` | 零初始化；**字符串解密输出缓冲 @`0x568fc4`** |

加密字符串数据池 **DATA @ `0xfbbb0`**（`.rodata` 内）。

---

## 3. 导出接口（70 个，版本符号 `@@TERSAFE`）

**TSS SDK（Java/C++ 新 API）**
```
TssSDKInit 0x1cc398   TssSDKInitEx 0x1cc964   TssSDKSetUserInfo 0x1ccce8
TssSDKSetUserInfoWithLicense 0x1cd07c   TssSDKOnPause 0x1cd904   TssSDKOnResume 0x1cdd28
TssSDKIoctl 0x1cf91c   TssSDKIoctlOld 0x1cf4e0   TssSDKFree 0x1cfcc8
TssSDKGetReportData 0x1ce214  /2 0x1d01ac  /3 0x1d0218  /4 0x1d0674
TssSDKDelReportData 0x1ce780  /3 0x1d0284  /4 0x1d0c2c
TssSDKOnRecvData 0x1cec70   TssSDKOnRecvSignature 0x1d101c
TssSDKRegistInfoListener 0x1d19e8   TssSDKForExport 0x1d1e94   GetTssExportFunc2 0x1d3220
```
**tss_sdk_*（内部 C API）**
```
tss_sdk_init 0x1bf3a0   tss_sdk_ioctl 0x1bce54
tss_sdk_encryptpacket 0x1b9c24   tss_sdk_decryptpacket 0x1b9fa4   tss_sdk_ischeatpacket 0x1b8fb0
tss_sdk_setgamestatus 0x1bb144   tss_sdk_setuserinfo(_ex/_with_license)
tss_sdk_gen_session_data 0x1c44f8   tss_sdk_set_token 0x1c4000   tss_sdk_wait_verify 0x1c4aac
tss_sdk_rcv_anti_data 0x1ba324   tss_sdk_dec_tss_info 0x1c1058   tss_recv_sec_signature 0x1c5dfc
tss_get_report_data 0x1b9660 /2 0x1bece0 /3 0x1c4b20 /4 0x1c5474   tss_del_report_data(*)
tss_enable_get_report_data 0x1b8ee8   tss_log_str 0x1b9908   tss_unity_str 0x1b7564
```
**tp2_*（TP2 兼容层）**
```
tp2_sdk_init 0x1c1498  /_ex 0x1c1aa0   tp2_sdk_ioctl 0x1c000c   tp2_getver 0x1c2550
tp2_setoptions 0x1c29e4   tp2_setgamestatus 0x1c311c   tp2_setuserinfo(withlicense)
tp2_regist_tss_info_receiver 0x1c3a84   tp2_dec_tss_info 0x1c3f70   tp2_free_anti_data 0x1c0fcc
```
**数值“加固”辅助（反内存改数值）**
```
tss_sdt_float2uint / double2uint64 / uint2float / uint642double
```
**JNI / C++**
```
JNI_OnLoad 0x1d62c4   tss_jni_cmd 0x2d0d58   TssJavaMethod_SendCmd 0x2d0d7c
TssSdk::gen_random/gen_random2/sdt_report_error   tp2::gen_random
```
导出对象 `g_AllTssExportFunc`（函数表，`GetTssExportFunc2` 返回）。

---

## 4. 内置组件（静态链接进来的“大件”）

- **MVM / AVM —— 自研内存虚拟机**：`AVM::BopMemoryOperation::PmemRead/PmemWrite(paddr_t,…)`、`mvm_bk_proc`、`mvm_bk_task`。执行**云端下发的字节码扫描脚本**（`Scan script`、`Invalid scan script at entry %d`、`wild scan`、`ScanCast`、`ms_scan_start`）——外挂特征以脚本下发、VM 内解释执行，规则可热更、不落硬编码。
- **inline-hook 引擎**：`ms_hook_opcode`、`ms_set_inlie_hook`、`set_inline_hook_error`、`inline_hook_opcode_dismatch`、`elf_hook_scan`、`opcode_scan`。
- **zlib ×3**（见 §10）：解压下发的 `.zip` 规则包 / `tpup*.zip` / `.so`·`.dex` 更新。
- **libjpeg**：大量 JPEG/量化表字符串（截图取证/图像处理）。
- **libunwind**：`.eh_frame` 展开、`scan_eh_tab`（崩溃/栈回溯）。
- **TinyXML**：`TiXmlDocument`（配置解析）。
- **密码学**：MD5/SHA1 家族 IV `0x67452301/0xefcdab89`@`0x99d20`、SHA-256 IV `0x6a09e667`@`0x9a1a0`（证书/签名校验）。

---

## 5. 字符串加密算法（完全逆向 + 可解密）

所有敏感字符串（服务器地址、检测特征、类名、日志）加密存放在只读池 **DATA @ `0xfbbb0`**，运行时按 offset 解密并缓存到 **.bss @ `0x568fc4`**。

- 每串一个**独立解密 stub**（全库 **101 个**），签名一致：`bl 0x4e4a30`(取 DATA 基址) + `bl 0x4e4a44`(取输出缓冲基址 `0x568fc4`)，差异仅一个**每串常量**（w15，如 `0x29/0x5b/0x45…`）。
- 调用形式：`mov w0,#<offset>; bl <stub>` → 返回解密后的 C 字符串。
- 等价算法：
  ```python
  key    = DATA[off]                    # 运行密钥种子
  length = DATA[off+1] ^ key
  for i in range(length):
      plain[i] = DATA[off+2+i] ^ (key & 0xff)
      key = ((key + i) ^ CONST) + 1     # CONST = 每串常量(w15)
  # 末尾另有基于 0xff 的校验/终止处理
  ```

**解密工具链**（本仓 `*.py`）：Capstone 全 `.text` 反汇编 → 识别 101 个 stub 与 3192 处调用点 → 提取 `(stub, imm)` 对 → **Unicorn** 加载镜像逐个调用 → 读 `0x568fc4` 得明文。共得 **2085 条**（去重 2059）。见 `decrypted.txt`、`decrypted_strings_sorted.txt`。

抽样验证：`0x4e9270(0x3ea9)`→`builtin_emu`、`0x4eca98(0xe4df)`→`builtin_ourplay`、`0x4eb1d8(0x3e61)`→`BlueStacksX86`、`0x4e65b0(0x3e81)`→`Win11X86`。

---

## 6. 反外挂 / 反调试 / 反环境检测能力

- **反 Frida**：`frida_scan`、`anti_frida`、`libfrida-gadget.so`、`frida-agent-32/64.so`、`frida_agent_main`、`FRIDA_AGENT_1.0`、`pool-frida`、`/data/local/tmp/re.frida.server`、`/system/bin/frida-server`、拆分混淆 `/data/local/tmp/12re.34frida.56server78`。
- **反 Root / Hook 框架**：`anti_root`、`gp4_no_root`、`mem_trap_no_root`、`is_root`、`unlock_root`、`root_process_exists`、`libsandhook.edxp.so`、`/system/lib(64)/libzygisk_loader.so`、`/system/etc/init.d/99SuperSUDaemon`、`/system/usr/we-need-root`；root 应用包 `com.kingroot.kinguser`、`com.kingo.root`、`com.speedsoftware.rootexplorer`、`com.alephzain.framaroot` 等。
- **反模拟器**：`IsEmulator2`、`ScanEmulator`、`antiemulator`、`builtin_emu`、`builtin_ourplay`、`BlueStacksX86`、`Win11X86`、`emu_crash/emu_crash_all/emu_tp/emu_white/force_emu_scan`。
- **反云手机**：`init.svc.cloudAppEngine`、`/vendor/bin/CloudAppEngine`、`ro.vendor.platform: cloudmatrix1/2/3`、`ro.com.cph.non_root`、`init.rockchip.rc`、`ro.vendor.rk_sdk`。
- **反调试**：`ptrace`、`android/os/Debug.isDebuggerConnected`、`android:debuggable`、`/proc/%u/status`、`/proc/%u/cmdline`、`/proc/self/root/proc/self/fd`、`/proc/%d/task`、inotify(`anti_inot_failed`)。
- **反多开/虚拟框架**：`ScanVirApp`、`IsVAP=%d|VAPName=%s|`、`dual_uid_%d`、`Fake_%s`、`pj.ishuaji.cheat`、`com.saitesoft.gamecheater`、`com.kascend.chushou.lu`。
- **签名/证书 & 应用清单**：`ScanCert`、`GET_SIGNATURES`、`cert_md5`/`official_cert_md5`/`fake_cert`、`MB_EnumApkOpen/Close`、`report_apk`。
- **触摸/自动点击**：`RecordTouchStart`、`start_anti_auto_clicker2`、`com/tencent/tp/TouchListenerProxy`。
- 汇总上报：`IsRoot=%d|RootReason=%s|IsNeedReqApkList=%d|`、`IsEmu=%d|EmuName=%s|`、`root=%d|x86=%d|apk_cnt=%d|adb=%d|machine=%s|sys_ver=%s|root_record=%d`。

---

## 7. MRPCS 模块与服务器地址（“解密地址 mrpcs”）

### 7.1 MRPCS 是什么
日志 tag `MRPCS_ANDROID`。负责**云端反外挂数据/扫描脚本的下载—扫描—上报**闭环，三线程：
- `mrpcs_download_data_thread`（下载）
- `mrpcs_scan_thread`（扫描，跑在 §4 的 MVM 里）
- `mrpcs_send_data_thread`（上报）
- 校验：`mrpcs_data_crc_error`、`mrpcs_data_len_error`、`mrpcs_single_data_not_match`、`mrpcs_common_data_not_match`。
- JNI 桥接：`OpenMrpcsBridge` / `MrpcsBridgeCmd` / `CloseMrpcsBridge`。

### 7.2 服务器地址（解密结果）
**下载 / CDN：** `down.anticheatexpert.com`（主）、`dl.putdl.com`、`dl.timedl.com`（备）
**完整 URL 样例：**
```
https://down.anticheatexpert.com/iedsafe/Client/android/8899/71C1E6D7/donot_delete_me
```
**URL 模板：** `%s://%s/iedsafe/Client/%s`、`https://%s/gamesafe/mobile/%s/%08X`、包名 `gamesafe/mobile/ano_dfh.zip`
**通信/频道服务器（cs_host）：**
`nj.cschannel.anticheatexpert.com`、`tyf.cschannel.anticheatexpert.com`、`acekeeper.anticheatexpert.com`
**IP 直连兜底：** `180.109.156.92`、`36.155.240.19`、`153.3.50.229`、`119.45.69.203`、`14.22.9.201`、`120.232.27.62`、`157.148.45.163`、`106.55.209.88`、`139.186.105.110/225/126/94`、`42.81.179.246`、`111.30.185.235`、`220.194.120.73`、`109.244.170.205`
**本地/回环：** `127.0.0.1`、`10.0.2.2`(模拟器网关)、网关探测 `8.8.8.8 via %s dev`。

### 7.3 上报协议（WB_Sync 系列）
```
func=WB_SyncGs2Host|game_id=%d|cdn_host=%s|cs_host=%s|cs_ip=
func=WB_SyncOpenID|open_id=%s|game_id=%d|locale=%d
func=WB_HeartBeat|index=%d|md5=%s|uid=%d
func=init_sdk|game_id=%u      func=set_user_info|entry_id=%d|open_id=%s
WB_GetReportStr / WB_SyncOpenIDEx
```
配置键：`cdn_host`、`game_host`、`is_update_cdn_ok`、`CDNHost:`、`SetChannelHost:`。

---

## 8. 日志系统

- 日志 TAG 唯一：**`"ACE"`**（模块内部另用 `MRPCS_ANDROID`）。
- 中央日志函数 **`0x4e6390`** → `__android_log_print(prio,"ACE","%s",msg)`（PLT `0x50eaf0`）。全库**仅 1 处**直接调 `__android_log_print`；各模块先把消息格式化好再传入。
- 全部可输出的日志/诊断串（明文 + 解密）见 `tersafe_logs.txt`（754 行），含 MRPCS 报错、扫描/检测消息、上报协议、libjpeg/libunwind/TinyXML 报错、pthread/文件 IO、TssSDK 接口名等。

---

## 9. 防篡改：完整性校验（CRC / Hash / 证书）

**三合一**，结果打包上报服务端二次核验：

1. **代码段自校验 `txt_seg_crc`**：对内存中自身 `.text` 段做 CRC32，存于结构体偏移 `+0x84`，抓 inline-hook / 内存改码。配套 `elf_hook_scan / opcode_scan / ScanOpcode / inline_hook_opcode_dismatch`。
2. **APK/文件校验**：`crc32_file`（4KB 分块 + size + mtime）校验 APK 本体、`inner_apk`、自身 so；判定 `apk_crc_eq/not_eq`、`inner_apk_crc_eq/not_eq`、`file_crc_eq/eq2/not_eq2`；本地缓存 `cache_crc.dat`。
3. **证书 MD5/SHA-256**：`cal_cert_md5` 对签名证书算 MD5，与内置 `official_cert_md5` 比对，不符置 `fake_cert=1`，抓重签名/盗版；`CertHash=%s|DST=%04x|PkgNamesCnt=%d|PkgNames=%s|`。

汇总上报串（组装于 `0x4cbd7c`）：
```
cert_md5=%s|apk_hash_1=0x%08x|apk_hash_2=0x%08x|txt_seg_crc=0x%08x
name=%s|size=%d|crc=0x%08x|mark=0x%08x
name=%s|feature=%s|size=%d|mtime=%d|cert_md5_crc=0x%08x
```
下发规则本身也带 CRC：`dl custom, name:%s, len:%d, crc:%08x, channel:%d`、`func=feature_rcv_start|name=%s|crc=%d|size=%d`，不符 `mrpcs_data_crc_error` 丢弃（防中间人篡改）。

---

## 10. CRC 变体：其实只有一个多项式

`.rodata` 有 4 处命中 CRC32 表签名，但**多项式统一为 `0xEDB88320`（标准 zlib CRC-32）**，区别只是存储形态与用途：

| 名称 | 表起始 | 宽度 | 类型 | 用途 |
|---|---|---|---|---|
| **T3** | `0xe2158` | u32 | 经典 `crc_table[256]`（`t[128]=0xEDB88320`） | **反篡改自用** |
| **T0** | `0xdc1c0` | u64 | zlib **braid** 表（值零扩展到 64 位） | 静态 zlib #1（解压） |
| **T1** | `0xdfeb8` | u64 | 同上 | 静态 zlib #2 |
| **T2** | `0xe1958` | u64 | 同上 | 静态 zlib #3 |

- T0/T1/T2 旁边紧跟的代码是 zlib `fixedtables()`（写回固定 Huffman 表 `lenfix=0xdc9c0`/`distfix=0xdd9c0`、`lenbits=9/distbits=5`）→ 确定是**解压**（解 MRPCS 下发 zip、tpup、so/dex 更新），非校验。
- 反篡改 CRC（T3）有 3 个入口变体，共享表 getter `0x489204`：
  - `crc32(buf,len)` **`0x489210`**：init `0xFFFFFFFF`，`crc=table[(crc^b)&0xff]^(crc>>8)`，末尾 `~`。
  - `crc32_cont(buf,len,seed)` **`0x48924c`**：无 init/无收尾，续算。
  - `crc32_file(path,*out,limit,k)` **`0x489288`**：`fopen("rb")` + 4KB 分块续算 + 末尾 `~`。核心 `0x489210` 被 200+ 处调用。
- 全库**无第二种 CRC 多项式，无 CRC-16**；证书/签名另用 **MD5 + SHA-256**。

---

## 11. JNI / Java 层交互

`JNI_OnLoad @ 0x1d62c4`；`.init_array` 64 个构造函数在加载时布置初始化/反调试。Java 侧类（解密自 native）：
- `com/tencent/tp/TssJavaMethod`、`com/tencent/tp/MainThreadDispatcher2`
- `com/tencent/tp/TouchListenerProxy`（触摸事件监控，反自动点击/宏）
- `com/tencent/gcloud/plugin/PluginUtils`
- 反射用：`android/app/ActivityThread`、`currentActivityThread`、`getClassLoader`、`dalvik.system.PathClassLoader`、`java/security/Signature`、`[Landroid/content/pm/Signature;`。

---

## 12. 关键地址速查

| 地址 | 作用 |
|---|---|
| `0x4e4a30` / `0x4e4a44` | 字符串解密公共子函数（取 DATA 基址 / 取输出缓冲） |
| `0x568fc4` | 解密输出缓冲(.bss) |
| `0xfbbb0` | 加密字符串数据池 DATA |
| `0x4e6390` | 中央日志函数 → `__android_log_print(_,"ACE","%s",_)` |
| `0x50eaf0` | `__android_log_print` PLT 桩 |
| `0x489204/0x489210/0x48924c/0x489288` | 反篡改 CRC 表getter/一次性/续算/文件 |
| `0xe2158` | 反篡改 CRC32 表（poly 0xEDB88320） |
| `0xdc1c0 / 0xdfeb8 / 0xe1958` | 3 份 zlib braid CRC 表（解压用） |
| `0x4cbd7c` | 组装 `cert_md5|apk_hash_1|apk_hash_2|txt_seg_crc` 上报 |
| `0x2db758` | APK 哈希 getter |
| `0x1d62c4` | `JNI_OnLoad` |
| 结构体 `+0x84` | 代码段自校验值 `txt_seg_crc` |

---

## 13. 观测/取证用 Hook 点（仅供分析，不用于对抗检测）

- **拿全部明文**：hook 解密子函数 `0x4e4a30`/`0x4e4a44` 返回处或读 `0x568fc4`。
- **拿全部日志**：hook 中央日志 `0x4e6390` 的 `msg` 入参。
- **抓上报明文**：hook `TssSDKGetReportData*`（`0x1ce214`/`0x1d01ac`）、`TssSDKOnRecvData 0x1cec70`、`TssSDKOnRecvSignature 0x1d101c`。
- **总入口**：`JNI_OnLoad 0x1d62c4`、`TssSDKInit 0x1cc398`。

> 注：本库自身具备反 hook / 反调试 / 代码段 CRC 自校验，上述仅用于在**自有离线环境**做行为分析/取证；不提供任何绕过或致盲其检测的方法。

---

## 14. 一句话总结

`libtersafe.so` = 腾讯 ACE/TP 7.7 反外挂 SDK（本包用于三角洲行动）：内置 mini-VM 跑云端下发的扫描脚本，配套 inline-hook、反调试/反 Frida/反 Root/反模拟器/反云手机/反多开；敏感字符串用“每串独立 stub + 变常量 XOR 流”加密（已解密 2085 条）；**MRPCS** 模块完成“云端规则下载→VM 扫描→加密上报”闭环，服务器为 `*.anticheatexpert.com`（下载 `down.`、频道 `*.cschannel.`、`acekeeper.`）+ 十余个 IP 兜底；防篡改由代码段 CRC 自校验 + APK/文件 CRC(zlib CRC-32) + 证书 MD5/SHA-256 组成，全部上报服务端核验。

---

## 附录 A：随附文件
- `FULL_REPORT.md`（本文，合订本）
- `tersafe_analysis.md`（原始分析）
- `tersafe_logs.txt`（754 行日志/诊断串）
- `anti_tamper_crc.md`（防篡改专题）
- `crc_variants.md`（CRC 变体专题）
- `decrypted.txt`（2085 条解密串，带 callsite/stub/id）
- `decrypted_strings_sorted.txt`（2059 条去重排序）
