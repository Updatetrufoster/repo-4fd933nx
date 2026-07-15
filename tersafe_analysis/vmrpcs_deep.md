# VMRPCS 深度逆向专题报告

目标库：`libtersafe.so`（腾讯 ACE / TP TenProtect mobile SDK，`GCLOUD_VERSION_TP_7.7.049.57576`，ARM64，目标 `com.tencent.tmgp.dfm` 三角洲行动）
BuildID/SHA1：`d70d7926094ae39a46745c12ddcc1877641f82e8`

本报告是从 `FULL_REPORT.md` 第 15/16/17 节抽出、并补全的 VMRPCS 独立专题。所有结论均有逐指令反汇编佐证；对反编译器字节/字重叠导致的不确定处已标注。

分析边界：仅静态逆向 / 取证，用于理解该反外挂模块的工作原理。不提供任何绕过、致盲、无痕 hook、反检测规避或篡改方法。

---

## 0. 一句话结论

**VMRPCS 是 TP 云端反外挂“扫描规则/数据”的私有封装格式。** 客户端下载 `mrpcs.data` → CRC 去重 → zlib 解压 → 魔数/长度加扰验签 → `(⊕k1)+k2` 反混淆 + 校验和 → 按命令号把 common/single 规则集装入上下文 → 内存扫描器读 `/proc/self/maps` 对 `r-xp`(代码段)/`r--p`(只读段) 做特征扫描 → 命中加密上报。它就是“云端下发→本地内存扫描→加密上报”闭环里**下发数据的载体格式**，用来热更外挂特征，并以魔数+长度加扰+校验和+CRC 抵抗中间人篡改。

---

## 1. 名称与隐藏字符串

模块内部标识 `MRPCS_ANDROID`；日志 TAG 统一 `"ACE"`。三个用 XOR 0x18 隐藏的关键串（在扫描/解压代码里现算现用，不落明文池）：

| 地址 | 密文 | ⊕0x18 明文 | 用途 |
|---|---|---|---|
| `0x99132` | `mvbqhujh{k6\|yly` | `unzipmrpcs.data` | zlib 解压标签 |
| `0x911e6` | `7hjw{7k}t~7uyhk` | `/proc/self/maps` | 内存映射枚举 |
| `0x3e0834` imm `0x6860356a` | — | `r-xp` | 可执行段过滤 |
| `0x3e084c` imm `0x6835356a` | — | `r--p` | 只读段过滤 |

相关明文日志：`mrpcs_download_data_thread_start_failed!`、`mrpcs_scan_thread_start_failed!`、`mrpcs_send_data_thread_start_failed!`、`mrpcs_data_crc_error`、`mrpcs_data_len_error`、`mrpcs_data_mode_name_len_error`、`mrpcs_common_data_not_match!`、`mrpcs_single_data_not_match!`。

---

## 2. 服务器与下载

下载/CDN 主机：`down.anticheatexpert.com`、`dl.putdl.com`、`dl.timedl.com`
样例 URL：`https://down.anticheatexpert.com/iedsafe/Client/android/8899/71C1E6D7/donot_delete_me`
模板：`%s://%s/iedsafe/Client/%s`、`https://%s/gamesafe/mobile/%s/%08X`、包名 `gamesafe/mobile/ano_dfh.zip`
频道/上报：`nj.cschannel.anticheatexpert.com`、`tyf.cschannel.anticheatexpert.com`、`acekeeper.anticheatexpert.com`（另有十余个 IP 兜底）。

---

## 3. 顶层接收器 `sub_42A5D8`（收到一包数据后的完整分派）

原型：`sub_42A5D8(ctx a1, buf a2, len a3, flag a4)`，由下载/分发线程 `sub_42A700` 调用。

### 3.1 CRC 指纹 + 去重缓存
```c
a1[405] = 1;                       // 状态字段 ctx+0x654 = 1「接收/校验中」
sub_2E5F08(v30);                   // crc32lei 上下文一次性初始化(全局锁 0x5637f0 / 标志 0x563818)
v13 = crc32lei(v30, a2, a3);       // 对【原始入包】算标准 CRC32 → v13(指纹)
if (!(a4 & 1)) {                   // 非强制
    if (sub_3F63F4(cache, a2, a3, v13) & 1) {  // 同 CRC 已处理 → 命中
        sub_3F6104(cache, a2, a3);              // 刷新缓存
        return 0;                               // 丢弃，不重复扫描
    }
}
```
- `crc32lei` = 标准 zlib CRC32（表 `0xe2158`，poly `0xEDB88320`；见 §7）。
- `sub_3F63F4 / sub_3F6104`（单例取自 `sub_3F5280`）是**按 CRC 去重缓存**：CRC 既做完整性又做去重键。日志 `mrpcs_data_crc_error` 即源于此。

### 3.2 前置分派
```c
if (sub_429AA4(a1) & 1)            // 上下文已就绪
    sub_42AD54(a1, a2, a3, v13);   // 调解析子例程(见 §4)
lock(unk_566818);
if (sub_429714(a1, v13) & 1)       // 该 CRC 已是当前生效下发 → 早退
    { unlock; return v22; }
```
`sub_42AD54` 是被 `sub_42A5D8` **有条件调用**的子例程，并非独立入口。

### 3.3 四种互斥分支
```c
if (*a2 == 0x04034B50) {           // (A) ZIP 头 "PK\x03\x04"：先 zlib 解压
    v21 = 1; v20 = sub_42A338(a1, a2, &v29);
    if (!v20 || !v29) {            // 解压失败 → 建错误对象上报坏包
        sub_4191C0(v28, 250); sub_419518(v28, v13);
        (*(*factory + 16))(factory, v28);   // 工厂 0x41A0A4 + 虚调 vtable+0x10
        a1[405] = -1; return -1;
    }
    a1[405] = 2;                   // 状态 2「已解压」
}

// 重建 6 字节签名(需 len>=0xB)：key = buf[1]+buf[3]; sig[i] = buf[4+i] ^ key
if (*v20) {
    if ( sig[i] == ((len & 0xff) ^ "VMRPCS"[i]) for all i ) {   // (B) VMRPCS 专包
        unlock;
        a1[405] = 4;               // 状态 4「VMRPCS 专包」
        sub_42A0E8(a1, v20, v29);  // → 异步任务(见 §5)
        return 0;
    }
    // (C) 非 VMRPCS 普通包：反混淆 + 命令分派
    once_init(unk_564988);
    sub_3A2D18(v27);
    v15 = sub_3A2D38(v27, v20, v29);   // (⊕k1)+k2 反混淆 + 校验和(见 §4.2)
    if (v15) {
        a1[403] = 0; a1[404] = 0;
        lock(...+12);
        switch (*v15) {            // 命令类型 = 解析对象首字节
            case 1: v22 = sub_42B570(a1, v15); break;   // common 规则集
            case 3: v22 = sub_42B87C(a1, v15); break;   // ack / 心跳
            case 4: v22 = sub_42BAD0(a1, v15); break;   // single 规则集
        }
        a1[405] = 3;               // 状态 3「完成」
    }
}
else {                             // (D) 首字节 0 = 空/复位包
    sub_3F878C(v20, v29);
    sub_429D4C(a1); sub_429E94(a1); sub_429FDC(a1);   // 清空 3 个规则容器
    sub_42A174(a1);
    a1[405] = 3;
}
```

**关键区分**：`VMRPCS` 魔数是**一类专包**（→ `sub_42A0E8` 异步任务）；命令号 `1/3/4` 是**另一类（非 VMRPCS）包**解析后的 `*v15`。两者互斥。

### 3.4 状态机字段 `ctx+0x654`（反编译器里的 `a1[405]`）
| 值 | 含义 |
|---|---|
| `1` | 接收 / CRC 校验中 |
| `2` | 已 zlib 解压 |
| `4` | VMRPCS 专包（走异步任务） |
| `3` | 处理完成 |
| `-1` | 坏包（解压失败等） |

---

## 4. 解析子例程 `sub_42AD54` / 反混淆 `sub_3A2D38`

### 4.1 `sub_42AD54`
与 `sub_42A5D8` 的 (C) 分支同源：建流读魔数(`sub_3F88BC/3F8AF8`)，判 ZIP(`0x04034B50`)否则 `sub_42A338` 解压，重建 `VMRPCS` 签名，加全局锁 `unk_566818` 后 `sub_3A2D38` 解析并 `switch` 命令类型，遍历扫描项调 `sub_3E06D0`，命中 `sub_434F3C`，收尾释放。

### 4.2 `sub_3A2D38` payload 反混淆 + 校验和（逐指令 `0x3a2de8..`）
```c
magic  = *(u32*)buf;   // 头部期望校验值
k1     = buf[0];       // 异或 key1
k2     = buf[1];       // 加法 key2
payload = buf + 4;
plen    = len - 4;
for (i = 0; i < plen; ++i)
    payload[i] = (payload[i] ^ k1) + k2;   // 反混淆
chk = sub_2E6188(payload, plen);           // 校验和
if (chk == magic)
    parse_with_factory_and_virtual_method();   // 工厂 0x41A0A4 建容器 + 虚调 vtable+0x10
```
注意：反编译器对前 4 字节的 字节/字 解释存在重叠，`magic` 与 `k1/k2` 的精确关系若要更严谨需再对照原始 ARM64 load。`sub_2E6188` 已确认为校验原语，但确切算法名未最终确定。

### 4.3 VMRPCS 签名（逐指令确认）
```c
key = buf[1] + buf[3];
for (i = 0; i < 6; ++i)
    sig[i] = buf[4 + i] ^ key;
// 通过条件：sig[i] == ((len & 0xff) ^ "VMRPCS"[i])
// "VMRPCS" = 56 4D 52 50 43 53
```

---

## 5. VMRPCS 专包异步处理器 `sub_42A0E8` → `sub_2eb80c`

```c
sub_42A0E8(ctx, buf, len):
    if (!global_0x566850) global_0x566850 = sub_433a5c();   // 单例
    if (!ctx[0x658]) ctx[0x658] = sub_2eb80c(buf, len);     // 首次投递并置位
    else             sub_2eb80c(buf, len);
```
`sub_2eb80c(buf,len)` → `sub_2f2478()` + `sub_2f2508(this, buf, len)`：构造并驱动一个**状态机任务对象**：
- ctor `0x2eb8bc`：`state = 7`，分配 `0x128` 字节，`sub_2eb9f8` 初始化；
- `step()` `0x2eb958`：带跳转表 `0x53aa50`，状态 `1/3/8` 流转，通过 `vtable+0x10` / `vtable+0x28` 驱动；
- dtor `0x2eb908`：虚调 `vtable+0x8` 释放。

即 VMRPCS 专包不是同步解析，而是**投入异步任务队列/状态机**逐步执行，与普通 `1/3/4` 同步分派区分开。

---

## 6. 三个命令处理器（普通包 case 1/3/4）

三者共用容器迭代器族（`0x42ca8c` 建迭代器 → `0x42cab0` 载入 → `0x42cc7c/ccb0/cce4` 遍历），差异在数据集来源与前置校验：

| case | 处理器 | 类型 | 关键动作 |
|---|---|---|---|
| 1 | `sub_42B570` | common 规则集 | 先 `sub_42c7e4` 前置校验(失败 -1)，`sub_42cab0(mode=1)` 载入，逐条 `sub_42cd20` 装入 common 容器 |
| 4 | `sub_42BAD0` | single 规则集 | 读包内标志 `buf[4]` 与内层对象 `[obj+8]` bit0，经 `sub_42da14` 定模式，`sub_42cab0(mode=1)` 载入 single 容器 |
| 3 | `sub_42B87C` | ack / 心跳 | `sub_42d3a0`→`sub_42d530` 载入，遍历后读 `[obj+0x11]` 标志，多为确认/状态回写，不投扫描 |

空包 (§3.3 D) 的复位三连 `sub_429D4C/429E94/429FDC` 分别清空 3 个规则容器全局单例（如 `0x564bc8`），对应“下发清空/失效”。

---

## 7. 规则装载 `sub_42BE5C`

入参 `(ctx, mode w1, is_single w2, vec3, vec5, vec6, vec7…)`：
- `mode==1`：用 `0x3646c0` 从 3 个来源向量拷入；否则用 `0x39f710`（3 次）。
- 按 `is_single` 选目标容器：single → ctx `+0x108`，common → ctx `+0xc0`。
- `0x42d28c` 装配；`0x429aa4` 校验，失败 `0x37da04(_, 1)` 通知。
- 结果：解出的规则集分别落到上下文 common(`+0xc0`) / single(`+0x108`) 两个槽位。

---

## 8. 内存扫描执行体 `sub_3E06D0`（VMRPCS 真正“干活”部分）

按规则项扫自身进程内存：
1. 反混淆 `/proc/self/maps`（`0x911e6 ⊕ 0x18`），`fopen`（PLT `0x50eac0/0x50ea90`）打开。
2. 反混淆权限过滤串：`0x3e0800 strh 0x6a`→`'r'`；`0x3e0834 0x6860356a ⊕0x18 = "r-xp"`（可执行段）；`0x3e084c 0x6835356a ⊕0x18 = "r--p"`（只读段）。
3. `0x37d514` 逐行读 maps → `0x37d3fc` 解析每个 region `[start, end, perm]`，筛 `r-xp`/`r--p`。
4. 对命中区按传入扫描描述符 `x1` 做特征/CRC 扫描（对应 MVM `wild scan`/`ScanCast` 与 `.text` 段 CRC 自校验 `txt_seg_crc`）。命中回填结果结构 `ctx[+0x140/+0x148]`，交上层 `sub_434F3C` 上报。

---

## 9. CRC / 完整性

- 全库单一多项式 `0xEDB88320`（标准 zlib CRC32），表在 `.rodata 0xe2158`。
- 入口变体：`0x489210` 一次性 `crc32(buf,len)`、`0x48924c` 续算、`0x489288` 文件 4KB 分块；表 getter `0x489204`。`crc32lei`(§3.1) 属同一族。
- 另有三张 64-bit zlib braid 表（`0xdc1c0/0xdfeb8/0xe1958`）仅用于解压，非独立 CRC 算法。
- 证书/签名指纹另走 MD5 + SHA-256（IV 常量 `0x99d20`/`0x9a1a0`）。
- 整体完整性上报串：`cert_md5=%s|apk_hash_1=0x%08x|apk_hash_2=0x%08x|txt_seg_crc=0x%08x`（组装于 `0x4cbd7c`）。

---

## 10. 完整数据流

```
sub_42A700 (下载线程)
  └─ sub_42A5D8(ctx, buf, len, flag)         顶层接收器
       ├─ crc32lei → v13                       标准 CRC32 指纹
       ├─ sub_3F63F4 去重缓存                  同 CRC 已处理 → 丢弃
       ├─ [ZIP] sub_42A338                     zlib 解压 mrpcs.data；失败→坏包上报
       ├─ 重建签名 == "VMRPCS" ^ (len&0xff) ?
       │    ├─ 是 → sub_42A0E8 → sub_2eb80c → sub_2f2508   VMRPCS 异步任务(状态机)
       │    └─ 否 → sub_3A2D38 [(⊕k1)+k2 + 校验和]
       │             switch(*v15): 1→sub_42B570(common) 3→sub_42B87C(ack) 4→sub_42BAD0(single)
       │                └─ sub_42BE5C 装载 → common(+0xc0)/single(+0x108)
       │                     └─ sub_3E06D0(/proc/self/maps, r-xp/r--p 扫描)
       │                          └─ sub_434F3C(命中上报)
       └─ [空包 *buf==0] sub_429D4C/429E94/429FDC   复位全部规则容器
```

---

## 11. 关键地址速查

| 地址 | 作用 |
|---|---|
| `0x42A700` | MRPCS 下载/分发线程入口 |
| `0x42A5D8` | 顶层接收器（CRC/去重/ZIP/VMRPCS/命令分派/复位） |
| `0x42AD54` | 解析子例程（(C) 分支同源） |
| `0x42A338` | zlib 解压 `mrpcs.data`（标签 `unzipmrpcs.data`） |
| `0x3A2D38` | payload `(⊕k1)+k2` 反混淆 + 校验和 |
| `0x2E6188` | 校验和原语 |
| `0x2E5F08` / crc32lei | 入包 CRC32 |
| `0x3F63F4` / `0x3F6104` / `0x3F5280` | CRC 去重缓存 |
| `0x42A0E8` → `0x2eb80c`/`0x2f2508` | VMRPCS 专包异步任务 |
| `0x42B570` / `0x42B87C` / `0x42BAD0` | 命令 1(common)/3(ack)/4(single) 处理器 |
| `0x429D4C` / `0x429E94` / `0x429FDC` | 空包复位规则容器 |
| `0x41A0A4` / `0x4191C0` / `0x419518` | 容器工厂 / ctor / init（虚调 vtable+0x10） |
| `0x42BE5C` | 规则装载（common `+0xc0` / single `+0x108`） |
| `0x3E06D0` | `/proc/self/maps` + `r-xp`/`r--p` 内存扫描器 |
| `0x434F3C` | 命中结果派发/上报 |
| `unk_566818` | 全局互斥锁 |
| `ctx+0x654` (`a1[405]`) | 状态机字段 |

---

## 11.5 MRPCS 关联子系统：去重缓存 + 单例/锁映射

`sub_42A5D8` 顶层接收器依赖两套全局单例（均在 `.bss` 段 `0x566000` 页内，各自「指针 + 锁」成对）：

**全局对象映射（base `0x566000`）：**
| 地址 | 含义 | getter / 锁 |
|---|---|---|
| `0x5663d0` | **去重/派发缓存**单例指针 | getter `sub_3F5280`，`lock_guard 0x364c84/0x364cec` |
| `0x566810` | **MRPCS 主接收器**单例指针 | getter `sub_428BD8`，`lock_guard 0x364c84/0x364cec` |
| `0x566818`(`unk_566818`) | 保护 `0x566810` 的互斥锁（即"改 566818"问的那把） | `sub_364BDC`/`sub_364C14` |
| `unk_564988` | 解析器一次性初始化对象 | `sub_419368`(判) + `sub_42B51C`(建) |

**去重路径三件套（对应 `sub_42A5D8` 里 CRC 去重分支）：**

1. **`sub_3F6348` — 特性门控**：读配置项 `"mp_lf_nwthrd"`（@`0x92cfa`，MRPCS 无锁/多工作线程去重开关）经配置 getter `sub_392bb8`，返回该去重/异步特性是否启用。`sub_3F63F4`(去重判定) 一进门先调它，未启用直接返回 false。

2. **`sub_3F63F4` — "是否重复/已生效"判定**（前面已列）：门控通过后建流读 ZIP 头→需要则 `sub_42A338` 解压→`sub_428BD8` 取主对象→`sub_42989C` 与当前生效数据比对，命中返回 true → 上层丢弃该包。

3. **`sub_42989C` — 当前生效集比对**：先读对象 `+0x5d0` 状态字节与 `0xFF` 比较（未初始化哨兵），随后 `sub_364BDC` 加锁遍历 `obj+0x840` 处的链表/记录，逐项 `ldr w12,[x8]; cmp w12,w13; cset ne`（比对 CRC/键），返回是否命中当前已装载集合。

4. **`sub_3F6104` — 登记已处理包**（去重命中或处理完时调用）：`sub_364BDC` 加锁 → `sub_3F88BC/3F8AF8` 建流 → **`sub_3F620C` 计算摘要键**（内部 `0x3f67b0/0x3f7afc/0x3f7c00/0x3f68dc…` 多步 update/final，形态为哈希/摘要原语）→ **`sub_3FA004` 插入去重缓存**（内部 `sub_3FA120`，`lock_guard 0x364c84`）→ 解锁。

**关系总结：** `0x566810/0x566818`(主接收器+锁) 与 `0x5663d0`(去重缓存) 是 MRPCS 的两个核心全局单例；`crc32lei` 算出的包 CRC 既是完整性校验，又作为**去重缓存的键**——`sub_3F63F4` 查（重复即丢，`mrpcs_data_crc_error`），`sub_3F6104` 记。去重特性由云端配置 `mp_lf_nwthrd` 控制开关。

---

## 12. 未决 / 置信度说明

- `sub_2E6188` 校验和的确切算法名未最终确定（已确认为校验原语）。
- `sub_3A2D38` 前 4 字节 magic 与 k1/k2 的精确字节关系被反编译器字节/字重叠掩盖，若需逐位精确应再对照原始 ARM64 load。
- VMRPCS 序列化字段 schema（头/命令字/规则容器边界之外）需更多样本 `mrpcs.data` 或更完整数据流跟踪。
- `0x41A0A4/0x4191C0` 背后的 C++ 类层次/vtable 归属未从 strip 符号中恢复。
