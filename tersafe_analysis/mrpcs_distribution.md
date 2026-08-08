# MRPCS 下发机制深度逆向（下载 → 接收 → 分支分发全链）

> 目标：`libtersafe.so`（TP 7.7.049.57576 / 三角洲行动 `com.tencent.tmgp.dfm`）
> 本报告把「MRPCS 下发」整条链逆到底：**主机/CDN 选择 → URL 构造 → 传输（native socket + Java URLConnection）→ 数据入口 `TssSDKOnRecvData` → 接收器 `sub_42A5D8` → 分发器 `sub_42AD54` 的全部分支**。
> 全部地址为库内相对地址（运行时 + load base）。置信度：**confirmed** / **强推断** / **未确认**。

---

## 0. 一句话结论

MRPCS 是**云端规则/特征下发通道**：客户端从 `WB_SyncGs2Host` 拿到 `cdn_host/cs_host/cs_ip`，按 3 套 URL 模板拼出下载地址，用 **native socket（`socket/connect/send/recv`）为主、Java `URLConnection` 兜底**去 CDN 拉 `mrpcs.data`/各类 `*.zip`；下载数据经 `TssSDKOnRecvData`（命令 ladder）投喂到接收器 `sub_42A5D8`，接收器用 `ctx+0x654` 状态机分 **1 接收 / 2 解压 / 3 普通完成 / 4 VMRPCS 特殊 / -1 失败** 五路，分发器 `sub_42AD54` 再按 **ZIP 头 / VMRPCS 魔数** 二次分流到解压、反混淆、规则装载。

---

## 1. 主机 / CDN 选择（host → native）

### 1.1 `WB_SyncGs2Host` @ `sub_282358`（confirmed）

宿主（Java/游戏）通过 `SendCmd` 把服务器分配的下载主机同步进来，native 组包字符串（`0x2823f8`）：

```
func=WB_SyncGs2Host|game_id=%d|cdn_host=%s|cs_host=%s|cs_ip=
```

- `0x282380 bl 0x215a1c` / `0x282384 bl 0x2166d8`：取/存 host 字段。
- `0x2823e0 bl 0x1f8350`：写入全局 host 表。
- `0x282434 add …#0x722 ","`：`cs_ip` 支持逗号分隔的多 IP 列表，逐个 `0x4a4738` 拷入（`cmp #0x200` 缓冲上限）。

相关解密串：`CDNHost:`(`0x1bdca8`)、`SetChannelHost:`(`0x1bdcd8`)、`cdn_host`(`0x216098`)、`game_host`(`0x1f850c`)。

### 1.2 三个内置下发域名（confirmed，解密串）

| 域名 | 用途（强推断） |
|---|---|
| `down.anticheatexpert.com`(`0x215f4c`) | 主 CDN（`iedsafe/Client` 静态分发） |
| `dl.putdl.com`(`0x215fb4`) | 备用下载 CDN |
| `dl.timedl.com`(`0x21601c`) | 备用下载 CDN |
| `nj.cschannel.anticheatexpert.com`(`0x1f85b8`) | cs 通道（上报/信令） |
| `tyf.cschannel.anticheatexpert.com`(`0x1f866c`) | cs 通道（上报/信令） |
| `acekeeper.anticheatexpert.com`(`0x282104`) | acekeeper 服务端 |

`cdn_host` 优先用 `WB_SyncGs2Host` 下发值，缺省回落到 `down.anticheatexpert.com`。

---

## 2. URL 模板与构造器

### 2.1 三套模板（confirmed，解密串）

```
%s://%s/iedsafe/Client/%s                 (0x21698c)   scheme+host+资源
https://%s/gamesafe/mobile/%s/%08X         (0x216ae4)   host+平台+版本hash
%s/%d/%08X/%s                              (0x219928)   host/game_id/hash/文件名
gamesafe/mobile/ano_dfh.zip                (0x4dbd14)   三角洲专包相对路径
```

固定探针（CDN 连通性自检）串：

```
https://down.anticheatexpert.com/iedsafe/Client/android/8899/71C1E6D7/donot_delete_me   (0x2224d0)
```

### 2.2 `mrpcs.data` URL 构造器 @ `sub_219844`（confirmed）

`sub_219844` 顺序解密一批组件（host、`cdn_host`、game_id、版本 `%08X`）再拼 `%s/%d/%08X/%s` + `mrpcs.data`：

```
0x219920 bl 0x4e79c4   -> "mrpcs.data"
0x219928 bl 0x4e7784   -> "%s/%d/%08X/%s"
0x219950 bl 0x218c8c   -> snprintf 组装
0x219964 bl 0x2dad88   -> 取 TLS/ctx
0x219968 bl 0x239b1c   -> 取 game_id/版本上下文
```

即最终下载 URL 形如：`https://<cdn_host>/<game_id>/<verHash>/mrpcs.data`。

### 2.3 CDN 探针 @ `sub_2223F0`（confirmed）

```
0x2224d0 bl 0x4e9fec   -> 解密 "https://…/donot_delete_me"
0x2224e4 bl 0x4c69d8   -> down_mrpcs(该 URL)         ← 触发下载
0x2224f0 bl 0x489210   -> crc32_once(结果)            ← 校验回包
0x222500 bl 0x4e9270   -> "donot_delete_me"
```

作用：定期拉一个「请勿删除」占位文件确认 CDN 可达 + 结果 CRC，服务端据此判断链路健康。

### 2.4 其它下发文件（tpup / ano_dfh）

```
%s/tpup.zip              (0x2d26dc)
%s/%d/%08X/tpup.zip      (0x2d287c)     TP shell 自升级
%s/%d/%08X/tpup64.zip    (0x2d2884)
gamesafe/mobile/ano_dfh.zip (0x4dbd14)  三角洲反外挂专包
```

---

## 3. 下载传输层

### 3.1 native socket 路径（confirmed）

导入表含完整 socket 族：`socket / connect / getaddrinfo / send / recv / recvfrom / recvmsg / sendmsg / sendto / inet_ntop / inet_pton`。

- `socket@LIBC` PLT stub `0x50e510`，调用点 `0x4cdef8`、`0x4ce228`、`0x24f434`。
- `connect@LIBC`：GOT `0x51cff8`(JUMP_SLOT) + `0x51c4e0`(GLOB_DAT)，经函数指针间接调用。
- socket 建连/收发助手：`sub_4CDE90`（建 socket + `0x50e520` setsockopt）、`sub_4CE1B0`（`getaddrinfo`/连接封装）。

即 native 自身能发起裸 HTTP GET 到 CDN 域名拉下发包。

### 3.2 Java `URLConnection` 兜底（confirmed）

```
java/net/URL                 (0x2d3318)
()Ljava/net/URLConnection;   (0x2d3380)
%s/Download                  (0x2c9a0c)
```

当 native 直连受限时，通过 JNI 走宿主 `java.net.URL.openConnection()` 下载，结果回填 native。

### 3.3 下载触发 `down_mrpcs` @ `sub_4C69D8`（confirmed）

```
0x4c6a1c bl 0x4e9ecc   -> 解密日志 tag "down_mrpcs"
0x4c6a34 bl 0x22da58   -> 构造下载任务对象
0x4c6a40 bl 0x49efe0   -> 入队/引用计数
0x4c6a78 bl 0x4c6cb4   -> 投递到下载线程
0x4c6a98 bl 0x50e160 / 0x4c6abc bl 0x50dfe0  -> pthread/回调 PLT
```

`down_mrpcs` 把 URL 封成异步下载任务投递到下载线程；日志 tag `down_mrpcs`(`0x4c6a1c`) 便于追踪。

---

## 4. 数据入口 `TssSDKOnRecvData` @ `0x1CEC70`（confirmed 导出）

宿主把下载/服务端下发的数据回投到导出符号 `TssSDKOnRecvData`。函数头是一段 **命令 ladder**（`cmp w25, wXX` 连环比较，`w25` = cmd id）按命令号分发：

```
0x1cece0..0x1cedd8  cmp w25, w{27,23,25,8,19,20,13,21,22,28,26,24,…}   ← cmd 分发
0x1cee08 bl 0x4c34d8   -> 命令处理/投喂接收器
```

配套导出：`TssSDKOnRecvSignature`(`0x1d101c`，挑战-签名应答，走 SHA-256 `0x2c0bb8`) 与 `TssJavaMethod_SendCmd`(`0x2d0d7c`，native→host 上行)。MRPCS 包命中对应 cmd → 进入 `sub_42A5D8`。

---

## 5. 接收器 `sub_42A5D8` 分支全图（confirmed）

状态字段 **`ctx+0x654`**（`a1[405]`）驱动五路状态机：

| 写点 | 值 | 含义 |
|---|---|---|
| `0x42a614 str w9,[x8,#0x654]` | **1** | 接收/校验中 |
| `0x42a848 str w8,[x9,#0x654]` | **2** | 已解压 |
| `0x42a9dc str w8,[x9,#0x654]` | **3** | 普通包完成 |
| `0x42aab4 str w8,[x9,#0x654]` | **4** | VMRPCS 特殊包 |
| `0x42a810 mov w8,#-1` | **-1** | 格式错误/解压失败 |

指令级流程：

```
1. 0x42a610 state=1
2. 0x42a630 bl 0x2e5f08 crc32lei_init  ┐ 整包 CRC = 完整性 + 去重键
   0x42a640 bl 0x2e6188 crc32lei_update ┘
3. 0x42a660 bl 0x3f5280 取去重缓存单例(0x5663d0)
   0x42a67c bl 0x3f63f4 判重复 → 命中则 0x42a6ac bl 0x3f6104 记账并丢弃
4. 0x42a6d8 bl 0x429aa4 / 0x42a700 bl 0x42ad54 分发器（见 §6）
5. 0x42a714 bl 0x364bdc lock(0x566818)   ← 主接收器互斥锁
   0x42a724 bl 0x429714 比对当前生效集
6. ZIP 检测：0x42a764 mov w10,#0x4b50 (PK\x03\x04 头 0x04034B50)
   0x42a78c bl 0x42a338 unzip/zlib 解压 → state=2
   0x42a808 bl 0x364c14 unlock
7. 普通包解析：0x42a9dc state=3
8. VMRPCS 包：0x42aab4 state=4 → 0x42aac4 bl 0x42a0e8 投递 VMRPCS 异步任务
              0x42ab20 bl 0x3a2d38 反混淆/校验
   失败：0x42a810 state=-1
```

`0x429714`(`sub_429714`)= 与「当前已生效规则集」比对，配合去重三件套 `0x3f63f4`(查)/`0x3f6104`(记)/`0x3fa004`(插入)。

---

## 6. 分发器 `sub_42AD54` 分支全图（confirmed）

按 **ZIP 头 / VMRPCS 魔数** 二次分流：

### 6.1 ZIP 分支

```
0x42adc8 bl 0x3f88bc / 0x42addc bl 0x3f8af8   -> 打开流读取器
0x42adf0 bl 0x3f8db0 (读头) / 0x42ae14 bl 0x3f8dc8 (读长度)
0x42ae2c mov w9,#0x4b50   -> 校验 PK header 0x04034B50
0x42ae54 bl 0x42a338      -> unzip/zlib inflate
```

### 6.2 VMRPCS 魔数逐字节校验（confirmed —— 直接指令证据）

分发器把 `"VMRPCS"` 逐字节拼出并比对：

```
0x42af64 mov w10,#0x56   'V'
0x42af80 mov w10,#0x4d   'M'
0x42af9c mov w10,#0x52   'R'
0x42afb8 mov w10,#0x50   'P'
0x42afd4 mov w10,#0x43   'C'
0x42aff0 mov w10,#0x53   'S'
```

魔数匹配 → 进入 VMRPCS 处理：

```
0x42b018 bl 0x3a2d18 / 0x42b060 bl 0x3a2d28 / 0x42b074 bl 0x3a2d38   反混淆 (⊕k1)+k2 + 头校验和
0x42b028 bl 0x364bdc lock / 0x42b090 bl 0x364c14 unlock
0x42b04c bl 0x42b51c   -> 规则装载
0x42b12c bl 0x2e63d0   -> crc32lei 收尾/校验
```

反混淆失败 → `mrpcs_*_data_not_match`；CRC 失败 → `mrpcs_data_crc_error`。

---

## 7. 下发包 / 模板名全表（confirmed，解密串）

| 名称 | 地址 | 类别 |
|---|---|---|
| `mrpcs.data` | 0x219920 | MRPCS 主下发数据 |
| `mrpcs` / `mrpcs1` | 0x219e98 / 0x22e080 | 通道名 |
| `comm.zip` | 0x21a058 | common 规则集 |
| `vm_rom.zip` | 0x1d6bb0 | mini-VM 脚本 rom |
| `builtin.zip` | 0x1d9e9c | 内置规则 |
| `ob_normal*.zip` `ob_x*.zip` | 0x1d9024… | obfuscated 规则集（普通/加强/64位/ace） |
| `ob_cdn{1,2}.zip` `ob_cs{1,2}.zip` `ob_gs{1,2}.zip` | 0x1da908… | 按下发通道(cdn/cs/gs)分包 |
| `ob_ace_gs_%d.zip` `ob_gs2_%d.zip` | 0x21a4d4 / 0x21a500 | 带序号的 gs 分包 |
| `ob_extension.zip` | 0x27eb14 | 扩展规则 |
| `ano_dfh.zip` | 0x4e5098 | 三角洲专包 |
| `cpfc.zip` `cpfc3.zip` `ce_pho_fpa.zip` | 0x2b6d04… | 专项检测包 |
| `tpup.zip` `tpup64.zip` `_w.zip` | 0x2d26dc… | TP shell 自升级 |
| `%s.zip` `%s%08X` | 0x229924 / 0x2c8f20 | 通用拼名模板 |

---

## 8. 关联全局对象 / 锁速查表

| 地址 | getter/lock | 作用 |
|---|---|---|
| `0x566810` | `sub_428BD8` | MRPCS 主接收器单例 |
| `0x566818` | `sub_364BDC/364C14` | 主接收器互斥锁 |
| `0x5663d0` | `sub_3F5280` | 去重/派发缓存单例 |
| `0x563818` / `0x5637F0` | — | crc32lei 全局状态 / 锁 |
| `0x53AA50` | — | VMRPCS 异步任务跳转表 |
| `unk_564988` | — | 解析器一次性 init 对象 |

## 8.1 关键函数速查

| 地址 | 名称 | 说明 |
|---|---|---|
| `0x282358` | WB_SyncGs2Host | 同步 cdn_host/cs_host/cs_ip |
| `0x219844` | mrpcs URL 构造 | `<host>/<gid>/<hash>/mrpcs.data` |
| `0x216878` / `0x216a60` | iedsafe / gamesafe URL 构造 | 静态资源 URL |
| `0x2223f0` | CDN 探针 | donot_delete_me + CRC |
| `0x4c69d8` | down_mrpcs | 下载任务投递 |
| `0x4cde90` / `0x4ce1b0` | socket 建连/收发助手 | native HTTP |
| `0x1cec70` | TssSDKOnRecvData | 数据入口 + cmd 分发 |
| `0x42a5d8` | 接收器 | ctx+0x654 状态机 |
| `0x42ad54` | 分发器 | ZIP / VMRPCS 分流 |
| `0x42a338` | unzip/zlib | 解压 |
| `0x3a2d38` | VMRPCS 反混淆/校验 | (⊕k1)+k2 + 魔数 |
| `0x42be5c` / `0x42b51c` | 规则装载 | 装载到扫描器 |
| `0x2e5f08/0x2e6188/0x2e60ec` | crc32lei | 完整性 + 去重键 |

---

## 9. 置信度说明

- **confirmed**：URL 模板/域名/包名（解密串直读）；`WB_SyncGs2Host` 组包；`mrpcs.data` 构造器；socket 族导入与调用点；`TssSDKOnRecvData` 导出与 cmd ladder；接收器 `ctx+0x654` 五状态写点；分发器 `"VMRPCS"` 逐字节 `mov w10` 魔数校验；ZIP 头 `0x04034B50`；crc32lei/去重三件套调用点。
- **强推断**：各域名的具体职责（主 CDN / 备用 / cs 通道）；`ob_*.zip` 分包与下发通道的对应；探针文件的服务端语义；Java `URLConnection` 作为 native 直连的兜底。
- **未确认（需运行态）**：`connect` 经 GOT 间接调用的确切 callsite 序列；服务端对 `donot_delete_me` 回包的完整校验语义；VMRPCS 反混淆密钥 `k1/k2` 的运行时取值；`cmd id` 到具体处理器的完整映射表（ladder 分支未逐条定名）。

> 本报告为防御性静态取证：只描述下发链的结构、字段、校验与状态语义；不提供拦截下载、伪造下发包、冻结规则热更或规避 CRC/去重/上报的方法。
