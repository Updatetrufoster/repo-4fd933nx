# libtersafe.so 防篡改 / 完整性校验（CRC · Hash · 证书 MD5）深度逆向

针对 `dfenxiwanjianlibtersafe.so`（腾讯 ACE/TP，target `com.tencent.tmgp.dfm`）。
文件按 vaddr==file offset 1:1 映射，下列地址即运行时虚拟地址。

---

## 1. CRC32 核心算法

标准 **CRC32（reflected，多项式 0xEDB88320，zlib 变体）**。查表法，表在 `.rodata` `0xe2158`（256×4 字节）。
`strings` 还能看到另外 3 张 CRC 表（`0xdc1c4 / 0xdfebc / 0xe195c`）——那些属于静态链接进来的 zlib(inflate/crc32)，反篡改代码只用 `0xe2158` 这一张。

### 1.1 `crc32_table()` @ `0x489204`
```
adrp x0,#0xe2000 ; add x0,x0,#0x158 -> 返回 &crc_table(0xe2158)
```

### 1.2 `crc32(buf, len)` @ `0x489210`  —— 一次性
```c
uint32_t crc32(const uint8_t* p, size_t n){
    if(!n) return 0;
    uint32_t crc = 0xFFFFFFFF;          // mov w8,#-1
    while(n--){
        uint8_t b = *p++;
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;                        // mvn w0,w8
}
```
汇编精确对应：
```
0x489214 mov  w8,#-1
0x489220 ldrb w10,[x0],#1
0x489228 eor  w10,w10,w8
0x48922c and  x10,x10,#0xff
0x489230 ldr  w10,[x9,x10,lsl #2]   ; table[idx]
0x489234 eor  w8,w10,w8,lsr #8
0x48923c mvn  w0,w8                  ; ~crc
```

### 1.3 `crc32_cont(buf, len, seed)` @ `0x48924c`  —— 可续算
和上面同一个循环，但**不做** `init 0xFFFFFFFF`、**不做** `~` 收尾，直接以传入的 `seed`(w2) 起算并返回原始 crc。用于分块/流式累加。

### 1.4 `crc32_file(path, *out_crc, size_limit, k)` @ `0x489288`  —— 文件 CRC
```c
*out = 0xFFFFFFFF;
FILE* f = fopen(path, "rb");            // 0x4b7a70
while(!feof(f)){                        // 0x4b7ed0
    n = fread(buf, 1, 0x1000, f);       // 0x4b7f18  每次 4KB
    if(n<=0x1000) { 累加 crc32_cont 到 *out; }
    if(ferror(f)) goto err;             // 0x4b7f00
    if(size_limit && (total+=n) > size_limit) 特殊处理;
}
fclose(f);                              // 0x4b79b8
*out = ~*out;                           // 0x489394 mvn
```
即：以 4KB 分块把整个文件流式 CRC32，最后取反。`size_limit` 用于只校验文件前 N 字节。

CRC32 核心被 **200+ 处**调用（`bl 0x489210`），说明整库大量用它做特征匹配、下发规则校验、缓存校验等。

---

## 2. 三层完整性上报（关键）

反篡改结果最终拼进这条上报串（解密得到，callsite `0x4cbd7c`，输出函数体在 `0x4cbd7c`）：
```
cert_md5=%s|apk_hash_1=0x%08x|apk_hash_2=0x%08x|txt_seg_crc=0x%08x
```
汇编里三个值来自一个已预先算好的结构体 `x20`：
- `apk_hash_1 / apk_hash_2` ← getter `0x2db758`（调用两次，返回 APK 的两个哈希）
- `txt_seg_crc` ← `ldr w6,[x20,#0x84]`（结构体偏移 **+0x84**，代码段 CRC 字段）
- `cert_md5` ← 解密串 stub `0x4ec3d8(id=0x7f49)` 拼装

### 2.1 代码段自校验 `txt_seg_crc`
- 保存在对象偏移 `+0x84`，在初始化阶段对**内存中自身 .text 段**做 CRC32 后写入。
- 上报时与 APK 哈希、证书 MD5 一起打包 → 服务端比对，检测 **inline hook / .text patch / 内存改代码**。
- 这也是 `[A] inline_hook_opcode_dismatch`、`[D] elf_hook_scan / opcode_scan / ms_hook_opcode / ScanOpcode` 这些扫描的配套：本地扫 hook 特征 + 代码段 CRC 上报双保险。

### 2.2 APK / 文件 CRC
判定结果串（解密）：
```
apk_crc_eq / apk_crc_not_eq
inner_apk_crc_eq / inner_apk_crc_not_eq
file_crc_eq / file_crc_eq2 / file_crc_not_eq2
inner_apk_file_crc_eq2 / inner_apk_file_crc_not_eq2
cache_crc.dat            // 本地缓存的 CRC 记录
```
上报模板：
```
name=%s|size=%d|crc=0x%08x|mark=0x%08x
name=%s|size=%d|crc=0x%08x|root=%d
name=%s|feature=%s|size=%d|mtime=%d|cert_md5_crc=0x%08x
```
即对 APK 本体、APK 内部文件（inner_apk）、SDK 自身文件用 `crc32_file` 算 CRC + size + mtime，和期望值/缓存比对，检测重打包、替换 so、篡改资源。

### 2.3 证书 / 签名校验（防重签名）
```
official_cert_md5        // 内置的官方签名证书 MD5（期望值）
cal_cert_md5             // 运行时计算得到的证书 MD5
cert_md5_eq / cert_md5_not_eq
name=%s|feature=%s|cert_md5=%s|fake_cert=%d   // fake_cert=1 表示签名不匹配
CertHash=%s|DST=%04x|PkgNamesCnt=%d|PkgNames=%s|%s|
cert=%s|author=%s
```
流程：通过 JNI 取 APK 签名证书（`GET_SIGNATURES`/`[Landroid/content/pm/Signature;`/`java/security/Signature`）→ 算 MD5(`cal_cert_md5`) → 与内置 `official_cert_md5` 比对 → 不一致置 `fake_cert=1` 上报。检测**重签名/盗版包**。

---

## 3. 下发规则 / VM 脚本的 CRC 校验
MRPCS 云端下发的扫描规则也带 CRC：
```
dl custom, name:%s, len:%d, crc:%08x, channel:%d
func=feature_rcv_start|name=%s|crc=%d|size=%d
mrpcs_data_crc_error / ms_data_crc / %s;crc:%s
```
下载到的规则/特征包会先校验 CRC，不符则 `mrpcs_data_crc_error` 丢弃，防止中间人篡改下发内容。

---

## 4. 关键地址速查

| 地址 | 作用 |
|------|------|
| `0x489204` | `crc32_table()` 返回 CRC 表 `0xe2158` |
| `0x489210` | `crc32(buf,len)`（init 0xFFFFFFFF，末尾 ~，标准 CRC32） |
| `0x48924c` | `crc32_cont(buf,len,seed)` 续算（无 init/无收尾） |
| `0x489288` | `crc32_file(path,*out,limit,k)` 4KB 分块文件 CRC |
| `0x4cbd7c` | 组装 `cert_md5=..|apk_hash_1=..|apk_hash_2=..|txt_seg_crc=..` 上报 |
| `0x2db758` | APK 哈希 getter（apk_hash_1 / apk_hash_2） |
| 结构体 `+0x84` | 代码段自校验值 `txt_seg_crc` |
| `.rodata 0xe2158` | 反篡改用 CRC32 表（poly 0xEDB88320） |

## 5. 一句话总结
这套防篡改是**三合一**：① 内存 `.text` 段 CRC32 自校验（`txt_seg_crc`，抓 inline-hook/内存改码）＋ ② APK/内部文件/自身 so 的 `crc32_file`＋size＋mtime 校验（抓重打包/替换）＋ ③ 签名证书 MD5 与内置 `official_cert_md5` 比对（抓重签名），全部连同结果打包上报服务端二次核验；下发规则本身也带 CRC 防篡改。CRC 用标准 zlib CRC32（表 `0xe2158`），核心函数 `0x489210`。
