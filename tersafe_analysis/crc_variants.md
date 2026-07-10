# libtersafe.so 里的“多套 CRC”深度逆向

上一篇发现 `.rodata` 里有 4 处命中 CRC32 表签名（`0xdc1c4 / 0xdfebc / 0xe195c / 0xe2158`）。逐一逆向后结论：

> **多项式只有一个：`0xEDB88320`（标准 zlib CRC-32，reflected）。** “好几套”不是不同算法，而是
> **1 套独立的整型 32-bit 表（反篡改自用）+ 3 套 zlib 的 64-bit “braid” 表（多份静态链接的 zlib 各带一份）**。
> 全库没有别的 CRC 多项式（扫过 CRC-16 ARC/CCITT、normal poly 0x04C11DB7/0x1EDC6F41 等，均无命中）。

---

## A. 表的真实类型（按字节精确还原）

| 名称 | 表起始 | 元素宽度 | 类型 | 归属 |
|------|--------|----------|------|------|
| **T3** | `0xe2158` | 4 字节 (u32) | 经典 `crc_table[256]`，`t[128]=0xEDB88320` | **反篡改自用 CRC32** |
| **T0** | `0xdc1c0` | 8 字节 (u64) | zlib **braid** 表 `crc_braid_table`，`entry[k]=std[k]` 零扩展到 64 位 | 静态 zlib #1 |
| **T1** | `0xdfeb8` | 8 字节 (u64) | 同上 | 静态 zlib #2 |
| **T2** | `0xe1958` | 8 字节 (u64) | 同上 | 静态 zlib #3 |

验证要点：
- 之前误读成 “`t[0]=0, t[1]=0x77073096, t[2]=0, t[3]=0xee0e612c…`”，是因为按 u32 读了 u64 表——真实起点前移 4 字节后按 u64 读：
  `entry = 0, 0x77073096, 0xee0e612c, 0x990951ba, …`，与标准 CRC32 表逐项相等（256 项全等，poly=0xEDB88320）。
- T0/T1/T2 三处**紧邻的消费代码就是 zlib 的 `fixedtables()`**：
  - `0x3ce6d8`：把 `lenfix=0xdc9c0`、`distfix=0xdd9c0` 连同 `lenbits=9 / distbits=5` 写回 inflate state → 100% 是 zlib 的固定 Huffman 表。
  - `0x47e994`：把 `0xe06b8 / 0xe16b8` 写入 state，`state=0x509`，同为 zlib fixedtables。
  这些区段（`0xdc000`、`0xe0000`、`0xe1000`）各自是一份完整 zlib（crc 表 + 固定 Huffman 表 + inflate 代码）。三份来自不同静态链接单元（SDK 自带 zlib、以及下载/更新与图像相关依赖各拉入一份）。

**结论**：T0/T1/T2 属于解压用途（解 MRPCS 下发的 `.zip` 规则包、`tpup*.zip`、`.so`/`.dex` 更新），不是独立的校验算法。

---

## B. 反篡改自用 CRC32（T3，`0xe2158`）—— 唯一“变体家族”

同一张表、同一多项式，围绕它有 **3 个入口变体**（对应不同调用场景）：

### B1. 一次性 `crc32(buf,len)` @ `0x489210`
`init=0xFFFFFFFF`，逐字节 `crc=table[(crc^b)&0xff]^(crc>>8)`，收尾 `~crc`。标准 CRC32。

### B2. 续算 `crc32_cont(buf,len,seed)` @ `0x48924c`
同循环，**不做 init、不做收尾**，以传入 `seed` 起算、返回裸 crc。用于把大对象分块累加。

### B3. 文件 `crc32_file(path,*out,limit,k)` @ `0x489288`
`fopen("rb")` → 每次 `fread 0x1000`（4KB）→ 用 B2 的续算逻辑累加 → 末尾 `~`。`limit` 支持只校验前 N 字节。

> 这三者共享 `crc32_table() @0x489204`（返回 `0xe2158`）。反篡改上报里的 `txt_seg_crc / apk_hash / crc:0x%08x` 全走这套。核心 `0x489210` 被 **200+ 处**调用。

---

## C. 顺带确认的其它校验/哈希原语

不是 CRC，但同属完整性/签名体系（`.rodata` 常量命中）：

| 算法 | 证据 | 用途 |
|------|------|------|
| **MD5**（或 MD4/SHA1 家族初值） | `0x99d20`: `67452301 efcdab89 (98badcfe 10325476)` | `cal_cert_md5` / `official_cert_md5` 证书指纹 |
| **SHA-256** | `0x9a1a0`: `6a09e667…`（IV 常量） | 签名校验 / 摘要 |
| **adler32 / CRC16** | 无命中 | 未使用 |

---

## D. 一句话总结
所谓“好几套 CRC”其实是**同一个 zlib CRC-32（poly 0xEDB88320）的两种存储形态**：反篡改模块用**经典 32-bit 表**（`0xe2158`，配 `crc32 / crc32_cont / crc32_file` 三入口）做完整性校验；另有**三份静态 zlib**各带一张 **64-bit braid 表**（`0xdc1c0/0xdfeb8/0xe1958`，配固定 Huffman 表）纯粹用于解压下发数据。证书/签名另用 **MD5 + SHA-256**。全程没有第二种 CRC 多项式，也没有 CRC-16。
