# Codex CLI 适配指南

AgentSight 通过 eBPF uprobe 捕获 Codex CLI 的 TLS 明文流量。Codex 静态链接 aws-lc（BoringSSL 兼容 C ABI），并使用 `SSL_write_ex` / `SSL_read_ex` 作为加密入口。当二进制保留符号时按符号挂载即可；剥离了符号时需要通过内置 offset 表查表。

## 三级回退

| Tier | 方式 | 适用场景 |
|------|------|---------|
| 1 | 按符号名挂 uprobe | 二进制保留 `.dynsym` / `.symtab` 时（自编译默认） |
| 2 | 字节码 pattern 扫描 | 已收录指纹的常见 BoringSSL 构建 |
| 3 | 内置 offset 表查表 | 已收录版本的 stripped binary |

未命中三级则放弃挂载并打印 warn 日志。

## 内置版本

写入 `src/agentsight/agentsight.json -> codex_offsets.entries` 即可。当前内置：

| codex 版本 | 状态 |
|------------|------|
| 0.141.0 | Tier 3 `SSL_*_ex` |
| 0.137.0 | Tier 3 `SSL_*_ex` |

## 为新版本提取偏移

### 前置：拿到一份**带符号**的同版本二进制

线上 codex release 是 stripped binary，nm 拿不到符号。你需要先准备一份**带符号**副本，再用它跑提取脚本。三种方式按优先级：

**方式 A：官方 symbols 包（0.140 及以上推荐）**

0.140 起 codex GitHub release 附带 `codex-symbols-x86_64-unknown-linux-musl.tar.gz`。下载并解压即可：

```bash
VERSION=0.141.0  # 替换成你的版本
curl -L -o codex-symbols.tar.gz \
  "https://github.com/openai/codex/releases/download/rust-v${VERSION}/codex-symbols-x86_64-unknown-linux-musl.tar.gz"
tar xzf codex-symbols.tar.gz
# 解压出 codex-symbols-x86_64-unknown-linux-musl/codex.debug，nm 可识别符号
```

**方式 B：自行编译，不要 strip（0.139 及以下，或希望可复现）**

0.139 及以下 release 没有 symbols 包；此时直接 clone 源码、checkout 对应 tag、编译时不要 strip：

```bash
git clone https://github.com/openai/codex.git
cd codex
git checkout rust-v0.137.0       # 替换成你的版本

# 编译前确认 codex-rs/Cargo.toml 里 [profile.release] 没有以下任一行：
#   strip = true
#   strip = "symbols"
# 若有，注释掉或改成 strip = "none"
cargo build --release -p codex --target x86_64-unknown-linux-musl
# 产物：target/x86_64-unknown-linux-musl/release/codex
nm --defined-only target/x86_64-unknown-linux-musl/release/codex | grep SSL_  # 验证有符号
```

> Tip：debug build (`cargo build` 不加 `--release`) 也带全套符号，但函数地址 / 二进制布局跟 release 不一致，不能直接用于线上 stripped binary 的偏移提取。请用 release 构建。

**方式 C：本机已经在跑带符号的版本**

如果是从源码 `cargo install --path ...` 安装的，本机 codex 一般就带符号，直接用即可。

### 另外还需要

- 一份**目标**（运行中那份） stripped binary —— 用于取指纹
- Python 3 + `nm`、`readelf`、`sha256sum`

### 步骤

1. 取 stripped binary 的指纹：

```bash
stat --printf='%s\n' /path/to/codex-stripped
head -c 65536 /path/to/codex-stripped | sha256sum
readelf -n /path/to/codex-stripped | grep "Build ID"   # 如有
```

2. 在**带符号**那份上跑提取脚本：

```bash
python3 src/agentsight/scripts/extract-codex-offsets.py /path/to/codex-with-symbols
```

脚本会优先匹配 `SSL_write_ex` / `SSL_read_ex` / `SSL_do_handshake`，若 `_ex` 变体不存在则退到 `SSL_write` / `SSL_read`，并据此生成 `write_is_ex` / `read_is_ex` 标志。输出形如：

```json
{
  "codex_version": "0.141.0",
  "fingerprint": {
    "file_size": 276579568,
    "head_64k_sha256": "f015ddd2a687c1fc0b3ce70d898c0a68eeab88ad0040e79b0fe49a8545ff52a9"
  },
  "offsets": {
    "ssl_write": 210691872,
    "ssl_read": 210691280,
    "ssl_do_handshake": 210689600,
    "write_is_ex": true,
    "read_is_ex": true
  }
}
```

3. 用**步骤 1** 拿到的 stripped binary 指纹覆盖 `fingerprint`，然后把整条 entry 追加到 `agentsight.json` 的 `codex_offsets.entries` 数组里。如果有 BuildID，也加进 `fingerprint`，AgentSight 会优先按 BuildID 匹配。

4. 验证：重新启动 agentsight 后日志会出现：

```
[attach_process] pid=<PID>: codex offset table matched for /proc/<PID>/root/.../codex
  (write=0x<...>, read=0x<...>, handshake=0x<...>)
```

## 手动提取（无脚本时）

```bash
# 优先用 _ex 变体（aws-lc / BoringSSL 默认导出）
nm --defined-only /path/to/codex-with-symbols | grep -E ' (SSL_write_ex|SSL_read_ex|SSL_do_handshake)$'

# 如果没有 _ex，退到普通 SSL_write / SSL_read
nm --defined-only /path/to/codex-with-symbols | grep -E ' (SSL_write|SSL_read|SSL_do_handshake)$'
```

`nm` 输出第一列就是文件偏移（十六进制），直接转十进制填入 `offsets`。

## 完全没有带符号副本时的后备路线

极端情况下既拿不到 symbols 包也无法重新编译（比如目标版本源码已不可获取），可以用 `objdump` 加 `bpftrace` / tracefs uprobe 的命中数比对来人工锁定地址。已收录的 0.137 偏移就是这样拿到的。大致思路：

1. `objdump -d` 找具备 aws-lc `SSL_write_ex` 序言特征的候选地址，可借助 `strings -t x` 反查 aws-lc 内部字符串引用收窄范围。
2. 用 `bpftrace -e 'uprobe:/path/to/codex:0x<CANDIDATE> { @ = count(); }'` 挂到候选 offset，同时跑一次真实 codex 请求；命中数应满足 `SSL_do_handshake = 1`、`SSL_write_ex ≈ 1`、`SSL_read_ex` 与 SSE chunk 数同阶。
3. 用 uretprobe 抓 `$retval` 判断是否 `_ex` 变体（返回值仅 0/1，真实长度由第 4 参数 `*written` 回写），据此设置 `write_is_ex` / `read_is_ex`。

这条路线工作量大且容易出错，建议优先走前面三种带符号副本的方式。

## 符号与 ABI

| 符号 | 角色 | 说明 |
|------|------|------|
| `SSL_write` / `SSL_write_ex` | 写端 | 应用明文进入加密管线入口 |
| `SSL_read` / `SSL_read_ex` | 读端 | 解密明文交给应用 |
| `SSL_do_handshake` | 握手 | 标记 TLS 握手完成 |

`*_ex` 与普通 `SSL_write/SSL_read` 的关键差异：返回值是 0/1 成功标志，真实长度通过出参 `written` / `readbytes` 写回。这要求 BPF 探针在 `kretprobe` 中读取出参而不是返回值，因此 offset 表里 `write_is_ex` / `read_is_ex` 不能省。

## PR 模板

新增版本偏移请附：

- [ ] codex 版本号
- [ ] stripped binary 的 `file_size` + `head_64k_sha256`（必须）+ BuildID（如有）
- [ ] 提取方式（脚本 / 手动）
- [ ] 验证截图（agentsight 启动日志 `codex offset table matched`）
