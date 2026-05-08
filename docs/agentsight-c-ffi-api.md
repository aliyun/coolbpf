# AgentSight C FFI API

本文档描述 AgentSight 提供的 C 语言接口。采用 **eventfd + read 模式**：AgentSight 内部通过 `eventfd` 通知调用方有新事件就绪，调用方可将该 fd 注册到自己的 epoll/select 事件循环中，被唤醒后调用 `agentsight_read()` 通过回调消费数据。

详细设计文档见 `src/agentsight/docs/design-docs/c-ffi-api.md`。

## 1. C 数据结构

```c
/* HTTP 层数据 — 非 LLM 的 HTTPS 流量会产生此结构 */
typedef struct {
    int32_t     pid;
    char        process_name[16];
    uint64_t    timestamp_ns;
    uint64_t    duration_ns;
    const char* method;               /* "GET", "POST", ...; NUL-terminated */
    const char* path;                 /* "/v1/chat/completions"; NUL-terminated */
    uint16_t    status_code;
    uint8_t     is_sse;
    const char* request_headers;      /* JSON string */
    uint32_t    request_headers_len;
    const char* request_body;         /* JSON or raw text, may be NULL */
    uint32_t    request_body_len;     /* 0 when request_body is NULL */
    const char* response_headers;     /* JSON string */
    uint32_t    response_headers_len;
    const char* response_body;        /* JSON or raw text, may be NULL */
    uint32_t    response_body_len;    /* 0 when response_body is NULL */
} AgentsightHttpsData;

/* LLM 语义层数据 — 仅当 HTTP 流量被识别为 LLM API 调用时产生 */
typedef struct {
    /* 追踪标识 */
    const char* response_id;          /* LLM API 响应 ID（如 chatcmpl-xxx）; may be NULL */
    const char* conversation_id;      /* 同一 user query 触发的调用链标识; may be NULL */
    const char* session_id;           /* may be NULL */

    /* 进程 */
    int32_t     pid;
    char        process_name[16];
    const char* agent_name;           /* may be NULL */

    /* 时间与延迟 */
    uint64_t    timestamp_ns;
    uint64_t    duration_ns;

    /* 请求信息 */
    const char* request_url;          /* 完整 API 地址，如 "https://api.openai.com/v1/chat/completions" */
    const char* provider;             /* "openai", "anthropic", ... */
    const char* model;
    uint16_t    status_code;
    uint8_t     is_sse;

    /* LLM 特有信息 */
    const char* finish_reason;        /* "stop", "length", "tool_calls", ...; may be NULL */

    /* Token 用量（无信息时全为 0）
     * llm_usage: true = 数据来自 LLM API 响应中的 usage 字段（精确值）
     *            false = 由 AgentSight 本地 tokenizer 计算 */
    bool        llm_usage;
    uint32_t    input_tokens;
    uint32_t    output_tokens;
    uint32_t    total_tokens;
    uint32_t    cache_creation_input_tokens;
    uint32_t    cache_read_input_tokens;

    /* 请求/响应语义内容（JSON 字符串） */
    const char* request_messages;     /* LLMRequest.messages 序列化 JSON */
    uint32_t    request_messages_len;
    const char* response_messages;    /* LLMResponse.messages 序列化 JSON */
    uint32_t    response_messages_len;
} AgentsightLLMData;
```

## 2. C API 接口

```c
/* ---- 错误处理 ---- */
/* 返回最近一次 API 调用的错误描述，未出错时返回 NULL。
 * 返回的指针在下次 API 调用前有效，调用者应立即拷贝。 */
const char* agentsight_last_error(void);

/* ---- 配置 ---- */
AgentsightConfigHandle* agentsight_config_new(void);
void agentsight_config_set_verbose(AgentsightConfigHandle* cfg, int verbose);
void agentsight_config_set_log_path(AgentsightConfigHandle* cfg, const char* path);
void agentsight_config_set_cmdline_pattern(AgentsightConfigHandle* cfg, const char* const* patterns, const char* agent_name, int allow);
void agentsight_config_set_domain_pattern(AgentsightConfigHandle* cfg, const char* pattern);
int agentsight_config_load_file(AgentsightConfigHandle* cfg, const char* path);
void agentsight_config_free(AgentsightConfigHandle* cfg);

/* ---- 回调类型 ---- */
typedef void (*agentsight_https_callback_fn)(const AgentsightHttpsData* data, void* user_data);
typedef void (*agentsight_llm_callback_fn)(const AgentsightLLMData* data, void* user_data);

/* ---- 生命周期 ---- */
AgentsightHandle* agentsight_new(AgentsightConfigHandle* cfg);
int agentsight_start(AgentsightHandle* h);
int agentsight_stop(AgentsightHandle* h);
void agentsight_free(AgentsightHandle* h);
const char* agentsight_version(void);

/* ---- 事件通知 ---- */
/* 获取 eventfd 文件描述符，可注册到调用方的 epoll/select 事件循环。
 * 当有新事件就绪时，该 fd 变为可读（EPOLLIN）。
 * 返回 >= 0 的 fd 表示成功，< 0 表示不支持（可降级为轮询模式）。
 * 注意：该 fd 由 AgentSight 内部管理，调用方不得 close()。 */
int agentsight_get_eventfd(AgentsightHandle* h);

/* ---- 数据读取 ---- */
/* 处理当前可用事件，通过回调返回数据。返回处理事件数，0=无事件，<0=出错。
 * 两个回调独立，传 NULL 表示不关心该类型。
 * flags: 0 = 非阻塞（处理当前队列后立即返回）
 *        AGENTSIGHT_READ_BLOCK = 阻塞直到有至少一个事件 */
#define AGENTSIGHT_READ_BLOCK 1
int agentsight_read(AgentsightHandle* h,
                    agentsight_https_callback_fn http_cb, void* http_ud,
                    agentsight_llm_callback_fn  llm_cb,  void* llm_ud,
                    int flags);
```

### 2.1 返回值

| 函数 | 返回值 | 说明 |
| --- | --- | --- |
| `agentsight_config_new` | `AgentsightConfigHandle*` | 成功返回句柄，失败返回 NULL |
| `agentsight_new` | `AgentsightHandle*` | 成功返回句柄，失败返回 NULL（可用 `agentsight_last_error` 查看原因） |
| `agentsight_start` | `int` | 0=成功，<0=失败 |
| `agentsight_stop` | `int` | 0=成功，<0=失败 |
| `agentsight_get_eventfd` | `int` | >= 0 为有效 fd，< 0 表示不支持 eventfd |
| `agentsight_read` | `int` | \>0=处理的事件数，0=无事件，<0=出错 |
| `agentsight_last_error` | `const char*` | 错误描述字符串，无错误时返回 NULL |
| `agentsight_version` | `const char*` | 版本号字符串（如 `"0.2.2"`），静态存储，无需释放 |
| `agentsight_config_set_cmdline_pattern` | `void` | cfg 或 patterns 为 NULL 时静默忽略 |
| `agentsight_config_set_domain_pattern` | `void` | cfg 或 pattern 为 NULL 时静默忽略 |
| `agentsight_config_load_file` | `int` | 0=成功，<0=失败（文件不存在或解析错误） |

### 2.2 线程安全

* 同一 `AgentsightHandle` 不可多线程并发调用，所有 API（start/read/stop）须在同一线程执行
* 回调函数在调用 `agentsight_read()` 的线程上同步执行，无需额外同步
* 不同 `AgentsightHandle` 实例之间完全独立，可跨线程使用
* `agentsight_get_eventfd()` 返回的 fd 可安全地在其他线程中用于 epoll/select 等待

## 3. 配置

### 3.1 配置默认值

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `verbose` | 0 | 设为 1 开启调试日志输出 |
| `log_path` | NULL | 日志文件保存路径，NULL 时输出到 stderr |
| `cmdline_patterns` | 空 | 用户自定义规则列表；allow=1 为进程白名单，allow=0 为域名黑名单 |
| `domain_patterns` | 空（不过滤） | 域名白名单规则列表，默认为空表示不添加白名单 |

### 3.2 Cmdline Pattern 配置

通过 `agentsight_config_set_cmdline_pattern()` 可添加用户自定义的匹配规则。`allow=1` 时添加进程匹配规则（匹配到的进程将被 attach SSL probe 并抓取 HTTPS 数据）；`allow=0` 时添加域名黑名单规则（已追踪进程访问黑名单域名时事件被丢弃）。

#### 函数签名

```c
void agentsight_config_set_cmdline_pattern(
    AgentsightConfigHandle* cfg,
    const char* const* patterns,
    const char* agent_name,
    int allow
);
```

#### 参数说明

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cfg` | `AgentsightConfigHandle*` | 配置句柄，为 NULL 时静默忽略 |
| `patterns` | `const char* const*` | NULL 结尾的 C 字符串指针数组 |
| `agent_name` | `const char*` | allow=1 时匹配成功使用的 agent 名称；allow=0 时忽略（传 NULL） |
| `allow` | `int` | 1=进程匹配规则（patterns 为 cmdline glob），0=域名黑名单（patterns 为域名 glob） |

#### allow=1：进程匹配

patterns 为 cmdline glob 通配符数组，按位置一一对应做前缀匹配：

- **按位置一一对应（前缀匹配）**：`patterns[i]` 对 `cmdline[i]` 做 glob 匹配
- **大小写不敏感**：所有 glob 匹配均忽略大小写
- **patterns 比 cmdline 短**：忽略多余的 cmdline 元素（前缀匹配成功）
- **cmdline 比 patterns 短**：不匹配（参数不够）
- **跳过不关心的位置**：用 `"*"` 作为通配，匹配该位置的任意值

#### allow=0：域名黑名单

patterns 为域名 glob 通配符数组，已追踪进程访问匹配的域名时事件被丢弃：

- **Glob 通配符**：支持 `*`（匹配任意字符序列）和 `?`（匹配单个字符）
- **大小写不敏感**：域名匹配忽略大小写
- **在 SNI 事件阶段评估**：仅对已追踪进程产生的事件生效
- **与 domain_pattern 白名单为 AND 关系**：域名必须在白名单中且不在黑名单中，才 attach

#### 示例

```c
/* 匹配 Claude Code 进程 (allow=1) */
const char* pats[] = {"node", "*claude*", NULL};
agentsight_config_set_cmdline_pattern(cfg, pats, "Claude Code", 1);

/* 匹配 Aider 进程 (allow=1) */
const char* pats2[] = {"*", "*aider*", NULL};
agentsight_config_set_cmdline_pattern(cfg, pats2, "Aider", 1);

/* 域名黑名单 (allow=0)：过滤噪音域名 */
const char* deny[] = {"*.sentry.io", "*.npmjs.org", NULL};
agentsight_config_set_cmdline_pattern(cfg, deny, NULL, 0);
```

### 3.3 Domain Pattern 配置

通过 `agentsight_config_set_domain_pattern()` 可配置域名白名单规则，命中即放行，与 Cmdline Pattern 为 OR 关系。

#### 设计动机

用户可能关心特定域名的流量（如 LLM API 域名），无论访问该域名的进程是否匹配 cmdline pattern。Domain Pattern 提供域名级别的白名单能力：只要域名命中白名单，事件即放行。

#### 函数签名

```c
void agentsight_config_set_domain_pattern(
    AgentsightConfigHandle* cfg,
    const char* pattern
);
```

#### 参数说明

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `cfg` | `AgentsightConfigHandle*` | 配置句柄，为 NULL 时静默忽略 |
| `pattern` | `const char*` | 域名 glob 模式（支持 `*`/`?`），为 NULL 时静默忽略 |

#### 行为语义

- **不调用**：不添加任何白名单规则，所有 SNI 事件均不 attach SSL 探针
- **调用一次或多次**：域名必须命中任一 pattern 才会 attach（前提是不被黑名单排除）
- **多次调用叠加**：规则之间为 OR 关系，不覆盖已有规则

#### 多次调用叠加

- 多次调用不覆盖，规则持续累加
- 同类规则之间为 OR 关系，任一匹配即命中

#### 匹配规则

- **匹配对象**：HTTP 请求的目标域名（从 `Host` header 或 URL 中提取，不含端口号）
- **Glob 通配符**：支持 `*`（匹配任意字符序列）和 `?`（匹配单个字符）
- **大小写不敏感**：域名匹配忽略大小写
- **对 LLMData 和 HttpsData 均生效**：LLMData 从 `request_url` 提取域名，HttpsData 从请求 headers 中的 `Host` 提取

#### 域名提取逻辑

```
request_url = "https://api.openai.com/v1/chat/completions"
                       ^^^^^^^^^^^^^^
                       提取此部分作为匹配目标

Host: api.anthropic.com:443
      ^^^^^^^^^^^^^^^^^^^
      去除端口号后匹配: "api.anthropic.com"
```

#### 示例

```c
AgentsightConfigHandle* cfg = agentsight_config_new();

/* 追踪 Claude Code 进程 (cmdline allow=1) */
const char* pats[] = {"node", "*claude*", NULL};
agentsight_config_set_cmdline_pattern(cfg, pats, "Claude Code", 1);

/* 域名黑名单 (cmdline allow=0)：过滤噪音域名 */
const char* deny[] = {"*.sentry.io", "*.npmjs.org", NULL};
agentsight_config_set_cmdline_pattern(cfg, deny, NULL, 0);

/* 域名白名单：无论哪个进程，访问这些域名就输出 */
agentsight_config_set_domain_pattern(cfg, "*.openai.com");
agentsight_config_set_domain_pattern(cfg, "*.anthropic.com");

AgentsightHandle* h = agentsight_new(cfg);
agentsight_config_free(cfg);
agentsight_start(h);
```

上述配置效果：
- Claude 进程访问 `api.openai.com` → attach（命中白名单，不在黑名单）
- Claude 进程访问 `o123.ingest.sentry.io` → 不 attach（命中黑名单，被排除）
- Claude 进程访问 `example.com` → 不 attach（未命中白名单）
- 非追踪进程访问任意域名 → 无事件（进程未被追踪，无 SNI 监控）

### 3.4 TOML 配置文件

除了通过 C API 逐条配置，也可通过 TOML 文件一次性加载所有 pattern 规则。

#### C API

```c
/* 从 TOML 文件加载 pattern 配置，追加到已有规则中。
 * 返回 0=成功，<0=失败（文件不存在或解析错误，可用 agentsight_last_error() 查看）。 */
int agentsight_config_load_file(AgentsightConfigHandle* cfg, const char* path);
```

#### 文件格式

```toml
# /etc/agentsight/config.toml

# --- 通用配置 ---
[general]
verbose = 1
log_path = "/var/log/agentsight.log"

# --- 进程匹配规则（cmdline allow=1）---
[[cmdline.allow]]
patterns = ["node", "*claude*"]
agent_name = "Claude Code"

[[cmdline.allow]]
patterns = ["*", "*aider*"]
agent_name = "Aider"

[[cmdline.allow]]
patterns = ["python3", "*my_agent*"]
agent_name = "My Agent"

# --- 域名黑名单（cmdline allow=0）---
[[cmdline.deny]]
patterns = ["*.sentry.io", "*.sentry-cdn.com"]

[[cmdline.deny]]
patterns = ["*.npmjs.org", "registry.npmmirror.com"]

# --- 域名白名单（domain_pattern）---
[[domain]]
patterns = ["*.openai.com", "*.anthropic.com"]

[[domain]]
patterns = ["*.deepseek.com", "generativelanguage.googleapis.com"]
```

#### 字段说明

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `general.verbose` | int (可选) | 1=开启调试日志，0=关闭，默认 0 |
| `general.log_path` | string (可选) | 日志文件路径，省略时输出到 stderr |
| `cmdline.allow[].patterns` | string array | cmdline glob 数组，按位置一一匹配 |
| `cmdline.allow[].agent_name` | string | 匹配成功时的 agent 名称 |
| `cmdline.deny[].patterns` | string array | 域名 glob 数组，匹配到的域名事件被丢弃 |
| `domain[].patterns` | string array | 域名白名单 glob 数组，命中即放行 |

#### 加载行为

- `agentsight_config_load_file()` 将文件中的规则**追加**到已有配置，不清空之前通过 C API 添加的规则
- 可多次调用加载多个文件，规则持续累加
- 文件不存在或解析失败时返回 `<0`，不影响已有配置

#### 使用示例

```c
AgentsightConfigHandle* cfg = agentsight_config_new();
agentsight_config_set_verbose(cfg, 1);

/* 从文件加载 pattern 规则 */
if (agentsight_config_load_file(cfg, "/etc/agentsight/config.toml") < 0) {
    fprintf(stderr, "load config failed: %s\n", agentsight_last_error());
}

/* 也可继续通过 API 追加规则 */
agentsight_config_set_domain_pattern(cfg, "*.my-custom-llm.com");

AgentsightHandle* h = agentsight_new(cfg);
agentsight_config_free(cfg);
agentsight_start(h);
```

### 3.5 匹配判定逻辑

匹配分为两个阶段：

#### 阶段一：进程创建时

当新进程创建时，检查 cmdline_allow 规则：

```
进程被追踪 = cmdline_allow匹配(进程)
```

匹配成功则 attach SSL 探针，开始捕获该进程的 HTTPS 流量。

#### 阶段二：SNI 事件到达时

当被追踪进程产生 SNI 事件时，按以下条件判定是否 attach SSL 探针：

```
attach_ssl = domain_pattern匹配(域名) AND NOT cmdline_deny匹配(域名)
```

流程图：

```
SNI 事件到达（来自已追踪进程）
  │
  ├─ 域名命中 domain_pattern 白名单？── 否 ──→ ❌ 不 attach
  │
  ├─ 域名命中 cmdline_deny 黑名单？─── 是 ──→ ❌ 不 attach
  │
  └─ 通过 ─────────────────────────────────→ ✅ attach SSL 探针，捕获 HTTPS 数据
```

关键语义：
- **cmdline_allow 决定追踪哪些进程**：仅在进程创建时评估一次，匹配后监控其 SNI 事件
- **domain_pattern 白名单是前置条件**：域名必须命中白名单才有资格 attach
- **cmdline_deny 黑名单是排除条件**：即使命中白名单，黑名单也能排除
- **都不配置**：不追踪任何进程，无事件输出

## 4. 使用示例

完整示例程序见 `tools/examples/agentsight/agentsight_example.c`。

### 4.1 eventfd + epoll 模式（推荐）

```c
/* --- 初始化阶段 --- */
AgentsightConfigHandle* cfg = agentsight_config_new();
agentsight_config_set_verbose(cfg, 1);

AgentsightHandle* h = agentsight_new(cfg);
agentsight_config_free(cfg);

if (!h) {
    fprintf(stderr, "agentsight_new failed: %s\n", agentsight_last_error());
    return -1;
}

agentsight_start(h);

/* 获取 eventfd，注册到统一 epoll */
int as_efd = agentsight_get_eventfd(h);
if (as_efd < 0) {
    fprintf(stderr, "eventfd not supported, fallback to polling\n");
    /* 降级到轮询模式，见 3.2 */
}

int epoll_fd = epoll_create1(0);
struct epoll_event ev = {
    .events   = EPOLLIN,
    .data.fd  = as_efd,
};
epoll_ctl(epoll_fd, EPOLL_CTL_ADD, as_efd, &ev);

/* --- 事件循环 --- */
while (running) {
    struct epoll_event events[64];
    int n = epoll_wait(epoll_fd, events, 64, 500 /* ms */);

    for (int i = 0; i < n; i++) {
        if (events[i].data.fd == as_efd) {
            agentsight_read(h, on_https_event, NULL,
                               on_llm_event,   NULL,
                               0 /* non-blocking */);
        }
    }
}

/* --- 清理阶段 --- */
epoll_ctl(epoll_fd, EPOLL_CTL_DEL, as_efd, NULL);
agentsight_stop(h);
agentsight_free(h);  /* 内部 close(as_efd)，调用方不得重复 close */
close(epoll_fd);
```

### 4.2 轮询模式（降级 / 简单场景）

```c
AgentsightConfigHandle* cfg = agentsight_config_new();
AgentsightHandle* h = agentsight_new(cfg);
agentsight_config_free(cfg);

if (!h) {
    fprintf(stderr, "agentsight_new failed: %s\n", agentsight_last_error());
    return -1;
}

agentsight_start(h);

while (running) {
    agentsight_read(h, my_http_cb, http_ctx,
                       my_llm_cb,  llm_ctx,
                       0 /* non-blocking */);
    usleep(100000);  // 100ms 轮询间隔
}

agentsight_stop(h);
agentsight_free(h);
```

## 5. 内存规则

* 回调中的指针仅在回调执行期间有效，调用方需自行拷贝
* `agentsight_new()` 内部拷贝配置，不消费 config handle，调用者须自行 `agentsight_config_free(cfg)`
* 同一 config handle 可复用于创建多个 `AgentsightHandle` 实例
* `agentsight_free()` 须在 `agentsight_stop()` 之后调用
* `agentsight_get_eventfd()` 返回的 fd 由 `agentsight_free()` 内部关闭，调用方**不得**自行 `close()`

## 6. HttpsData 与 LLMData 的关系

一条被捕获的 HTTPS 流量只会产生一种数据：若被识别为 LLM API 调用，则产生 `AgentsightLLMData`；否则产生 `AgentsightHttpsData`。两者互斥，不会同时产生，无需关联。

## 7. 编译与链接

### 7.1 从源码构建（CMake 集成）

AgentSight 已集成到 coolbpf 的 CMake 构建系统中，通过 `ENABLE_AGENTSIGHT` 选项控制：

```bash
# 构建 libagentsight（不含 server/Dashboard，无需 Node.js）
mkdir -p build && cd build
cmake -DENABLE_AGENTSIGHT=on ..
make libagentsight

# 同时构建 C 示例程序
cmake -DENABLE_AGENTSIGHT=on -DBUILD_EXAMPLE=on ..
make agentsight_example

# 安装
make install
```

CMake 选项说明：

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `ENABLE_AGENTSIGHT` | OFF | 构建AgentSight FFI 库（`libagentsight.so` + `agentsight.h`） |

构建产物：

| 文件 | 安装路径 | 说明 |
| --- | --- | --- |
| `libagentsight.so` | `${prefix}/lib/` | C FFI 共享库 |
| `agentsight.h` | `${prefix}/include/` | C 头文件（cbindgen 自动生成） |

### 7.2 链接

```bash
gcc -I/usr/local/include -L/usr/local/lib -lagentsight -o myapp myapp.c
```

### 7.3 独立构建（含 Dashboard）

如需构建完整的 AgentSight（含嵌入式 Web Dashboard），使用 `src/agentsight/Makefile`：

```bash
cd src/agentsight
make build-all          # 构建前端 + Rust 二进制
make install            # 安装 agentsight CLI
```

## 8. 变更记录

| 版本 | 变更 |
| --- | --- |
| v0.1 | 初始版本，轮询 read 模式 |
| v0.2 | 升级为 eventfd + read 模式；新增 `agentsight_get_eventfd()`；`agentsight_read()` 增加 `flags` 参数；新增 `agentsight_config_set_log_path()`；大 buffer 指针增加 `_len` 字段；新增 `llm_usage` 字段区分 token 数据来源 |
| v0.2.1 | 集成 CMake 构建系统（`ENABLE_AGENTSIGHT` 选项）；新增 C 示例程序 `tools/examples/agentsight/`；新增 `cbindgen.toml` 自动生成完整 C 头文件；新增 FFI API 文档 |
| v0.3 | `agentsight_config_set_cmdline_pattern()` 新增 `allow` 参数：allow=1 为进程匹配规则，allow=0 为域名黑名单 |
| v0.4 | 新增 `agentsight_config_set_domain_pattern()` 接口，支持域名白名单；与 cmdline pattern 形成 OR 匹配逻辑；新增 `agentsight_config_load_file()` 支持 TOML 配置文件加载 |
