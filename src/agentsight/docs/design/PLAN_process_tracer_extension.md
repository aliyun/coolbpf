# AgentSight 增强计划：扩展 process tracer

## 硬性约束（实现时必须遵守）

1. **现有文件不修改**——`process.bpf.c`、`process.c`、`process.h`、`process_utils.h`、`process_filter.h` 完全不动。新功能通过独立的 `process_new` 程序实现
2. **现有 JSON 输出格式不可变**——EXEC/EXIT/FILE_OPEN/BASH_READLINE 的字段名、字段顺序、值类型必须与当前 process.c 输出完全一致。任何消费者（Rust collector、分析脚本）不应因升级而 break
3. **新增 SUMMARY 事件必须遵循现有字段约定**：
   - 字段顺序：`timestamp`（纳秒）→ `event` → `comm` → `pid` → 类型特定字段
   - `timestamp` 使用 `bpf_ktime_get_ns()` 纳秒值（与现有事件一致），不是秒或毫秒
   - `event` 字段统一为 `"SUMMARY"`，用 `type` 子字段区分具体事件类型
4. **process_new 默认行为与 process 完全一致**——不加新 flag 时，输出、性能、CLI 行为相同
5. **struct event 不变**——新事件不使用 struct event 结构体，不经过 ring buffer
6. **新增头文件统一放 `bpf/process_ext/` 子目录**——不污染 `bpf/` 顶层目录（注：最初设计为 `process_new/`，因与二进制同名冲突已改为 `process_ext/`）

## 背景

Branch context 论文需要证明 AI agent 的探索路径会产生**多维状态副作用**（文件系统、网络、进程、环境），而现有机制无法统一回滚。AgentSight 现有的 `process` tracer 只追踪了文件打开和进程生命周期，缺少文件删除/重命名、网络端口、进程组变更等关键数据。

**方案**：新建独立的 `process_new` 程序（`process_new.bpf.c` + `process_new.c`），复用现有 `process` 的核心逻辑（ring buffer 事件、PID 过滤等），新增 BPF map 聚合能力。现有 `process.bpf.c` / `process.c` **完全不动**，避免引入回归 bug。

### 开发策略约束

1. **现有 `process.bpf.c` 和 `process.c` 不修改**——确保已有功能零回归风险
2. **`process_new` 是独立的编译目标**——`make process_new` 单独构建，不影响 `make process`
3. **新增头文件统一放在 `bpf/process_ext/` 子目录**——BPF 侧和用户空间侧的模块化头文件集中管理，不污染 `bpf/` 顶层
4. **`process_new` 复制必要的现有代码**——不通过 `#include "process.bpf.c"` 复用，而是直接复制 handle_exec/handle_exit 等 handler + 需要的工具函数。代价是少量代码重复，换来两个程序完全解耦
5. **未来合并可选**——当 `process_new` 稳定后，可以考虑替换 `process`，但不是必须的

### 为什么不改现有文件

| | 修改现有 process | 新建 process_new |
|---|---|---|
| 回归风险 | ❌ 高——改动 process.bpf.c 700+ 行可能引入 bug | ✅ 零——现有代码不动 |
| 调试难度 | ❌ 新旧逻辑交织 | ✅ 新代码独立，bug 定位简单 |
| 渐进开发 | ❌ 每步都要保证不破坏现有行为 | ✅ 新程序可以自由迭代 |
| 代码重复 | ✅ 无重复 | ❌ 少量重复（handle_exec 等基础 handler） |
| 构建/测试 | ❌ 共用一个目标，改动牵一发动全身 | ✅ 独立目标，互不影响 |

## 当前 process tracer 的能力

```
现有事件类型：
├── EVENT_TYPE_PROCESS (EXEC/EXIT)     ← tp/sched/sched_process_exec, sched_process_exit
├── EVENT_TYPE_BASH_READLINE           ← uretprobe//usr/bin/bash:readline
└── EVENT_TYPE_FILE_OPERATION          ← tp/syscalls/sys_enter_openat, sys_enter_open
```

## 核心设计原则：全部追踪，统一内核聚合

**所有新增事件统一走 BPF hash map 内核聚合**，不经过 ring buffer。

- Ring buffer **只给现有事件**（EXEC/EXIT/FILE_OPEN/BASH_READLINE）——已验证稳定
- 所有新增事件在内核侧按合适的 key 粒度聚合计数
- 用户空间定时（每 N 秒）遍历 map → flush 为 summary JSON
- 低频事件（setsid、bind）自然 count=1，等价于逐条 report，不需要特殊路径

**一条路径，零例外。**

### 统一聚合 map 设计

所有新事件共用一个 `event_agg_map`：

```c
/*
 * 统一的聚合 key：按 (pid, event_type, detail) 分组
 * detail 的含义随 event_type 变化：
 *   FS mutations:  dir_prefix（父目录路径前缀）
 *   Write:         fd（文件描述符）
 *   Network:       addr:port（远端/本地地址+端口）
 *   Signals:       target_pid + signal（目标进程+信号）
 *   Pgrp/Session:  new_pgid / new_sid
 *   Fork:          （空，按 pid 聚合子进程数量）
 *   Mmap:          fd
 *   Chdir:         path
 */

#define DETAIL_LEN 64

struct agg_key {
    u32 pid;
    u32 event_type;
    char detail[DETAIL_LEN];    // 语义随 event_type 变化
};

struct agg_value {
    u64 count;
    u64 total_bytes;            // 仅 write/mmap 使用，其余为 0
    u64 first_ts;
    u64 last_ts;
    char comm[TASK_COMM_LEN];   // 最后一次操作的进程名（flush 时输出）
    char extra[MAX_FILENAME_LEN];  // 最后一次操作的额外信息（完整路径/new_path 等）
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct agg_key);
    __type(value, struct agg_value);
} event_agg_map SEC(".maps");
```

### 各事件类型的 key 设计

| 事件 | event_type | detail 内容 | extra 内容 | 典型 count |
|------|-----------|-------------|-----------|-----------|
| FILE_DELETE | 10 | dir_prefix（`/testbed/venv/lib`） | last_path | 高（rm -rf） |
| FILE_RENAME | 11 | new_path 的 dir_prefix | old_path:new_path | 高（pip install） |
| DIR_CREATE | 12 | parent_dir | last_dirpath | 高（pip install） |
| FILE_TRUNCATE | 13 | fd（sprintf） | — | 低 |
| CHDIR | 14 | path | — | 极低 |
| WRITE | 15 | fd（sprintf） | — | 极高 |
| NET_BIND | 20 | `addr:port`（`0.0.0.0:8080`） | — | 极低（1-2） |
| NET_LISTEN | 21 | fd（sprintf） | — | 极低 |
| NET_CONNECT | 22 | `addr:port`（`api.anthropic.com:443`） | — | 中（API 调用） |
| PGRP_CHANGE | 30 | `pid:pgid`（`1234:5678`） | — | 极低 |
| SESSION_CREATE | 31 | `sid`（`1234`） | — | 极低 |
| SIGNAL_SEND | 32 | `target:sig`（`5678:9`） | — | 低 |
| PROC_FORK | 33 | 空或 `child_pid` | — | 中 |
| MMAP_SHARED | 40 | fd（sprintf） | — | 中 |
| COW_FAULT | 41 | 空（按 pid 聚合） | — | 极高（fork 后） |

### Flush 输出格式

用户空间每 5 秒遍历 map，对每个非零条目输出一行 JSON：

```jsonl
// 高频事件 → 高 count，按目录聚合（字段顺序：timestamp → event → comm → pid → type → ...，与现有事件一致）
{"timestamp":260000000000,"event":"SUMMARY","comm":"pip","pid":1234,"type":"DIR_CREATE","detail":"/testbed/venv/lib/requests","count":47,"extra":"/testbed/venv/lib/requests/utils"}
{"timestamp":260000000000,"event":"SUMMARY","comm":"pip","pid":1234,"type":"FILE_RENAME","detail":"/testbed/venv/lib","count":203,"extra":"/testbed/venv/lib/urllib3/response.py"}
{"timestamp":260000000000,"event":"SUMMARY","comm":"pip","pid":1234,"type":"WRITE","detail":"fd=5","count":1847,"total_bytes":4521984,"extra":"/testbed/venv/lib/requests/api.py"}

// 低频事件 → count=1，等价于逐条
{"timestamp":260000000000,"event":"SUMMARY","comm":"python","pid":5678,"type":"NET_BIND","detail":"0.0.0.0:8080","count":1}
{"timestamp":260000000000,"event":"SUMMARY","comm":"kill","pid":1234,"type":"SIGNAL_SEND","detail":"5678:9","count":1}
{"timestamp":260000000000,"event":"SUMMARY","comm":"bash","pid":1234,"type":"SESSION_CREATE","detail":"sid=1234","count":1}
```

**关键**：消费者不需要关心 count 是 1 还是 1000——格式统一，逻辑统一。

## 新增事件类型

```
新增事件类型（全部走 BPF map 内核聚合，通过 feature flags 控制）：
│
├── --trace-fs（文件系统 mutations）
│   ├── FILE_DELETE                     ← tp/syscalls/sys_enter_unlinkat
│   ├── FILE_RENAME                     ← tp/syscalls/sys_enter_renameat2
│   ├── DIR_CREATE                      ← tp/syscalls/sys_enter_mkdirat
│   ├── WRITE (bytes+count)             ← tp/syscalls/sys_enter_write + sys_exit_write
│   ├── FILE_TRUNCATE                   ← tp/syscalls/sys_enter_ftruncate
│   └── CHDIR                           ← tp/syscalls/sys_enter_chdir
│
├── --trace-net（网络状态）
│   ├── NET_BIND                        ← tp/syscalls/sys_enter_bind
│   ├── NET_LISTEN                      ← tp/syscalls/sys_enter_listen
│   └── NET_CONNECT                     ← tp/syscalls/sys_enter_connect
│
├── --trace-signals（进程协调）
│   ├── PGRP_CHANGE                     ← tp/syscalls/sys_enter_setpgid
│   ├── SESSION_CREATE                  ← tp/syscalls/sys_enter_setsid
│   ├── SIGNAL_SEND                     ← tp/syscalls/sys_enter_kill
│   └── PROC_FORK                       ← tp/sched/sched_process_fork
│
├── --trace-mem（内存/共享状态）
│   └── MMAP_SHARED                     ← tp/syscalls/sys_enter_mmap（内核侧过滤仅 MAP_SHARED）
│
└── --trace-cow（CoW page fault 追踪，用于内存重叠分析）
    └── COW_FAULT                       ← kprobe/do_wp_page（或 tp/exceptions/page_fault_user）

附加用户空间增强（不需要新 BPF 程序）：
└── per-process 内存采集              ← 在 EXEC/EXIT handle_event 中读 /proc/pid/statm + /proc/pid/status

所有事件统一路径：tracepoint → BPF map 计数 → 用户空间定时 flush → JSON summary
```

## 关键设计

### 1. 零开销特性开关

在 BPF 侧用 `const volatile` 变量控制，JIT 编译后禁用的分支直接被优化掉：

```c
// process_new.bpf.c
const volatile bool trace_fs_mutations = false;   // --trace-fs
const volatile bool trace_network = false;         // --trace-net
const volatile bool trace_signals = false;         // --trace-signals
const volatile bool trace_memory = false;          // --trace-mem
const volatile bool trace_cow = false;             // --trace-cow

SEC("tp/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    if (!trace_fs_mutations)       // ← JIT 优化为 nop
        return 0;
    // ... 正常处理
}
```

用户空间在 load skeleton 后、attach 前设置：

```c
// process_new.c
skel->rodata->trace_fs_mutations = env.trace_fs;
skel->rodata->trace_network = env.trace_net;
skel->rodata->trace_signals = env.trace_signals;
skel->rodata->trace_memory = env.trace_mem;
```

**结果**：不加新 flag → 行为完全不变、性能完全不变。

### 1.5 BPF 侧 PID 过滤（防止 map 污染）

现有 process tracer 的 PID 过滤在用户空间做（ring buffer 回调中检查 pid_tracker）。但对 BPF map 聚合事件，**不在 BPF 侧过滤的话 map 会被无关进程的数据填满**（max_entries=8192 很快耗尽）。

**方案**：新增一个 BPF hash map `tracked_pids`，用户空间在检测到新进程（EXEC 事件）时将 pid 写入 map；进程退出时删除。所有新 BPF handler 在聚合前先查这个 map：

```c
// process_new.bpf.c
const volatile bool filter_pids = false;  // 仅在 -c/-p 模式下启用

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TRACKED_PIDS);
    __type(key, u32);   /* pid */
    __type(value, u8);  /* dummy, 存在即 tracked */
} tracked_pids SEC(".maps");

static __always_inline bool is_pid_tracked(void)
{
    if (!filter_pids) return true;  // 无过滤模式（-m 0）追踪所有进程
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    return bpf_map_lookup_elem(&tracked_pids, &pid) != NULL;
}
```

**用户空间维护**（process_new.c handle_event）：

```c
case EVENT_TYPE_PROCESS:
    if (!e->exit_event) {
        // EXEC：如果通过 comm 过滤，加入 tracked_pids
        if (should_track_pid(tracker, e->pid, e->comm)) {
            u8 val = 1;
            bpf_map_update_elem(bpf_map__fd(skel->maps.tracked_pids),
                                &e->pid, &val, BPF_ANY);
        }
    } else {
        // EXIT：从 tracked_pids 移除
        bpf_map_delete_elem(bpf_map__fd(skel->maps.tracked_pids), &e->pid);
    }
```

**为什么不直接在 BPF 侧匹配 comm**：现有 process tracer 的 comm 匹配逻辑在用户空间（支持多个 -c 参数、子进程继承追踪等复杂语义），搬到 BPF 侧会增加复杂度。用 tracked_pids map 做桥梁，用户空间决策、BPF 侧执行，职责清晰。

**代价**：EXEC 到用户空间决策再到 BPF map 更新有微秒级延迟，新进程的前几次 syscall 可能漏掉。对于聚合统计场景，这个误差可忽略。

### 2. write() 的 BPF map 内核聚合

write/pwrite64 每秒可达数万次。使用**统一 event_agg_map** 聚合，`detail` 字段存 `"fd=N"`。

需要额外的 `write_fd_map` 暂存 enter 阶段的 fd（配对 enter/exit syscall）——这不是聚合 map，是临时上下文：

```c
/* write_fd_map：暂存 enter 阶段的 fd，exit 阶段查找后删除。非聚合用途。 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);  /* pid_tgid */
    __type(value, int); /* fd from enter */
} write_fd_map SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx) {
    if (!trace_fs_mutations) return 0;
    if (!is_pid_tracked()) return 0;    // BPF 侧 PID 过滤（见第 1.5 节）
    u64 id = bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    bpf_map_update_elem(&write_fd_map, &id, &fd, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_write")
int trace_write_exit(struct trace_event_raw_sys_exit *ctx) {
    if (!trace_fs_mutations) return 0;
    long ret = ctx->ret;
    if (ret <= 0) return 0;

    u64 id = bpf_get_current_pid_tgid();
    int *fd_ptr = bpf_map_lookup_elem(&write_fd_map, &id);
    if (!fd_ptr) return 0;

    // 使用统一 event_agg_map，detail = "fd=N"
    struct agg_key key = { .pid = id >> 32, .event_type = EVENT_TYPE_WRITE };
    // BPF 中不能用 snprintf，用固定格式写入 "fd=N"
    bpf_snprintf(key.detail, sizeof(key.detail), "fd=%d", fd_ptr, sizeof(int));  // "fd=5"
    bpf_map_delete_elem(&write_fd_map, &id);

    update_agg_map(&key, 1, (u64)ret);  // count=1, bytes=ret
    return 0;
}
```

fd→path 解析在用户空间 flush 时做：读 `/proc/<pid>/fd/<fd>` 符号链接（进程存活时有效），填入 SUMMARY JSON 的 `extra` 字段。

### 3. 文件系统 mutations 的 BPF map 内核聚合

FILE_DELETE、FILE_RENAME、DIR_CREATE 同样使用**统一 event_agg_map**，`detail` 字段存目录前缀：

```c
SEC("tp/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    if (!trace_fs_mutations) return 0;
    if (!is_pid_tracked()) return 0;

    char filepath[MAX_FILENAME_LEN];
    bpf_probe_read_user_str(filepath, sizeof(filepath), (const char *)ctx->args[1]);

    struct agg_key key = { .pid = bpf_get_current_pid_tgid() >> 32, .event_type = EVENT_TYPE_FILE_DELETE };
    extract_dir_prefix(filepath, key.detail, sizeof(key.detail));

    // 统一聚合更新
    struct agg_value *val = bpf_map_lookup_elem(&event_agg_map, &key);
    if (val) {
        __sync_fetch_and_add(&val->count, 1);
        val->last_ts = bpf_ktime_get_ns();
        bpf_probe_read_kernel_str(val->extra, sizeof(val->extra), filepath);
    } else {
        u64 now = bpf_ktime_get_ns();
        struct agg_value new_val = { .count = 1, .first_ts = now, .last_ts = now };
        bpf_get_current_comm(new_val.comm, sizeof(new_val.comm));
        bpf_probe_read_kernel_str(new_val.extra, sizeof(new_val.extra), filepath);
        bpf_map_update_elem(&event_agg_map, &key, &new_val, BPF_ANY);
    }
    return 0;
}
// renameat2, mkdirat 同理
```

### extract_dir_prefix 实现

在 BPF 中提取路径的父目录前缀（截断到最后一个 `/`）。BPF verifier 要求固定上界循环：

```c
// process_ext/bpf_fs.h
static __always_inline void extract_dir_prefix(const char *path, char *out, int out_len)
{
    int last_slash = 0;

    // BPF verifier 要求固定上界循环
    #pragma unroll
    for (int i = 0; i < DETAIL_LEN - 1; i++) {
        if (path[i] == '\0') break;
        if (path[i] == '/') last_slash = i;
        out[i] = path[i];
    }

    // 截断到最后一个 '/'
    if (last_slash > 0)
        out[last_slash] = '\0';
}
```

**优点**（vs 用户空间 dedup）：
- `pip install` 创建 3000 个文件时，ring buffer 零事件（全在 map 里），不会丢失
- 用户空间 dedup 在高频场景下可能来不及处理导致 ring buffer 溢出
- 内核聚合按目录前缀分组，直接得到"哪个目录变化最多"的分布信息

### update_agg_map 通用辅助函数

所有新事件共用一个聚合更新逻辑，抽为 BPF inline helper：

```c
// process_ext/bpf_common.h
static __always_inline void update_agg_map(struct agg_key *key, u64 count, u64 bytes)
{
    struct agg_value *val = bpf_map_lookup_elem(&event_agg_map, key);
    if (val) {
        __sync_fetch_and_add(&val->count, count);
        if (bytes)
            __sync_fetch_and_add(&val->total_bytes, bytes);
        val->last_ts = bpf_ktime_get_ns();
    } else {
        u64 now = bpf_ktime_get_ns();
        struct agg_value new_val = {
            .count = count, .total_bytes = bytes,
            .first_ts = now, .last_ts = now
        };
        bpf_get_current_comm(new_val.comm, sizeof(new_val.comm));
        bpf_map_update_elem(&event_agg_map, key, &new_val, BPF_ANY);
    }
}
```

### 4. mmap(MAP_SHARED) 的内核侧过滤

mmap 调用频率高，但只有 `MAP_SHARED` 的才涉及跨进程共享状态。在 BPF 侧过滤：

```c
SEC("tp/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx) {
    if (!trace_memory) return 0;
    if (!is_pid_tracked()) return 0;
    int flags = (int)ctx->args[3];
    if (!(flags & 0x01))  // MAP_SHARED = 0x01
        return 0;         // 跳过 MAP_PRIVATE

    int fd = (int)ctx->args[4];
    u64 len = ctx->args[1];
    struct agg_key key = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .event_type = EVENT_TYPE_MMAP_SHARED
    };
    bpf_snprintf(key.detail, sizeof(key.detail), "fd=%d", &fd, sizeof(int));
    update_agg_map(&key, 1, len);
    return 0;
}
```

### 5. CoW page fault 追踪（--trace-cow）

用于论文实验 3.6：精确度量 fork 后 CoW 的触发频率和开销。

```c
// process_ext/bpf_cow.h
// kprobe 挂在 do_wp_page（CoW 核心路径）上，按 pid 聚合 minor fault 计数

SEC("kprobe/do_wp_page")
int trace_cow_fault(struct pt_regs *ctx) {
    if (!trace_cow) return 0;
    if (!is_pid_tracked()) return 0;   // BPF 侧 PID 过滤

    struct agg_key key = {
        .pid = bpf_get_current_pid_tgid() >> 32,
        .event_type = EVENT_TYPE_COW_FAULT
    };
    // detail 留空，按 pid 聚合

    update_agg_map(&key, 1, 0);  // 使用统一辅助函数
    return 0;
}
```

输出示例：
```jsonl
{"timestamp":260000000000,"event":"SUMMARY","comm":"python","pid":1234,"type":"COW_FAULT","detail":"","count":12847}
```

**用途**：`count` = CoW 页面复制次数。对比 `RSS / PAGE_SIZE` 即可得到写脏比例。

**注意**：`do_wp_page` 是内核内部函数，不同内核版本符号可能不同。需要用 `bpf_ksym_exists()` 或 BTF 做兼容。备选：`tp/exceptions/page_fault_user` + 过滤 minor fault。

### 6. per-process 内存采集（用户空间增强，无需新 BPF 程序）

用于论文实验 3.7：补充 per-process 内存分解数据。

在 `handle_event()` 中，对 EXEC/EXIT 事件额外读 `/proc/<pid>/statm` 和 `/proc/<pid>/status`：

```c
// process_ext/mem_info.h — 用户空间 header-only

struct proc_mem_info {
    long rss_pages;      // /proc/pid/statm field 1
    long shared_pages;   // /proc/pid/statm field 2
    long text_pages;     // /proc/pid/statm field 3
    long data_pages;     // /proc/pid/statm field 5
    long vm_hwm_kb;      // /proc/pid/status VmHWM（峰值 RSS）
};

static inline bool read_proc_mem_info(pid_t pid, struct proc_mem_info *info) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/statm", pid);
    FILE *f = fopen(path, "r");
    if (!f) return false;
    fscanf(f, "%*ld %ld %ld %ld %*ld %ld",
           &info->rss_pages, &info->shared_pages,
           &info->text_pages, &info->data_pages);
    fclose(f);

    // 读 VmHWM
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    f = fopen(path, "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "VmHWM:", 6) == 0) {
                sscanf(line + 6, "%ld", &info->vm_hwm_kb);
                break;
            }
        }
        fclose(f);
    }
    return true;
}
```

在 handle_event 中使用：

```c
case EVENT_TYPE_PROCESS:
    if (!e->exit_event) {
        // EXEC 事件：记录新进程的初始内存
        struct proc_mem_info mem;
        if (read_proc_mem_info(e->pid, &mem)) {
            // 在现有 EXEC JSON 的末尾追加内存字段（保持现有字段不变）
            // 现有：timestamp, event, comm, pid, ppid, filename, full_command
            // 追加：rss_kb, shared_kb, text_kb, data_kb
            printf("{\"timestamp\":%llu,\"event\":\"EXEC\",\"comm\":\"%s\",\"pid\":%d,"
                   "\"ppid\":%d,\"filename\":\"%s\",\"full_command\":\"%s\","
                   "\"rss_kb\":%ld,\"shared_kb\":%ld,\"text_kb\":%ld,\"data_kb\":%ld}\n",
                   ts, e->comm, e->pid, e->ppid, e->filename, e->full_command,
                   mem.rss_pages * page_size_kb, mem.shared_pages * page_size_kb,
                   mem.text_pages * page_size_kb, mem.data_pages * page_size_kb);
        }
    } else {
        // EXIT 事件：记录峰值内存
        struct proc_mem_info mem;
        if (read_proc_mem_info(e->pid, &mem)) {
            // 输出包含 vm_hwm_kb
        }
    }
```

**注意**：EXIT 事件时进程可能已经退出，`/proc/<pid>/` 可能已不存在。可以：
- 在 EXEC 时缓存初始 RSS，EXIT 时输出差值
- 或在 handle_event 中尽快读取（ring buffer 延迟通常 <1ms）

输出示例：
```jsonl
{"timestamp":123000000000,"event":"EXEC","comm":"pytest","pid":1234,"ppid":1000,"filename":"/usr/bin/pytest","full_command":"pytest test.py","rss_kb":15360,"shared_kb":12800,"text_kb":2048,"data_kb":512}
{"timestamp":456000000000,"event":"EXIT","comm":"pytest","pid":1234,"ppid":1000,"exit_code":0,"duration_ms":5000,"vm_hwm_kb":524288}
```

## 数据结构

### struct event（不修改）

现有 `struct event` + ring buffer 只服务于 4 种现有事件（EXEC/EXIT/FILE_OPEN/BASH_READLINE），**不变**。

### agg_key + agg_value（新增，用于 BPF map 聚合）

所有新增事件共用一套聚合结构：

```c
// process_new.h（新增文件，#include "process.h" 后扩展）

#define DETAIL_LEN 64

/* 聚合 key：(pid, event_type, detail) */
struct agg_key {
    __u32 pid;
    __u32 event_type;          // EVENT_TYPE_FILE_DELETE, NET_BIND, etc.
    char detail[DETAIL_LEN];   // 语义随 event_type 变化（见上文 key 设计表）
};

/* 聚合 value：count + bytes + timestamps + extra info */
struct agg_value {
    __u64 count;
    __u64 total_bytes;         // 仅 write/mmap 使用
    __u64 first_ts;
    __u64 last_ts;
    char comm[TASK_COMM_LEN];  // 最后一次操作的进程名
    char extra[MAX_FILENAME_LEN]; // 最后一次操作的额外信息（完整路径等）
};

/* event_type 编号（新增部分） */
enum event_type {
    // ... 现有 0-2 不变 ...
    EVENT_TYPE_FILE_DELETE = 10,
    EVENT_TYPE_FILE_RENAME = 11,
    EVENT_TYPE_DIR_CREATE = 12,
    EVENT_TYPE_FILE_TRUNCATE = 13,
    EVENT_TYPE_CHDIR = 14,
    EVENT_TYPE_WRITE = 15,
    EVENT_TYPE_NET_BIND = 20,
    EVENT_TYPE_NET_LISTEN = 21,
    EVENT_TYPE_NET_CONNECT = 22,
    EVENT_TYPE_PGRP_CHANGE = 30,
    EVENT_TYPE_SESSION_CREATE = 31,
    EVENT_TYPE_SIGNAL_SEND = 32,
    EVENT_TYPE_PROC_FORK = 33,
    EVENT_TYPE_MMAP_SHARED = 40,
    EVENT_TYPE_COW_FAULT = 41,
};
```

**BPF map 定义**（process_new.bpf.c）：

```c
/* 统一聚合 map：所有新增事件的唯一聚合目标 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);    // 足够容纳多 pid × 多 event_type × 多 detail
    __type(key, struct agg_key);
    __type(value, struct agg_value);
} event_agg_map SEC(".maps");

/* write 专用：暂存 enter 阶段的 fd（非聚合，临时上下文） */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);    /* pid_tgid */
    __type(value, int);    /* fd */
} write_fd_map SEC(".maps");

/* PID 过滤 map：用户空间在 EXEC 时写入，BPF 侧查询 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_TRACKED_PIDS);
    __type(key, __u32);    /* pid */
    __type(value, __u8);   /* dummy */
} tracked_pids SEC(".maps");

/* map 溢出计数器（per-CPU，零竞争） */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} agg_overflow_count SEC(".maps");
```

### Map 溢出处理

当 `event_agg_map` 达到 max_entries 时，`bpf_map_update_elem` 对新 key 返回 `-ENOSPC`。策略：

```c
// update_agg_map 中的溢出处理
if (bpf_map_update_elem(&event_agg_map, key, &new_val, BPF_NOEXIST) < 0) {
    // map 满了，记录溢出计数
    u32 zero = 0;
    u64 *overflow = bpf_map_lookup_elem(&agg_overflow_count, &zero);
    if (overflow)
        __sync_fetch_and_add(overflow, 1);
    // 事件丢失，但不影响已有聚合条目的更新
}
```

**用户空间监控**：每次 flush 后检查 overflow_count，非零则输出警告：

```jsonl
{"timestamp":260000000000,"event":"WARNING","comm":"","pid":0,"type":"AGG_MAP_OVERFLOW","overflow_count":42,"map_size":16384}
```

**缓解手段**：
- 默认 16384 条目（vs 之前的 8192），足够 ~100 个 tracked pid × ~160 种 (event_type, detail) 组合
- BPF 侧 PID 过滤（第 1.5 节）大幅减少无关条目
- 进程 EXIT 时立即 flush + 删除该 pid 的条目（释放空间）
- 如果仍不够，可在用户空间 flush 时用 `bpf_map__set_max_entries()` 在下次 load 前调大

## CLI 接口变更

### 现有 process（完全不变）

```
./process [-v] [-d MS] [-c COMMANDS] [-p PID] [-m MODE]
```

### 新程序 process_new（兼容现有参数 + 新增 flags）

```
./process_new [-v] [-d MS] [-c COMMANDS] [-p PID] [-m MODE] [--trace-fs] [--trace-net] [--trace-signals] [--trace-all]
```

| Flag | 启用的追踪 | 默认 |
|------|-----------|------|
| （无新 flag） | EXEC + EXIT + FILE_OPEN + BASH_READLINE | ✅ 与当前完全一致 |
| `--trace-fs` / `-F` | + FILE_DELETE, FILE_RENAME, DIR_CREATE, WRITE, FILE_TRUNCATE, CHDIR | off |
| `--trace-net` / `-N` | + NET_BIND + NET_LISTEN + NET_CONNECT | off |
| `--trace-signals` / `-S` | + PGRP_CHANGE + SESSION_CREATE + SIGNAL_SEND + PROC_FORK | off |
| `--trace-mem` / `-M` | + MMAP_SHARED | off |
| `--trace-cow` / `-C` | + COW_FAULT（kprobe/do_wp_page，高频） | off |
| `--trace-all` / `-A` | 以上全部（不含 --trace-cow，需显式启用） | off |

### Rust collector 侧

`ProcessRunner` 新增 `with_trace_features()` builder 方法，将对应 flags 转为 CLI 参数传给 BPF 二进制：

```rust
let runner = ProcessRunner::from_binary_extractor(path)
    .with_args(&["--trace-all"])    // 新增
    .with_args(&["-c", "python"]);
```

**不需要修改 Runner trait 或 Event 结构**——新事件类型自动通过 JSON → Event 流水线流入 analyzer chain。

## JSON 输出格式

### 现有事件（不变）

```jsonl
{"timestamp":123000000000,"event":"EXEC","comm":"python","pid":1234,"ppid":1000,"filename":"/usr/bin/python3","full_command":"python3 -m pytest"}
{"timestamp":124000000000,"event":"EXIT","comm":"python","pid":1234,"ppid":1000,"exit_code":0,"duration_ms":5000}
{"timestamp":125000000000,"event":"FILE_OPEN","comm":"python","pid":1234,"count":1,"filepath":"/testbed/main.py","flags":0}
{"timestamp":126000000000,"event":"BASH_READLINE","comm":"bash","pid":1000,"command":"pytest test.py"}
```

### 新增事件（统一 summary 格式，来自 BPF map flush）

```jsonl
// === 文件系统（高频 → 高 count） ===
// 字段顺序统一：timestamp(ns) → event → comm → pid → type → detail → count → [total_bytes] → [extra]
{"timestamp":260000000000,"event":"SUMMARY","comm":"pip","pid":1234,"type":"DIR_CREATE","detail":"/testbed/venv/lib/requests","count":47,"extra":"/testbed/venv/lib/requests/utils"}
{"timestamp":260000000000,"event":"SUMMARY","comm":"pip","pid":1234,"type":"FILE_RENAME","detail":"/testbed/venv/lib","count":203,"extra":"/testbed/venv/lib/urllib3/response.py"}
{"timestamp":260000000000,"event":"SUMMARY","comm":"pip","pid":1234,"type":"FILE_DELETE","detail":"/tmp/pip-build-xyz","count":89,"extra":"/tmp/pip-build-xyz/setup.py"}
{"timestamp":260000000000,"event":"SUMMARY","comm":"pip","pid":1234,"type":"WRITE","detail":"fd=5","count":1847,"total_bytes":4521984,"extra":"/testbed/venv/lib/requests/api.py"}
{"timestamp":260000000000,"event":"SUMMARY","comm":"python","pid":1234,"type":"FILE_TRUNCATE","detail":"fd=5","count":1}
{"timestamp":260000000000,"event":"SUMMARY","comm":"bash","pid":1234,"type":"CHDIR","detail":"/testbed/src","count":2}

// === 网络（低频 → count 通常 1-2） ===
{"timestamp":260000000000,"event":"SUMMARY","comm":"python","pid":5678,"type":"NET_BIND","detail":"0.0.0.0:8080","count":1}
{"timestamp":260000000000,"event":"SUMMARY","comm":"python","pid":5678,"type":"NET_LISTEN","detail":"fd=3","count":1}
{"timestamp":260000000000,"event":"SUMMARY","comm":"curl","pid":9012,"type":"NET_CONNECT","detail":"127.0.0.1:8080","count":1}
{"timestamp":260000000000,"event":"SUMMARY","comm":"pip","pid":1234,"type":"NET_CONNECT","detail":"pypi.org:443","count":15}

// === 进程协调（低频 → count=1，等价于逐条） ===
{"timestamp":260000000000,"event":"SUMMARY","comm":"bash","pid":1234,"type":"PGRP_CHANGE","detail":"pid=1234,pgid=5678","count":1}
{"timestamp":260000000000,"event":"SUMMARY","comm":"daemon","pid":1234,"type":"SESSION_CREATE","detail":"sid=1234","count":1}
{"timestamp":260000000000,"event":"SUMMARY","comm":"kill","pid":1234,"type":"SIGNAL_SEND","detail":"target=5678,sig=9","count":1}
{"timestamp":260000000000,"event":"SUMMARY","comm":"python","pid":1234,"type":"PROC_FORK","detail":"","count":3}

// === 内存 ===
{"timestamp":260000000000,"event":"SUMMARY","comm":"python","pid":1234,"type":"MMAP_SHARED","detail":"fd=5","count":2,"total_bytes":8192}
```

**所有新事件统一 `event: "SUMMARY"` + `type` 字段**，消费者用 `type` 区分。

**兼容性**：现有消费者（Rust ProcessRunner、analyzer chain）对未知 event type 直接透传，不影响。

## 用户空间 flush 循环（新增事件的输出路径）

**核心**：新增事件**不经过** ring buffer 和 handle_event，而是通过定时遍历 BPF map 输出。

### handle_event 不变

`handle_event()` 只处理现有 4 种 ring buffer 事件（EXEC/EXIT/FILE_OPEN/BASH_READLINE），**不增加新 case**。唯一修改：在 EXEC/EXIT 事件中附加 per-process 内存信息（见第 6 节）。

### flush 循环：与 ring_buffer__poll 共存

现有 event loop 使用 `ring_buffer__poll(rb, -1)` 无限阻塞。改为带超时的轮询 + 定时 flush：

```c
// process_new.c — 主循环
#define POLL_TIMEOUT_MS  1000   // ring buffer poll 超时 1 秒
#define FLUSH_INTERVAL_S 5      // BPF map flush 间隔 5 秒

static uint64_t last_flush_time = 0;

while (!exiting) {
    // 1. 处理 ring buffer 事件（现有 EXEC/EXIT/FILE_OPEN/BASH_READLINE）
    int err = ring_buffer__poll(rb, POLL_TIMEOUT_MS);
    if (err == -EINTR)
        continue;

    // 2. 检查是否到了 flush 时间
    uint64_t now = time(NULL);
    if (now - last_flush_time >= FLUSH_INTERVAL_S) {
        flush_agg_map(skel->maps.event_agg_map);
        last_flush_time = now;
    }
}

// 退出时做最终 flush
flush_agg_map(skel->maps.event_agg_map);
```

### flush_agg_map 实现

```c
// process_ext/map_flush.h

static void flush_agg_map(int map_fd)
{
    struct agg_key key = {}, next_key;
    struct agg_value val;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0 && val.count > 0) {
            // 输出 SUMMARY JSON（字段顺序与现有事件一致：timestamp → event → comm → pid → ...）
            printf("{\"timestamp\":%llu,\"event\":\"SUMMARY\","
                   "\"comm\":\"%s\",\"pid\":%u,"
                   "\"type\":\"%s\",\"detail\":\"%s\","
                   "\"count\":%llu,\"total_bytes\":%llu,"
                   "\"extra\":\"%s\"}\n",
                   val.last_ts, val.comm, next_key.pid,
                   event_type_name(next_key.event_type),
                   next_key.detail, val.count, val.total_bytes, val.extra);

            // 删除已 flush 的条目（释放 map 空间）
            bpf_map_delete_elem(map_fd, &next_key);
        }
        key = next_key;
    }
    fflush(stdout);
}
```

### 进程 EXIT 时的 flush

进程退出后其 map entries 不再更新，但仍占 map 空间。在 handle_event 处理 EXIT 事件时，触发一次**该 pid 的局部 flush**：

```c
// handle_event 中 EXIT 分支末尾新增：
case EVENT_TYPE_PROCESS:
    if (e->exit_event) {
        // ... 现有 EXIT 处理 ...
        // 新增：flush 该进程在 agg map 中的残留条目
        flush_pid_from_agg_map(skel->maps.event_agg_map, e->pid);
    }
    break;
```

```c
// process_ext/map_flush.h
static void flush_pid_from_agg_map(int map_fd, u32 target_pid)
{
    struct agg_key key = {}, next_key;
    struct agg_value val;
    struct agg_key to_delete[256];  // 批量删除缓冲
    int del_count = 0;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (next_key.pid == target_pid) {
            if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0 && val.count > 0) {
                // 输出 SUMMARY
                print_summary_json(&next_key, &val);
            }
            if (del_count < 256)
                to_delete[del_count++] = next_key;
        }
        key = next_key;
    }

    // 批量删除（遍历中不能删，会破坏迭代器）
    for (int i = 0; i < del_count; i++)
        bpf_map_delete_elem(map_fd, &to_delete[i]);
    fflush(stdout);
}
```

**注意**：`bpf_map_get_next_key` 遍历整个 map 来找特定 pid 的条目，复杂度 O(map_size)。对 16384 条目的 map 这是可接受的（<1ms）。如果 map 很大，可以维护一个 per-pid 的 key 索引（用户空间 hash map）来加速。

## 代码组织：独立 process_new + 子目录模块化

现有 `process.bpf.c` 和 `process.c` **完全不动**。新建 `process_new.bpf.c` + `process_new.c` 作为独立编译目标，所有新增头文件放在 `bpf/process_ext/` 子目录中（注：最初设计为 `process_new/`，因与二进制文件同名冲突已重命名为 `process_ext/`）：

```
bpf/
│
├── process.h                          ← 现有，不修改
├── process.bpf.c                      ← 现有，不修改
├── process.c                          ← 现有，不修改
├── process_utils.h                    ← 现有，不修改
├── process_filter.h                   ← 现有，不修改
│
├── process_new.h                      ← 新增：扩展事件结构（agg_key/agg_value/新 event_type enum）
├── process_new.bpf.c                  ← 新增：BPF 胶水文件（定义 maps + flags + #include 子目录模块）
├── process_new.c                      ← 新增：用户空间主程序（CLI + flush 循环 + handle_event）
│
├── process_ext/                       ← 新增子目录：所有模块化头文件
│   │
│   ├── ===== BPF 内核侧 =====
│   ├── bpf_common.h                   ← is_pid_tracked() + update_agg_map() + format_fd_detail() + format_ipv4_port()
│   ├── bpf_fs.h                       ← 文件系统 tracepoints（unlinkat, renameat2, mkdirat, ftruncate, chdir）+ extract_dir_prefix()
│   ├── bpf_write.h                    ← write enter/exit handlers + write_fd_map（临时上下文）
│   ├── bpf_net.h                      ← 网络 tracepoints（bind, listen, connect + sockaddr 解析 + format_family()）
│   ├── bpf_signals.h                  ← 进程协调 tracepoints（setpgid, setsid, kill, fork）+ write_uint/write_int/write_str
│   ├── bpf_mem.h                      ← 内存 tracepoints（mmap MAP_SHARED 过滤）
│   ├── bpf_cow.h                      ← CoW page fault 追踪（kprobe/do_wp_page）
│   │
│   ├── ===== 用户空间 =====
│   ├── map_flush.h                    ← event_type_name() + json_escape() + print_summary_json() + flush_agg_map() + flush_pid_from_agg_map() + check_overflow()
│   └── mem_info.h                     ← read_proc_mem_info()：读 /proc/pid/statm + /proc/pid/status
│
└── tests/
    ├── test_process_utils.c           ← 现有，不修改
    ├── test_process_filter.c          ← 现有，不修改
    ├── test_process_new_header.c      ← 新增：结构体布局、枚举值、常量（49 tests）
    ├── test_process_new_map_flush.c   ← 新增：event_type_name, json_escape, print_summary_json（48 tests）
    ├── test_process_new_mem_info.c    ← 新增：/proc 内存信息读取（18 tests）
    ├── test_integration.sh            ← 新增：eBPF 加载集成测试（19 test cases，需 sudo + jq）
    └── bpf/                           ← 测试用 libbpf stub 头文件
        ├── bpf.h
        └── libbpf.h
```

**BPF 侧模块化说明**：

`process_new.bpf.c` 是独立的胶水文件，定义所有资源 + include 子目录模块：

```c
// process_new.bpf.c — 独立新程序，不修改现有 process.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "process.h"        // 复用现有 struct event（ring buffer 事件）
#include "process_new.h"    // 新增 agg_key/agg_value/新 event_type

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* === 共享资源（ring buffer 用于现有事件） === */
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024); } rb SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 8192); __type(key, pid_t); __type(value, u64); } exec_start SEC(".maps");

/* === 新增资源（BPF map 聚合用于新事件） === */
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 16384); __type(key, struct agg_key); __type(value, struct agg_value); } event_agg_map SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, MAX_TRACKED_PIDS); __type(key, u32); __type(value, u8); } tracked_pids SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1); __type(key, u32); __type(value, u64); } agg_overflow_count SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;
const volatile bool filter_pids = false;
const volatile bool trace_fs_mutations = false;
const volatile bool trace_network = false;
const volatile bool trace_signals = false;
const volatile bool trace_memory = false;
const volatile bool trace_cow = false;

/* === 通用辅助（必须在所有模块之前） === */
#include "process_ext/bpf_common.h"    // is_pid_tracked() + update_agg_map()

/* === 现有 handlers（从 process.bpf.c 复制） === */
// handle_exec, handle_exit, trace_openat, trace_open, bash_readline
// 注意：直接复制而非 #include，确保两个程序完全解耦

/* === 新增模块（全部使用 event_agg_map + is_pid_tracked） === */
#include "process_ext/bpf_fs.h"        // unlinkat, renameat2, mkdirat, ftruncate, chdir
#include "process_ext/bpf_write.h"     // write enter/exit（write_fd_map 为临时上下文，聚合到 event_agg_map）
#include "process_ext/bpf_net.h"       // bind, listen, connect
#include "process_ext/bpf_signals.h"   // setpgid, setsid, kill, fork
#include "process_ext/bpf_mem.h"       // mmap (MAP_SHARED only)
#include "process_ext/bpf_cow.h"       // CoW page fault (kprobe/do_wp_page)
```

每个 BPF header-only 模块的结构一致：

```c
// process_ext/bpf_fs.h — 文件系统 mutations
#ifndef __PROCESS_NEW_BPF_FS_H
#define __PROCESS_NEW_BPF_FS_H

// 引用 process_new.bpf.c 中定义的共享资源（extern 不需要，BPF 同一编译单元）

SEC("tp/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    if (!trace_fs_mutations) return 0;
    // ...
}

SEC("tp/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    if (!trace_fs_mutations) return 0;
    // ...
}

// ... mkdirat, ftruncate, chdir 同理 ...

#endif /* __PROCESS_NEW_BPF_FS_H */
```

**好处**：
- **零回归风险**：现有 `process` 完全不动，`make process` 结果不变
- 每个模块独立可读（~50-80 行），不用在一个 500+ 行的 .bpf.c 里翻找
- BPF 编译器看到的仍是单个编译单元（通过 #include），maps 和 flags 自然共享
- 子目录 `process_ext/` 集中管理，不污染 `bpf/` 顶层
- 可以按模块 review、按模块 disable（注释掉一行 #include）

**模块化原则**：
- 每个 `.h` 文件是 header-only（函数带 `static inline` 或 `static`），不生成额外 .o
- `process_new.c` 的 `#include` 顺序就是依赖顺序
- 测试文件独立编译，不需要 BPF skeleton
- 现有测试 (`test_process_utils`, `test_process_filter`) 不受影响

**process_ext/ 子目录模块清单**：

| 模块 | 内容 | 行数（约） |
|------|------|-----------|
| `bpf_common.h` | `is_pid_tracked()` + `update_agg_map()` + overflow 处理 | ~60 |
| `bpf_fs.h` | unlinkat, renameat2, mkdirat, ftruncate, chdir + `extract_dir_prefix()` | ~120 |
| `bpf_write.h` | write enter/exit + `write_fd_map`（临时上下文） | ~60 |
| `bpf_net.h` | bind, listen, connect + sockaddr 内核读取 | ~80 |
| `bpf_signals.h` | setpgid, setsid, kill, fork | ~80 |
| `bpf_mem.h` | mmap (MAP_SHARED only) | ~30 |
| `bpf_cow.h` | kprobe/do_wp_page | ~30 |
| `output.h` | `print_summary_json()` + 新事件的 print 函数 | ~150 |
| `dedup.h` | FILE_OPEN dedup（从 process.c 复制，独立实现） | ~250 |
| `map_flush.h` | flush_agg_map() + flush_pid_from_agg_map() + fd→path 解析 | ~150 |
| `net_fmt.h` | sockaddr 解析, IP/port 格式化 | ~80 |
| `mem_info.h` | read_proc_mem_info(), per-process RSS/shared/VmHWM | ~60 |

## 测试计划

### 现有单元测试（不修改）

```bash
make test  # 运行全部 5 个测试套件（199 tests）
```

| 测试 | 测试数 | 覆盖内容 |
|------|--------|---------|
| test_process_utils | 24 | read_proc_comm, read_proc_ppid, command_matches_filter |
| test_process_filter | 60 | PID 跟踪、hash、过滤模式 |
| test_process_new_header | 49 | agg_key/agg_value 结构体布局、枚举值、常量 |
| test_process_new_map_flush | 48 | event_type_name, json_escape, print_summary_json |
| test_process_new_mem_info | 18 | /proc 内存信息读取，边界情况 |

### 集成测试（需要 root/eBPF）

集成测试通过 Python 脚本 `bpf/tests/test_integration.py` 实现，需要 `sudo` + `python3`。Python 便于解析 JSON、管理子进程、做结构化断言。

#### 运行方式

```bash
make process_new process          # 先构建
sudo python3 tests/test_integration.py        # 运行全部集成测试
sudo python3 tests/test_integration.py -k fs  # 只跑名字含 "fs" 的测试
# 或
make integration-test             # Makefile 快捷方式（含 sudo）
```

#### Python 测试框架设计

```python
# tests/test_integration.py
import subprocess, signal, json, tempfile, time, os, socket, mmap

BPF_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESS_NEW = os.path.join(BPF_DIR, "process_new")
PROCESS_OLD = os.path.join(BPF_DIR, "process")

class TracerSession:
    """启动 process_new 后台进程，收集 JSON 输出"""
    def __init__(self, *extra_args, wait_attach=2):
        self.outfile = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False)
        self.proc = subprocess.Popen(
            [PROCESS_NEW] + list(extra_args),
            stdout=self.outfile, stderr=subprocess.DEVNULL)
        time.sleep(wait_attach)  # 等 BPF 加载

    def stop(self):
        self.proc.send_signal(signal.SIGINT)  # 触发 final flush
        self.proc.wait(timeout=10)
        self.outfile.close()

    def events(self) -> list[dict]:
        """解析所有 JSON 行"""
        with open(self.outfile.name) as f:
            return [json.loads(line) for line in f if line.strip()]

    def find(self, **filters) -> list[dict]:
        """按字段值过滤事件，例如 find(event="EXEC", comm="echo")"""
        result = []
        for ev in self.events():
            if all(ev.get(k) == v for k, v in filters.items()):
                result.append(ev)
        return result

    def find_summary(self, type_name, **extra) -> list[dict]:
        """查找 SUMMARY 事件，例如 find_summary("FILE_DELETE")"""
        return self.find(event="SUMMARY", type=type_name, **extra)

    def assert_has(self, desc, **filters):
        """断言至少存在一条匹配事件"""
        matches = self.find(**filters)
        assert len(matches) > 0, f"FAIL: {desc} — no events matching {filters}"
        print(f"  [PASS] {desc} ({len(matches)} events)")

    def assert_has_summary(self, desc, type_name, **extra):
        matches = self.find_summary(type_name, **extra)
        assert len(matches) > 0, f"FAIL: {desc} — no SUMMARY type={type_name}"
        print(f"  [PASS] {desc} ({len(matches)} events)")

    def assert_none(self, desc, **filters):
        """断言不存在匹配事件"""
        matches = self.find(**filters)
        assert len(matches) == 0, f"FAIL: {desc} — found {len(matches)} unexpected events"
        print(f"  [PASS] {desc} (0 events, correct)")
```

#### 测试用例（每个 test 函数是独立用例）

| # | 函数名 | CLI flags | 工作负载 | 验证内容 |
|---|--------|-----------|----------|----------|
| 1 | `test_basic_lifecycle` | `-m 0` | `subprocess.run(["/bin/echo", "hello"])` | EXEC+EXIT, pid/ppid/filename/exit_code=0 |
| 2 | `test_nonzero_exit` | `-m 0` | `bash -c 'exit 42'` | EXIT exit_code=42 |
| 3 | `test_command_filter` | `-c bash` | bash + python 子进程 | bash 有 EXEC，python3 无 EXEC |
| 4 | `test_pid_filter` | `-p PID` | 指定 PID + 无关进程 | 仅目标 PID |
| 5 | `test_mode_all` | `-m 0` | echo + python | 两者都有 EXEC |
| 6 | `test_trace_fs` | `-m 0 --trace-fs` | os.mkdir/os.remove/os.rename/os.truncate/os.chdir | SUMMARY: DIR_CREATE, FILE_DELETE, FILE_RENAME, FILE_TRUNCATE, CHDIR |
| 7 | `test_trace_write` | `-m 0 --trace-fs` | `dd if=/dev/zero bs=1024 count=10` | SUMMARY WRITE，total_bytes > 0 |
| 8 | `test_trace_net` | `-m 0 --trace-net` | socket bind+listen+connect (port 19876) | NET_BIND(含端口), NET_LISTEN, NET_CONNECT(含端口) |
| 9 | `test_trace_signals` | `-m 0 --trace-signals` | os.fork + os.kill | PROC_FORK, SIGNAL_SEND |
| 10 | `test_bash_readline` | `-m 0` | `echo cmd \| bash -i` | BASH_READLINE（软失败 pytest.skip） |
| 11 | `test_file_open` | `-m 0` | `cat /etc/hostname` | FILE_OPEN 含 filepath |
| 12 | `test_trace_all` | `-m 0 --trace-all` | fs+net+signal 组合 | 所有 SUMMARY 类型都出现 |
| 13 | `test_multi_app` | `-m 0` | bash + python 并发子进程 | 两种 comm 都捕获 |
| 14 | `test_compat` | `-m 0` | echo | process vs process_new EXEC/EXIT/FILE_OPEN 字段一致 |
| 15 | `test_summary_json_schema` | `-m 0 --trace-fs` | mkdir+rm | SUMMARY 字段类型：timestamp=int, comm=str, pid=int, count=int |
| 16 | `test_flush_on_sigint` | `-m 0 --trace-fs` | mkdir+rm，1s 后停 | 不到 5s 也有 SUMMARY |
| 17 | `test_trace_mem` | `-m 0 --trace-mem` | mmap.mmap(MAP_SHARED) | MMAP_SHARED 事件 |
| 18 | `test_duration_filter` | `-m 0 -d 2000` | echo(快) + sleep 3(慢) | 仅长时间进程 EXIT |
| 19 | `test_idempotent` | `-m 0` | 两次 TracerSession | 两次都成功 |

#### 关键测试场景详解

**test_trace_fs** — 最重要的集成测试，直接用 Python os 模块触发 syscall：
```python
def test_trace_fs(tmp_path):
    t = TracerSession("-m", "0", "--trace-fs")
    workdir = tmp_path / "fs_test"
    workdir.mkdir()
    # 触发各种 FS syscall
    subprocess.run(["/bin/bash", "-c", f"""
        cd {workdir}
        mkdir -p subdir1
        echo data > to_delete.txt && rm to_delete.txt
        echo data > old.txt && mv old.txt new.txt
        truncate -s 0 new.txt
        cd subdir1
    """])
    time.sleep(1)
    t.stop()
    t.assert_has_summary("mkdir → DIR_CREATE", "DIR_CREATE")
    t.assert_has_summary("rm → FILE_DELETE", "FILE_DELETE")
    t.assert_has_summary("mv → FILE_RENAME", "FILE_RENAME")
    t.assert_has_summary("truncate → FILE_TRUNCATE", "FILE_TRUNCATE")
    t.assert_has_summary("cd → CHDIR", "CHDIR")
```

**test_trace_net** — Python 直接做 socket 操作，精确控制端口：
```python
def test_trace_net():
    t = TracerSession("-m", "0", "--trace-net")
    # 用子进程避免 tracer 自己的 socket 被捕获
    subprocess.run(["python3", "-c", """
import socket
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(('127.0.0.1', 19876))
srv.listen(1)
cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cli.connect(('127.0.0.1', 19876))
conn, _ = srv.accept()
conn.close(); cli.close(); srv.close()
"""])
    time.sleep(1)
    t.stop()
    # 验证 detail 包含端口号
    binds = t.find_summary("NET_BIND")
    assert any("19876" in e.get("detail", "") for e in binds), "NET_BIND should contain port 19876"
    t.assert_has_summary("listen", "NET_LISTEN")
    connects = t.find_summary("NET_CONNECT")
    assert any("19876" in e.get("detail", "") for e in connects), "NET_CONNECT should contain port 19876"
```

**test_compat** — 对比 `process` 和 `process_new` 的核心 JSON 字段：
```python
def test_compat():
    if not os.path.isfile(PROCESS_OLD):
        print("  [SKIP] process binary not found")
        return
    # 运行两个 tracer 对同一工作负载
    for binary, label in [(PROCESS_OLD, "old"), (PROCESS_NEW, "new")]:
        # ... 启动、运行 echo、停止、收集事件 ...
    # 对比 EXEC 字段集合
    required_exec = {"event", "comm", "pid", "ppid", "filename", "timestamp"}
    required_exit = {"event", "comm", "pid", "ppid", "exit_code", "timestamp"}
    required_file_open = {"event", "comm", "pid", "filepath", "flags"}
    # 验证 process_new 输出的字段集是 process 输出字段集的超集
```

**test_summary_json_schema** — 验证每条 SUMMARY 的字段类型：
```python
def test_summary_json_schema():
    # ... 触发一些 FS 操作 ...
    for ev in t.find(event="SUMMARY"):
        assert isinstance(ev["timestamp"], int), "timestamp must be int"
        assert isinstance(ev["comm"], str), "comm must be str"
        assert isinstance(ev["pid"], int), "pid must be int"
        assert isinstance(ev["type"], str), "type must be str"
        assert isinstance(ev["detail"], str), "detail must be str"
        assert isinstance(ev["count"], int), "count must be int"
        if "total_bytes" in ev:
            assert isinstance(ev["total_bytes"], int), "total_bytes must be int"
        if "extra" in ev:
            assert isinstance(ev["extra"], str), "extra must be str"
```

#### 注意事项

- **需要 root**：脚本开头检查 `os.geteuid() == 0`，否则提示 `sudo`
- **BPF 加载等待**：`wait_attach=2` 秒，给 BPF skeleton open/load/attach 足够时间
- **SIGINT flush**：`process_new.c:669` 在退出时调用 `flush_agg_map()`，确保不丢聚合事件
- **BASH_READLINE** (Test 10)：uretprobe 依赖 `/usr/bin/bash:readline`，非交互 bash 可能不触发，标记软失败
- **--trace-cow 不测**：kprobe/do_wp_page 依赖内核版本，且不含在 --trace-all 中
- **端口 19876**：高端口避免冲突，`SO_REUSEADDR` 防绑定失败
- **系统噪声**：`-m 0` 捕获所有进程，断言用 comm/port 等字段精确过滤
- **清理**：每个测试用 `tempfile` 创建临时目录，结束自动清理

## 实施步骤

### Step 1：搭建 process_new 骨架（1 小时）

**创建独立的新程序，复制现有核心逻辑**：

- 创建 `bpf/process_ext/` 子目录
- 创建 `bpf/process_new.h`：复制 `process.h` 内容 + 新增 `agg_key` / `agg_value` / 新 event_type enum
- 创建 `bpf/process_new.bpf.c`：从 `process.bpf.c` 复制现有 handlers（handle_exec/handle_exit/trace_openat/trace_open/bash_readline）+ 新增 maps（event_agg_map/tracked_pids/agg_overflow_count）+ feature flags
- 创建 `bpf/process_new.c`：从 `process.c` 复制 main/handle_event/CLI 解析，改 skeleton 引用为 `process_new`
- 更新 `Makefile`：新增 `process_new` 编译目标（`APPS += process_new`）
- 验证：`make process_new` 编译通过，`./process_new -c python` 行为与 `./process` 一致

### Step 2：基础设施——PID 过滤 + flush 循环（1 小时）

**在加任何新 tracepoint 之前**，先搭好基础设施：

- `process_ext/bpf_common.h`：`is_pid_tracked()` + `update_agg_map()` 通用辅助
- `process_ext/map_flush.h`：`flush_agg_map()` + `flush_pid_from_agg_map()`
- `process_new.c`：主循环从 `ring_buffer__poll(rb, -1)` 改为 `ring_buffer__poll(rb, POLL_TIMEOUT_MS)` + 定时调用 `flush_agg_map()`
- `process_new.c` handle_event：EXEC 时写 `tracked_pids`，EXIT 时删除 + 调用 `flush_pid_from_agg_map()`
- 验证：无新 flag 时行为与现有 `process` 完全一致（map 为空，flush 不输出）

### Step 3：分批新增 BPF tracepoints（2-3 小时）

每批加完即可测试：

**批次 A（文件系统 mutations）**：
- 新增 `process_ext/bpf_fs.h`：`unlinkat`, `renameat2`, `mkdirat`, `ftruncate`, `chdir`（全部调用 `update_agg_map`）
- 新增 `process_ext/bpf_write.h`：write enter/exit + `write_fd_map`（临时上下文）→ 聚合到 `event_agg_map`
- 新增 `extract_dir_prefix()` BPF inline helper

**批次 B（网络）**：
- 新增 `process_ext/bpf_net.h`：`bind`, `listen`, `connect`
- 新增 `process_ext/net_fmt.h`（用户空间 sockaddr 解析）+ `tests/test_process_new_net.c`

**批次 C（进程协调）**：
- 新增 `process_ext/bpf_signals.h`：`setpgid`, `setsid`, `kill`, `sched_process_fork`
- 参数都是整数，实现最简单

**批次 D（内存）**：
- 新增 `process_ext/bpf_mem.h`：`mmap`（内核侧过滤仅 MAP_SHARED）

**批次 E（CoW page fault 追踪）**：
- 新增 `process_ext/bpf_cow.h`：kprobe/`do_wp_page`
- 需要内核版本兼容处理（BTF 查找符号）
- 不含在 `--trace-all` 中

### Step 4：用户空间增强（1 小时）

- `process_new.c` CLI 新增参数：`--trace-fs`, `--trace-net`, `--trace-signals`, `--trace-mem`, `--trace-cow`, `--trace-all`
- 设置 BPF feature flags + `filter_pids`
- per-process 内存采集：`process_ext/mem_info.h`，在 EXEC/EXIT handle_event 中调用
- fd→path 解析：flush 时读 `/proc/<pid>/fd/<fd>`
- `process_ext/output.h`：JSON 输出函数
- `process_ext/dedup.h`：FILE_OPEN dedup（从 process.c 复制）

### Step 5：新增测试（1 小时）

- 新增 `tests/test_process_new_output.c`（SUMMARY JSON 格式验证）
- 新增 `tests/test_process_new_dedup.c`（dedup 逻辑）
- 新增 `tests/test_process_new_net.c`（sockaddr 解析）
- 新增 `tests/test_process_new_map_flush.c`（flush 逻辑 + fd→path）
- 更新 Makefile：新测试目标，`make test` 同时运行新旧测试
- **现有测试不修改**

### Step 6：集成测试 + Rust collector（30 分钟）

- 手动运行集成测试（用 `process_new` 代替 `process`）
- 可选：给 `ProcessRunner` 加 `with_trace_features()` builder，可选择运行 `process_new` 二进制

## 与论文实验的对应

| 论文实验 | 需要的事件/能力 | 启用 flag |
|----------|----------------|----------|
| 1.2（文件变更范围 + CoW 收益） | DIR_CREATE + FILE_DELETE + FILE_RENAME + WRITE | `--trace-fs` |
| 1.3（内存积累 + per-process） | EXEC/EXIT + /proc/pid/statm | 现有 + 用户空间增强 |
| 2.2（进程隔离对比/Table 2） | PGRP_CHANGE + SESSION_CREATE + SIGNAL_SEND | `--trace-signals` |
| 3.1（内存/端口/IPC 污染） | NET_BIND + SIGNAL_SEND + MMAP_SHARED | `--trace-net --trace-signals --trace-mem` |
| 3.3（多维副作用频率） | 全部 | `--trace-all` |
| 3.5（内存重叠率） | — | 独立实验（fork + smaps），不需要 agentsight |
| 3.6（page fault 追踪） | COW_FAULT | `--trace-cow` |
| 3.7（per-process 内存分解） | EXEC/EXIT + /proc/pid/statm + VmHWM | 用户空间增强 |

## 设计约束

1. **现有文件不修改**——`process.bpf.c`、`process.c`、`process.h` 完全不动，零回归风险
2. **独立编译目标**——`process_new` 是独立的 `make` 目标，不影响 `make process`
3. **头文件集中在子目录**——所有新增模块放在 `bpf/process_ext/`，不污染 `bpf/` 顶层
4. **统一聚合 map**——所有新增事件走同一个 `event_agg_map`，不引入独立的 per-事件-类型 map
5. **struct event 不变**——新事件不用 struct event，不占 ring buffer。ring buffer 只给现有 4 种事件
6. **BPF 侧 PID 过滤**——新事件在 BPF handler 中通过 `tracked_pids` map 过滤，防止 map 被无关进程污染
7. **handle_event 不处理新事件**——新事件通过定时 flush 循环输出，不在 ring buffer 回调中出现
8. **process_new 默认行为与 process 一致**——不加新 flag 时行为、性能完全相同
9. **现有 FILE_OPEN 不变**——仍用用户空间 60 秒窗口 dedup（向后兼容）
10. **主循环改为 poll+flush**——`ring_buffer__poll(rb, TIMEOUT)` 带超时，每次返回后检查 flush timer
11. **map 溢出可观测**——overflow per-CPU counter + 用户空间警告 JSON
12. **mmap() 内核侧过滤**——只聚合 MAP_SHARED 的 mmap，忽略 MAP_PRIVATE
13. **--trace-cow 不含在 --trace-all 中**——page fault 追踪开销较高且是专用场景，需显式启用
14. **per-process 内存采集是用户空间增强**——不需要新 BPF 程序，只在 handle_event 中读 /proc
