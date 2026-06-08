# AgentSight 中断检测场景测试

对 AgentSight 的中断检测、分类、logtail 导出进行端到端验证。通过向 LLM API 发送构造好的请求（正常 / 错误），检查 AgentSight 是否正确识别中断类型并写入数据库和 logtail 文件。

## 前置条件

**远程机器上需要：**

1. AgentSight 服务运行中（`systemctl status agentsight`）

2. **配置 AgentSight 监控测试进程** — 编辑 `/etc/agentsight/config.json`（若不存在则创建），确保包含以下内容：

   ```json
   {
     "https": [
       {"rule": ["*.dashscope.aliyuncs.com"]}
     ],
     "cmdline": {
       "allow": [
         {"rule": ["*python3*"], "agent_name": "TestAgent"}
       ]
     }
   }
   ```

   说明：
   - `https` 规则：让 AgentSight 通过 DNS 探针发现到 `dashscope.aliyuncs.com` 的 HTTPS 连接并附着 SSL 探针
   - `cmdline.allow` 规则：当检测到命令行包含 `python3` 的进程时，将其识别为名为 `TestAgent` 的 agent 并开始追踪

   如果机器上已有其他规则（如 Hermes / OpenClaw），**追加** `*python3*` 规则即可，不要覆盖已有配置。修改后需重启服务：

   ```bash
   systemctl restart agentsight
   ```

3. **配置 logtail 导出**（可选，用于验证 SLS 写入）：

   ```bash
   mkdir -p /etc/systemd/system/agentsight.service.d
   cat > /etc/systemd/system/agentsight.service.d/logtail.conf << 'EOF'
   [Service]
   Environment=SLS_LOGTAIL_FILE=/var/sysom/ilog/agentsight
   Environment=RUST_LOG=info
   EOF
   systemctl daemon-reload
   systemctl restart agentsight
   ```

4. 一个有效的 dashscope API key

## 快速开始

```bash
# 1. 上传脚本到远程机器
scp integration-tests/interruption/scenario_test.py root@<HOST>:/tmp/

# 2. 跑一个场景
ssh root@<HOST> "python3 /tmp/scenario_test.py auth_single --api-key sk-your-key"

# 3. 跑所有场景
ssh root@<HOST> "python3 /tmp/scenario_test.py all --api-key sk-your-key"

# API key 也可以通过环境变量传入
ssh root@<HOST> "DASHSCOPE_API_KEY=sk-your-key python3 /tmp/scenario_test.py all"
```

## 场景说明

### auth_single — 单次认证错误

发送 1 个请求，使用无效 API key。

- 预期 HTTP 状态码：`401`
- 预期中断类型：`auth_error`（severity: high）
- 用途：验证 401 + `invalid_api_key` 关键字被正确分类为 `auth_error`

### auth_storm — 认证错误风暴

用同一个无效 key 快速发送 5 个请求（模拟重试风暴）。

- 预期：5 个 `auth_error` 中断
- 用途：验证同一根因的重复错误在健康分计算中受到 per-session penalty cap 限制（cap=10，等于 1 次 critical）

### mixed_light — 轻度混合

10 个请求：8 个正常 + 2 个认证错误。

- 预期：2 个 `auth_error`，8 个正常 LLMCall
- 用途：验证正常请求和错误请求混合时的检测准确性

### mixed_heavy — 重度混合

10 个请求：5 个正常 + 5 个认证错误（交替发送）。

- 预期：5 个 `auth_error`，5 个正常 LLMCall
- 用途：验证高错误率场景下的健康分计算

### multi_type — 多种错误类型

5 个请求：3 个正常 + 1 个认证错误 + 1 个不存在模型（404）。

- 预期：1 个 `auth_error` + 1 个 `llm_error`
- 用途：验证不同类型中断的正确分类

### healthy — 健康基线

10 个正常请求。

- 预期：0 个中断
- 用途：建立正常对话基线，验证无误报

### all — 全部场景

按顺序运行：healthy → auth_single → auth_storm → mixed_light → multi_type。

## 输出说明

脚本运行后会自动等待 AgentSight 处理事件，然后输出：

```
  === Results for 'multi_type' ===
  Calls made: 5
    normal qwen-max -> 200           # 正常请求
    auth_error qwen-max -> 401       # 认证错误
    normal qwen-max -> 200
    model_not_found nonexistent-model-xyz-999 -> 404  # 模型不存在
    normal qwen-max -> 200
  Logtail: 5 chat records, 2 interruption records    # logtail 导出记录
    INT: type=auth_error severity=high agent=TestAgent
    INT: type=llm_error severity=high agent=TestAgent
  DB interruption_events: 2 new                       # DB 中断记录
    type=auth_error severity=high agent=TestAgent
    type=llm_error severity=high agent=TestAgent
```

**验证要点：**

| 检查项 | 说明 |
|--------|------|
| HTTP 状态码 | 401/404 等错误码正确返回 |
| Logtail chat records | 每个请求产生 1 条 chat 记录 |
| Logtail interruption records | 错误请求产生对应 interruption 记录 |
| 中断类型分类 | auth_error / llm_error / network_timeout 正确匹配 |
| DB 记录 | interruption_events 表新增对应记录 |
| 无误报 | 正常请求不产生 interruption 记录 |

## 中断类型对照表

| 类型 | 触发条件 | 严重级别 |
|------|----------|----------|
| `auth_error` | 401/403，或错误信息含 `invalid_api_key` / `unauthorized` | high |
| `rate_limit` | 429，或错误信息含 `rate_limit` | medium |
| `network_timeout` | 408/504，或错误信息含 `timeout` | high |
| `service_unavailable` | 502/503，或错误信息含 `overloaded` | high |
| `safety_filter` | finish_reason == `content_filter` | medium |
| `context_overflow` | 错误信息含 `context_length_exceeded` 等 | high |
| `token_limit` | finish_reason == `length` 且 output_tokens >= max_tokens * 0.95 | medium |
| `llm_error` | HTTP >= 400 通用兜底（优先级最低） | high |
| `sse_truncated` | SSE 流未正常结束 | high |
| `agent_crash` | Agent 进程中途消失 | critical |

## 健康分计算

测试后可手动验证健康分：

```bash
ssh root@<HOST> 'python3 -c "
import json
from collections import defaultdict
with open(\"/var/sysom/ilog/agentsight\") as f:
    logs = [json.loads(l) for l in f]
chat = [l for l in logs if l.get(\"gen_ai.operation.name\") != \"interruption\"]
ints = [l for l in logs if l.get(\"gen_ai.operation.name\") == \"interruption\"]
convs = set(l.get(\"gen_ai.conversation.id\") for l in chat if l.get(\"gen_ai.conversation.id\"))
w = {\"critical\": 10, \"high\": 5, \"medium\": 2, \"low\": 1}
ss = defaultdict(int)
for il in ints:
    sid = il.get(\"gen_ai.session.id\", \"none\")
    ss[sid] += w.get(il.get(\"agentsight.interruption.severity\", \"medium\"), 1)
capped = sum(min(s, 10) for s in ss.values())
tc = len(convs)
score = round(max(0, 100 - min(100, capped / max(1, tc) * 100)), 1) if tc else 100.0
print(\"conversations={} interruptions={} capped_penalty={} health_score={}\".format(tc, len(ints), capped, score))
"'
```

公式：`score = 100 - min(100, capped_penalty / total_conversations * 100)`

- 分母用 conversation 数（不用 session 数），避免长生命周期 agent 被单次错误过度惩罚
- 同一 session 内的罚分上限 = 10（等于 1 次 critical），避免重试风暴放大惩罚

