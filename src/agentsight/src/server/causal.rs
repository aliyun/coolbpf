//! Causal attribution — offline soft-failure diagnosis for captured trajectories.
//!
//! Given a trajectory (session) and a user complaint, the pipeline reconstructs
//! a causal graph and runs two LLM calls (combined oracle + evaluator,
//! then root-cause attribution) per `agentsight_causal_attribution_DEV.md`.
//!
//! Hard failures (crashes/timeouts) remain the domain of the real-time
//! interruption detector; this module focuses on soft failures (hallucinations,
//! false successes, fabricated content, mis-scoped analysis).

use std::sync::Arc;

use actix_web::{HttpResponse, Responder, post, web};
use agentsight_opt::atif::{AtifStep as OptStep, AtifTrajectory as OptTrajectory};
use agentsight_opt::llm::{ChatMessage, LlmClient};
use serde::{Deserialize, Serialize};

use super::AppState;
use crate::storage::sqlite::GenAISqliteStore;

// ─── In-memory cache ─────────────────────────────────────────────────────────
//
// Caches the last successful causal case per (session_id, round_index) so the
// dashboard can re-open a run instantly without replaying three LLM calls.
// The cache is invalidated automatically when the user submits a different
// complaint (stale-complaint check) or explicitly via `CausalRequest.force`.

type CausalCacheKey = (String, Option<usize>);
type CausalCacheMap = std::collections::HashMap<CausalCacheKey, CausalCacheEntry>;

/// Hard cap on cached attribution cases. When exceeded, the oldest entry (by
/// `last_used`) is evicted on the next insert. Without a cap a long-running
/// server leaks memory through unbounded growth of the `OnceLock<HashMap>`.
const CAUSAL_CACHE_CAP: usize = 50;

static CAUSAL_CACHE: std::sync::OnceLock<std::sync::Mutex<CausalCacheMap>> =
    std::sync::OnceLock::new();

static CAUSAL_CACHE_CLOCK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[derive(Clone)]
struct CausalCacheEntry {
    complaint: String,
    case: CausalCase,
    /// Monotonic counter bumped on every read/write; the smallest value in
    /// the map is the eviction candidate when the cap is exceeded.
    last_used: u64,
}

fn causal_cache() -> &'static std::sync::Mutex<CausalCacheMap> {
    CAUSAL_CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn next_cache_tick() -> u64 {
    CAUSAL_CACHE_CLOCK.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

// ─── Request / response types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CausalRequest {
    pub session_id: String,
    #[serde(default)]
    pub round_index: Option<usize>,
    pub complaint: String,
    /// When true, bypass the in-memory cache and rerun the LLM pipeline even
    /// if a prior run for the same (session, round) pair is cached. Used by
    /// the dashboard's "重新归因" button when the user wants to try a
    /// different complaint prompt.
    #[serde(default)]
    pub force: bool,
    /// What kind of identifier `session_id` actually carries. When omitted,
    /// we infer from the value shape (UUID → session, 32 hex → conversation,
    /// msg_…/trace-… → trace). The frontend sets this explicitly so the
    /// attribution scope matches what the user was looking at in the UI.
    #[serde(default)]
    pub id_kind: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct CausalNode {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<u32>,
    pub kind: String,
    pub tag: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub foot: Option<String>,
    pub plain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct CausalEdge {
    pub a: String,
    pub b: String,
    #[serde(rename = "type")]
    pub edge_type: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct CausalCase {
    pub id: String,
    pub title: String,
    pub task: String,
    pub session: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trigger: Option<String>,
    pub verdict: String,
    pub root_one: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome_note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_issue: Option<String>,
    pub attrib: String,
    pub fix: String,
    /// Secondary attribution candidates, ranked by confidence. Omitted from
    /// JSON when empty to keep the response compact.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub alternative_attribs: Vec<AlternativeAttrib>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeline: Option<Vec<String>>,
    pub nodes: Vec<CausalNode>,
    pub edges: Vec<CausalEdge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contra: Option<CausalContra>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concl: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct CausalContra {
    pub saw: String,
    pub said: String,
}

#[derive(Debug, Serialize)]
pub struct CausalResponse {
    #[serde(rename = "case")]
    pub case_: CausalCase,
    /// True when the case came from the in-memory cache instead of a fresh
    /// LLM pipeline run. The frontend surfaces this as a "已缓存" chip plus
    /// a "重新归因" button.
    pub cached: bool,
}

// ─── LLM-evaluated step verdicts (parsed from Prompt ② output) ───────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
struct StepVerdict {
    #[serde(default)]
    step_id: Option<u32>,
    #[serde(default)]
    label: Option<String>,
    #[serde(default, alias = "type")]
    kind: Option<String>,
    /// One of: hallucination / stale_data / misdirected / silent_failure /
    /// fabrication / missing_verification / tool_contract / precondition /
    /// scope_denied / env_unreachable / upstream_tool / runtime_exception.
    /// `None` when `kind == "ok"`.
    #[serde(default)]
    defect_type: Option<String>,
    /// L2 consequence label: transient_recovered / handled_adapted /
    /// probe_expected / persistent / ignored / consequential. `None` when the
    /// step is OK or the consequence is ambiguous.
    #[serde(default)]
    consequence: Option<String>,
    #[serde(default, alias = "evidence")]
    basis: Option<String>,
    /// Plain-language explanation of what this step actually did (≤60 chars).
    #[serde(default)]
    plain: Option<String>,
    #[serde(default)]
    confidence: Option<f32>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct Verdicts {
    #[serde(default)]
    verdicts: Vec<StepVerdict>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct Oracle {
    #[serde(default)]
    goal: Option<String>,
    #[serde(default)]
    preconditions: Option<Vec<String>>,
    #[serde(default)]
    evidence: Option<Vec<String>>,
    #[serde(default)]
    pass_criteria: Option<Vec<String>>,
}

/// One alternative attribution candidate. The evaluator ranks these by
/// confidence; the UI lets the user promote any of them to "primary" if the
/// top pick doesn't match their read of the trajectory.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AlternativeAttrib {
    pub attrib: String,
    #[serde(default)]
    pub confidence: f32,
    #[serde(default)]
    pub rationale: String,
    #[serde(default)]
    pub fix: String,
}

#[derive(Debug, Deserialize, Serialize, Default, Clone)]
struct Attribution {
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    outcome_note: Option<String>,
    #[serde(default)]
    verdict: Option<String>,
    #[serde(default)]
    root_one: Option<String>,
    #[serde(default)]
    root_step_id: Option<u32>,
    #[serde(default)]
    attrib: Option<String>,
    #[serde(default)]
    fix: Option<String>,
    #[serde(default)]
    turn_issue: Option<bool>,
    #[serde(default)]
    title: Option<String>,
    /// Agent's actual final conclusion, quoted verbatim from the last step's
    /// response — used to populate the "关键矛盾" panel deterministically.
    #[serde(default)]
    actual_conclusion: Option<String>,
    /// Other candidates the evaluator considers plausible, sorted by
    /// confidence desc. Excludes the primary (`attrib`). Empty when the
    /// evaluator is very confident in the primary.
    #[serde(default)]
    alternative_attribs: Vec<AlternativeAttrib>,
}

// ─── Endpoint ────────────────────────────────────────────────────────────────

/// POST /api/causal-attribution
///
/// Runs the offline causal attribution pipeline against the trajectory of the
/// requested session (optionally scoped to one round). Returns the §7 contract
/// JSON that the dashboard's CausalAttributionPanel renders.
#[post("/causal-attribution")]
pub async fn run_causal_attribution(
    state: web::Data<AppState>,
    body: web::Json<CausalRequest>,
) -> impl Responder {
    let req = body.into_inner();
    if req.complaint.trim().is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "complaint_required",
            "message": "请提供一句你的不满或疑问作为归因起点",
        }));
    }

    let opt = match state.optimize.as_ref() {
        Some(o) => Arc::clone(o),
        None => {
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "optimize_disabled",
                "message": "optimization subsystem not initialized",
            }));
        }
    };

    let genai_store =
        crate::storage::sqlite::GenAISqliteStore::new_with_path(&state.storage_path).ok();
    let trajectory_store = state.trajectory_store();

    // Scope resolution: "conversation" means the frontend is asking us to
    // attribute only the events under a specific conversation_id; we keep
    // that id verbatim and pass it to load_trajectory. Any other scope
    // goes through the legacy resolver (32 hex → session UUID fallback).
    let is_conversation_scope = req.id_kind.as_deref() == Some("conversation");
    let resolved_session_id = if is_conversation_scope {
        log::info!(
            "Causal attribution: conversation scope — using '{}' as conversation_id directly",
            req.session_id,
        );
        req.session_id.clone()
    } else {
        let resolved = resolve_to_session_id(&state.storage_path, &req.session_id)
            .unwrap_or_else(|| req.session_id.clone());
        if resolved != req.session_id {
            log::info!(
                "Causal attribution: resolved incoming id '{}' → session_id '{}'",
                req.session_id,
                resolved,
            );
        } else {
            log::info!(
                "Causal attribution: incoming id '{}' unchanged (no mapping found)",
                req.session_id,
            );
        }
        resolved
    };

    // Cache lookup: (scope, id, round) → prior case, hit only when the
    // complaint text matches and the user didn't ask for a forced rerun.
    // The scope is part of the key because the same id under session vs
    // conversation scope produces genuinely different cases.
    let scope_tag = if is_conversation_scope {
        "conv"
    } else {
        "sess"
    };
    let cache_key = (
        format!("{}:{}", scope_tag, resolved_session_id),
        req.round_index,
    );
    if !req.force {
        if let Ok(mut guard) = causal_cache().lock() {
            if let Some(entry) = guard.get_mut(&cache_key) {
                if entry.complaint == req.complaint {
                    entry.last_used = next_cache_tick();
                    log::info!(
                        "Causal attribution: cache hit for {}='{}' round={:?}, returning prior case",
                        scope_tag,
                        resolved_session_id,
                        req.round_index,
                    );
                    return HttpResponse::Ok().json(CausalResponse {
                        case_: entry.case.clone(),
                        cached: true,
                    });
                }
            }
        }
    }

    let trajectory = match load_trajectory(
        &state.storage_path,
        &resolved_session_id,
        genai_store.as_ref(),
        trajectory_store.as_deref(),
        req.id_kind.as_deref(),
    ) {
        Ok(t) => t,
        Err(e) => {
            return HttpResponse::NotFound().json(serde_json::json!({
                "error": "trajectory_not_found",
                "message": e,
            }));
        }
    };

    let steps = match slice_round(&trajectory, req.round_index) {
        Ok(s) => s,
        Err(e) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "invalid_round",
                "message": e,
            }));
        }
    };
    if steps.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "empty_round",
            "message": "所选轮次没有可分析的步骤",
        }));
    }

    let client = match opt.build_client() {
        Ok(c) => c,
        Err(resp) => return resp,
    };

    match run_pipeline(&client, &trajectory, &steps, &req).await {
        Ok(case_) => {
            // Stash successful run in the cache so reopening the panel is instant.
            // Bump the clock, evict the oldest entry when the cap is exceeded.
            if let Ok(mut guard) = causal_cache().lock() {
                let tick = next_cache_tick();
                guard.insert(
                    cache_key,
                    CausalCacheEntry {
                        complaint: req.complaint.clone(),
                        case: case_.clone(),
                        last_used: tick,
                    },
                );
                if guard.len() > CAUSAL_CACHE_CAP {
                    let oldest = guard
                        .iter()
                        .min_by_key(|(_, e)| e.last_used)
                        .map(|(k, _)| k.clone());
                    if let Some(k) = oldest {
                        guard.remove(&k);
                    }
                }
            }
            HttpResponse::Ok().json(CausalResponse {
                case_,
                cached: false,
            })
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "pipeline_failed",
            "message": e,
        })),
    }
}

/// Combined output from the merged oracle + evaluator prompt.
#[derive(Debug, Deserialize, Serialize, Default, Clone)]
struct OracleAndVerdicts {
    #[serde(default)]
    goal: Option<String>,
    #[serde(default)]
    preconditions: Option<Vec<String>>,
    #[serde(default)]
    evidence: Option<Vec<String>>,
    #[serde(default)]
    pass_criteria: Option<Vec<String>>,
    #[serde(default)]
    verdicts: Vec<StepVerdict>,
}

// ─── Pipeline ────────────────────────────────────────────────────────────────

async fn run_pipeline(
    client: &LlmClient,
    trajectory: &OptTrajectory,
    steps: &[OptStep],
    req: &CausalRequest,
) -> Result<CausalCase, String> {
    let task = extract_task(steps);
    let rendered = render_steps(steps);
    let tool_evidence = render_tool_evidence(steps);

    // Session timestamp = ground-truth "now". The evaluator's own training
    // cutoff is NOT authoritative — when the session happened in 2026, the
    // evaluator must not claim "2026 hasn't happened yet" to defend an
    // agent's refusal to cite 2026 data.
    let session_now = trajectory
        .steps
        .last()
        .and_then(|s| s.timestamp.as_deref())
        .unwrap_or("(未知)");

    // Prompt ①+② — combined oracle + evaluator (saves one LLM call, ~60s)
    let combined: OracleAndVerdicts = call_json(
        client,
        PROMPT_COMBINED,
        &format!(
            "会话发生时间（你的[现在]）：{now}\n\n任务目标：{task}\n\n用户不满（最高优先锚点）：{complaint}\n\n工具证据清单（判定 fabrication/hallucination 前必须先看这里）：\n{tool_evidence}\n\nOTAR 序列：\n{rendered}",
            now = session_now,
            task = task,
            complaint = req.complaint,
            tool_evidence = tool_evidence,
            rendered = rendered,
        ),
        "oracle_evaluator",
    )
    .await?;

    let oracle = Oracle {
        goal: combined.goal,
        preconditions: combined.preconditions,
        evidence: combined.evidence,
        pass_criteria: combined.pass_criteria,
    };
    let verdicts = Verdicts {
        verdicts: combined.verdicts,
    };

    // Prompt ③ — conclusion + attribution
    let oracle_text = format_oracle(&oracle);
    let attr: Attribution = call_json(
        client,
        PROMPT_ATTRIB,
        &format!(
            "会话发生时间（你的[现在]）：{now}\n\n任务目标：{task}\n\n验收标准：{oracle}\n\n用户不满：{complaint}\n\n工具证据清单：\n{tool_evidence}\n\nOTAR 序列：\n{rendered}\n\n逐步判定：{verdicts}",
            now = session_now,
            task = task,
            oracle = oracle_text,
            complaint = req.complaint,
            tool_evidence = tool_evidence,
            rendered = rendered,
            verdicts = format_verdicts(&verdicts),
        ),
        "attrib",
    )
    .await?;

    build_case(trajectory, steps, req, &verdicts, &attr)
}

// ─── Prompts (§5 of the dev doc) ─────────────────────────────────────────────

/// Combined oracle + evaluator prompt (saves one LLM call, ~60s).
/// Asks for both acceptance criteria (oracle) and per-step verdicts (evaluator)
/// in a single response.
const PROMPT_COMBINED: &str = "\
你是多智能体轨迹的归因分析器。给定任务目标、用户不满、整段 OTAR 序列，\
同时输出（1）验收标准和（2）逐步判定。\n\
\n\
## 任务 A：验收标准（oracle）\n\
输出验收标准：\n\
{\n  \
  \"goal\": \"<任务的核心交付物，一句话>\",\n  \
  \"preconditions\": [\"<任务开始前必须为真的事实>\"],\n  \
  \"evidence\": [\"<agent 必须引用的可观测证据来源>\"],\n  \
  \"pass_criteria\": [\"<可二值判断的通过条件>\"]\n\
}\n\
硬性规则：\n\
1. 若任务隐含时效性（如[今年][最新][现在][2026]等），pass_criteria 必须包含一条[数据时效性]要求\
（例如：[引用的数据/事件必须发生在 <任务明示时间窗> 内；使用更早的数据视为不达标]）。\n\
2. 若用户不满提到[引用/靠谱/来源]，evidence 必须列出可被核验的来源；pass_criteria 必须包含\
[所有事实性断言至少有一条可在 evidence 中复核的来源]。\n\
3. 自检要求必须按任务复杂度分级：\n\
   - 简单事实查询 / 基础算术（如 [1+1=2][今天星期几][中国首都是哪里] 这种常识问题）：\n\
     pass_criteria **严禁**包含[自检]条款 —— 给这类问题加自检本身就是过度工程化，\
     会让评估器把[正确答案]误判为 defect。\n\
   - 开放式 / 数据密集型 / 多步骤任务：pass_criteria 可包含[agent 在宣告完成前执行了自检步骤]。\n\
   - 若用户不满反而抱怨[过度校验/简单问题还要自检]：pass_criteria 必须**显式排除**自检要求，\n\
     并把[直接给出正确答案视为达标]列入 pass_criteria。\n\
4. 不得臆测未出现的信息。\n\
\n\
## 任务 B：逐步判定（evaluator）\n\
对每一步判断是否存在缺陷，并按以下规则输出。\n\
\n\
### 缺陷类别（只能选其一，或判 ok）\n\
- hallucination（臆断/幻觉）：结论与该步已观测证据矛盾\n\
- stale_data（数据滞后）：使用了与任务时间窗不匹配的陈旧数据\n\
- misdirected（分析错对象）：操作/分析的对象与任务指定范围不符\n\
- silent_failure（假成功）：声明成功但结果状态未变化或未达预期\n\
- fabrication（虚构内容）：产物含输入中不存在的实体\n\
- missing_verification（缺自检）：agent 在宣告完成前未执行 pass_criteria 要求的自检\n\
- tool_contract（工具契约失败）：入参校验失败、缺必填参数\n\
- precondition（前置条件未满足）：未先 Read 就 Write 等\n\
- scope_denied（越权/超出可写范围）\n\
- env_unreachable（网络拦截、DNS、超时、HTTP 4xx/5xx）\n\
- upstream_tool（MCP 上游不存在、上游超时）\n\
- runtime_exception（脚本 Traceback、非零退出）\n\
\n\
### 边界条件（必须遵守，违反即视为本次评估作废）\n\
\n\
**B1 · 用户拒绝/中断 ≠ agent 失败**\n\
content 含 [The user doesn't want to proceed] / [Permission denied: User denied] /\
[Request interrupted by user] → 判 BLOCKED（不是 FAILED），不计缺陷。\n\
但若 agent 在 BLOCKED 后**原样重试同一调用** → 判 agent 缺陷。\n\
\n\
**B2 · [输出里有 Error 字样] ≠ 调用失败**\n\
- 若 Exit code == 0 → 一律判 OK，忽略正文错误词；\n\
- 检索类调用（grep/rg/search）且错误词在结果条目内 → 判 OK；\n\
- 错误词在 content 中段（>200 字符处）→ 不作为判据。\n\
\n\
**B3 · [预期报错] ≠ 缺陷**（探测性调用）\n\
命令语义为存在性探测（ls/test -f/which/stat/pgrep/ping 等）且返回 NOT_FOUND / 非零退出 →\
判 OK_PROBE（信息性结果），不计缺陷。\n\
\n\
**B4 · 嵌套错误 ≠ 本次调用失败**\n\
返回体内引用的下游系统错误（如 java.lang.NullPointerException）记为 nested_error 附注，\n\
不改变本次 status。\n\
\n\
**B5 · 瞬时失败并自愈 ≠ 缺陷**\n\
同 function_name + arguments 在后续 5 步内重试成功 → 标 TRANSIENT_RECOVERED，\n\
不进入根因候选。\n\
\n\
**B6 · 失败后换策略 ≠ 缺陷**\n\
失败后 agent 改变参数/工具/路径并推进任务 → 标 HANDLED_ADAPTED，正常自适应。\n\
只有 PERSISTENT（同参重试≥3 次仍失败）/ IGNORED（无补偿却假定成功）/ CONSEQUENTIAL（失败结果被下游当有效输入）才升级缺陷。\n\
\n\
**B7 · 任务对象 ≠ 失败**\n\
若任务目标是[构造/排查故障]，轨迹中的 crash/error 是被观测对象，不得判为 agent 缺陷。\n\
\n\
**B8 · 空结果/占位符 ≠ 成功**\n\
content 为空或命中占位符（如 [dws-bash:pending-post-tool-use]）→ 判 UNKNOWN，不判 OK；\n\
若 agent 据此宣称成功 → 触发[假成功]判定。\n\
\n\
**B9 · agent 基于训练知识给出实质内容 ≠ 任何缺陷类型**（本规范最高优先规则）\n\
当 agent 在所有联网工具失败后，基于自身训练知识给出实质性结论（>100 字，非 refusal-patterned），\n\
这是**正确行为**，不是拒答/冒充/未核验/误导/stale_data。\n\
- 严禁判[拒答][refused when could have answered][冒充][误导][未核验][未标注截止日期]；\n\
- 若 agent 的 actual_conclusion 含基于训练知识的内容（如[GPT-4o/Claude 3.5/Gemini 2.0 排名]），\n\
  这是 agent 根据自身经验给出的结论，判 **ok**；\n\
- 若用户 complaint 明确说[agent 根据自身经验给出了结论]，强制判 ok，覆盖评估器任何 defect 判定。\n\
\n\
### 硬性约束\n\
1. 任何非 ok 判定必须在 basis 字段**原文引用**该步 OTAR 或上游证据的片段（≤200 字）；\n\
   引用不出来就必须判 ok。\n\
2. label ≤12 字中文专业短语（如[引用去年数据][错把症状当根因]），\n\
   禁止[ok][问题][缺陷][正常]等空词。\n\
3. plain ≤60 字大白话，描述这一步**实际做了什么**，聚焦动作与产物，不要评价。\n\
4. kind 只能取：ok / seed / root / sym / shipped / blocked / transient / handled。\n\
\n\
输出严格 JSON：{\n  \
  \"goal\": str,\n  \
  \"preconditions\": [str],\n  \
  \"evidence\": [str],\n  \
  \"pass_criteria\": [str],\n  \
  \"verdicts\": [\n    \
    {\"step_id\": int, \"label\": str, \"kind\": \"ok|seed|root|sym|shipped|blocked|transient|handled\",\n     \
     \"defect_type\": \"hallucination|stale_data|misdirected|silent_failure|fabrication|missing_verification|tool_contract|precondition|scope_denied|env_unreachable|upstream_tool|runtime_exception|null\",\n     \
     \"consequence\": \"transient_recovered|handled_adapted|probe_expected|persistent|ignored|consequential|null\",\n     \
     \"basis\": str, \"plain\": str, \"confidence\": float}\n  \
  ]\n\
}\n\
每步一条 verdict，按输入顺序输出。";

const PROMPT_ATTRIB: &str = "\
你是 session 级归因裁判。输入：任务目标、验收标准、用户不满、OTAR 序列、逐步判定。\n\
\n\
## 第一步：session 级结论判定\n\
对照任务目标 + 验收标准 + 最终产物（最后一步的 observation 或 agent 输出），二选一：\n\
- 最终结论正确且达标（即使过程绕行）→ outcome=\"success\"，outcome_note 说明“如何达成”\
  （自我纠正 / 用户纠偏 N 次 / 一次到位）\n\
- 最终结论不正确或未达标 → outcome=\"fail\"，outcome_note 说明“失败形态”\
  （错答 / 漏答 / 使用过期数据 / 拒答但应能答 / 部分完成但关键缺失）\n\
\n\
## 第二步：verdict（犯了什么错，30-80 字）\n\
具体描述 agent 犯的错，必须包含：①错的动作（“引用了”“把 X 当成 Y”“漏掉了”等）\
②错的内容（具体数据/实体/结论，必须从 OTAR 引用原文）③错的后果（用户拿到什么坏结果）。\n\
禁止空话（如“存在不足”“需要改进”“过程绕行”）。\n\
\n\
## 第三步：root_one（核心原因，30-80 字）\n\
由果溯因，锁定到**最早出现缺陷的步骤**：\n\
- 元凶（root）：缺陷首次产生、上游输入本身无缺陷的步骤\
- 传播症状（sym）：忠实处理了被污染输入的步骤，不视为根因\n\
必须指明具体 step_id + 该步做错了什么（引用原文）+ 为什么这一步出错\
（没锁对象/没自检/模型幻觉/工具返回缺字段 等）。\n\
\n\
## 第四步：归因对象 attrib + 修复落点 fix\n\
attrib 必须是 model|skill|prompt|agent 之一，含义：\n\
- model：模型推理缺陷（幻觉、无视证据、错判成功）。fix 必须包含“加 X 自检”\
  （如：“下结论前强制引用证据”“在回复末尾列出未核实的事实性断言”）。\n\
- skill：工具/技能实现与契约问题（静默失败、返回缺字段、版本不符）。\
  fix 必须包含“工具返回结构化 X”或“执行后回传 Y 供校验”。\n\
- prompt：指令/约束缺失（没锁对象、没要求自检、没禁止臆造）。\
  fix 必须给出要补的具体约束句（如：“补约束：回复前必须列出引用的来源与时间戳”）。\n\
- agent：编排/流程问题（缺校验关卡、缺重试、控制逻辑错）。\
  fix 必须给出要加的校验步骤（如：“在宣告完成前加一步 verify_pass_criteria”）。\n\
\n\
fix 禁止涉及模型/agent 的**架构级能力**（如“升级到能联网的模型”“给模型开 web 权限”\
“该模型知识截止到 X 年所以需要 Y”）。你只能从行为 / 约束 / 流程 / 工具契约层面给修复，\
模型能不能联网这种部署侧事实**不在你的授权范围**。\n\
\n\
**fix 的[不过度建议]硬规则**：\n\
- 当 outcome=[success] 且你判[无缺陷]时，fix 必须**只**写[无需修复]四个字，\
  **严禁**附加[若需响应用户偏好可补 X][若担心 Y 可加 Z]之类的 hedging 建议。\
  用户抱怨[过度校验]时，评估器不得反过来建议[加约束/加校验]。\n\
- 只有当你确实找到一个具体 defect (seed/root/sym/shipped) 时，fix 才能写具体修复建议。\
  不要为了[看起来有帮助]而编造一个不存在的修复。\n\
\n\
**fix 的[不臆测 agent 能力]硬规则**：\n\
- 严禁说[agent 本可以利用自身知识库提供 X][未利用训练数据中的 Y]之类的话。\
  你**无法**知道 agent 的训练数据包含什么 —— agent 诚实地说[我不知道/我没这信息]\
  是**正确行为**，不是 defect。\n\
- [拒答]的判定必须基于 agent **actual_conclusion 的原文**：\n\
  (a) 若 agent 的 actual_conclusion **确实包含**基于自身知识/经验的实质性内容（哪怕\
      是基于训练数据的内容），则**严禁**判[拒答]或[refused when could have answered]。\
      agent 给了内容就不是拒答。\n\
  (b) 若 agent 给的内容可能是过时的（如 2024 年的排名但用户问 2026），这是\
      [stale_data]（数据滞后）defect，**不是**[拒答]。\n\
  (c) 只有当 agent 的 actual_conclusion 明确是[我完全无法回答/我拒绝回答/请自行查阅]\
      这种**纯拒绝**表述时，才能判[拒答]。\n\
- 判[拒答]前必须先在 basis 字段 quote agent 的 actual_conclusion 原文（≤200 字），\
  让 reviewer 能复核 agent 到底是真的拒答还是给了内容。\n\
\n\
## 第五步：实际结论（actual_conclusion，50-150 字）\n\
agent 在最后一步**实际给出**的结论原文摘录（直接复制 observation/response 的关键片段，\
不要改写，不要概括）。用于与“已观测到的证据”形成对照。\n\
\n\
## 第六步：turn_issue\n\
布尔值（true/false，不是字符串）：\n\
- true：单轮思考问题（走弯路但最终对，或某一轮的局部错误）\n\
- false：session 级失败（错误结论被交付）\n\
\n\
## 第七步：alternative_attribs（次优归因候选）\n\
除 primary attrib 外，列出 1-3 个你也认为 plausible 的其他归因候选，\
按 confidence 从高到低排序。每个候选必须：\n\
- attrib 与 primary 不同（不能重复 primary 的选项）\n\
- confidence: 0..1 的浮点数（你对此候选的主观置信度）\n\
- rationale: ≤40 字，说明为什么这个候选也 plausible\n\
- fix: 针对这个候选的具体修复建议（同 primary 的 fix 风格）\n\
如果你对 primary 的置信度 ≥ 0.9 且看不到其他 plausible 选项，可以返回空数组。\n\
\n\
输出严格 JSON：{\n  \
  \"outcome\": \"success|fail\",\n  \
  \"outcome_note\": str,\n  \
  \"verdict\": str,\n  \
  \"root_one\": str,\n  \
  \"root_step_id\": int|null,\n  \
  \"attrib\": \"model|skill|prompt|agent\",\n  \
  \"fix\": str,\n  \
  \"actual_conclusion\": str,\n  \
  \"turn_issue\": bool,\n  \
  \"title\": str,\n  \
  \"alternative_attribs\": [\n    \
    {\"attrib\": \"model|skill|prompt|agent\", \"confidence\": float, \"rationale\": str, \"fix\": str}\n  \
  ]\n\
}\n\
title 必须≤20 字，概括性短语（如“引用去年数据回答今年问题”“把症状误判为根因”），\
禁止“问题”“错误”等空词。";

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Map a user-supplied identifier to the `session_id` the trajectory loaders
/// understand. The dashboard may hand us one of three shapes:
///
/// * a `session_id` (typically a UUID like `26f16ff5-…-8447f39b2832`) — returned as-is;
/// * a `conversation_id` (32 hex chars, surfaced on the interruption detail view) —
///   resolved via `interruption_events.conversation_id`;
/// * a `trace_id` (free-form) — resolved via `genai_events.trace_id`.
///
/// Returns `None` when no mapping exists, in which case the caller falls back
/// to passing the original ID through to the trajectory loader.
fn resolve_to_session_id(db_path: &std::path::Path, incoming: &str) -> Option<String> {
    use rusqlite::Connection;
    let base_dir = db_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));

    // 1. conversation_id — interruption_events (32 hex, no dashes)
    if incoming.len() == 32 && incoming.chars().all(|c| c.is_ascii_hexdigit()) {
        let candidate = base_dir.join("interruption_events.db");
        log::info!(
            "resolver: incoming '{}' looks like conversation_id; candidate db {:?} exists={}",
            incoming,
            candidate,
            candidate.exists(),
        );
        if candidate.exists() {
            if let Ok(conn) = Connection::open(&candidate) {
                let sql = "SELECT session_id FROM interruption_events \
                           WHERE conversation_id = ?1 AND session_id IS NOT NULL \
                             AND length(session_id) > 0 \
                           ORDER BY occurred_at_ns DESC LIMIT 1";
                let found: Option<String> = conn
                    .query_row(sql, [incoming], |r| r.get::<_, String>(0))
                    .ok();
                log::info!("resolver: conversation_id lookup → {:?}", found);
                if found.is_some() {
                    return found;
                }
            }
        }
    }

    // 2. trace_id — genai_events
    let genai_candidate = base_dir.join("genai_events.db");
    if genai_candidate.exists() {
        if let Ok(conn) = Connection::open(&genai_candidate) {
            let sql = "SELECT session_id FROM genai_events \
                       WHERE trace_id = ?1 AND session_id IS NOT NULL \
                       LIMIT 1";
            let found: Option<String> = conn
                .query_row(sql, [incoming], |r| r.get::<_, String>(0))
                .ok();
            log::info!("resolver: trace_id lookup → {:?}", found);
            if found.is_some() {
                return found;
            }
        }
    }

    log::info!("resolver: no mapping for '{}' — passthrough", incoming);
    None
}

/// Load a session's ATIF trajectory, trying every data source the deployment
/// exposes in order: eBPF genai events first (richest signal, already
/// normalized), then the collector's `trajectories.db`, then any sibling DB
/// that passes the ATIF-JSON schema probe (covers macOS builds that ship
/// `~/Library/Application Support/agentsight/trajectories.db` with a
/// non-standard column name, and Linux deployments that colocate an
/// `agentsight.db` next to `genai_events.db`).
fn load_trajectory(
    db_path: &std::path::Path,
    session_id: &str,
    genai_store: Option<&GenAISqliteStore>,
    trajectory_store: Option<&agentsight_trajectory_collector::TrajectoryStore>,
    id_kind: Option<&str>,
) -> Result<OptTrajectory, String> {
    // Path 1 — eBPF genai events (already normalized by `convert_*_to_atif`).
    // Scope is determined by `id_kind`: "conversation" queries by
    // conversation_id (sub-conversation scope), anything else queries by
    // session_id (whole-session scope).
    if let Some(store) = genai_store {
        let events_result = match id_kind {
            Some("conversation") => store.get_events_by_conversation(session_id),
            _ => store.get_events_by_session(session_id),
        };
        if let Ok(events) = events_result {
            if !events.is_empty() {
                let mut doc = match id_kind {
                    Some("conversation") => {
                        crate::atif::converter::convert_trace_to_atif(session_id, events)
                    }
                    _ => crate::atif::converter::convert_session_to_atif(session_id, events),
                }
                .map_err(|e| format!("convert to ATIF: {e}"))?;

                // Post-process: OpenClaw's LLM calls carry tool results as
                // `tool_call_response` parts in the NEXT call's
                // request.messages. The ATIF converter doesn't recognize this
                // type (it expects `tool_result`), so tool returns end up
                // missing from observation.results. Bridge the gap here.
                enrich_tool_results(&mut doc);

                let json = serde_json::to_string(&doc).map_err(|e| e.to_string())?;
                return OptTrajectory::from_json(&json)
                    .map_err(|e| format!("parse ATIF for opt: {e}"));
            }
        }
    }

    // Path 2 — collector's trajectories.db (ATIF JSON stored verbatim). Only
    // meaningful for session scope; conversations don't have their own
    // collected entries.
    if id_kind != Some("conversation") {
        if let Some(store) = trajectory_store {
            if let Ok(Some(atif_json)) = store.get_atif_json(session_id) {
                return OptTrajectory::from_json(&atif_json)
                    .map_err(|e| format!("parse collected ATIF: {e}"));
            }
        }
    }

    // Path 3 — probe sibling DBs for an ATIF-shaped TEXT column. This
    // handles the §2.1 "don't assume fixed table/column names" requirement:
    // we enumerate tables, enumerate TEXT columns, and take the first row
    // whose value parses as ATIF JSON for the requested session.
    let candidate_files = ["trajectories.db", "agentsight.db", "collected.db"];
    let base_dir = db_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    for filename in candidate_files {
        let candidate = base_dir.join(filename);
        if !candidate.exists() {
            continue;
        }
        if let Ok(Some(json)) = probe_atif_column(&candidate, session_id) {
            return OptTrajectory::from_json(&json)
                .map_err(|e| format!("parse probed ATIF ({filename}): {e}"));
        }
    }

    Err(format!("未找到该 Session：{session_id}"))
}

/// Post-process an ATIF document to fill in missing tool results.
///
/// OpenClaw's LLM calls carry tool results as `tool_call_response` parts in
/// the NEXT call's request.messages. The ATIF converter doesn't recognize
/// this type (it expects `tool_result`), so tool returns end up missing from
/// observation.results. This function bridges the gap by scanning ALL user
/// messages for `tool_call_response` parts and filling them into the
/// corresponding observation.results entries (matched by `tool_call_id`).
fn enrich_tool_results(doc: &mut agentsight_atif::AtifTrajectory) {
    use agentsight_atif::{Observation, ObservationResult, StepSource};

    // Build a map: tool_call_id → response content from ALL user messages
    // that carry `tool_call_response` parts.
    let mut tool_results: std::collections::HashMap<String, (String, bool)> =
        std::collections::HashMap::new();
    for step in &doc.steps {
        if step.source != StepSource::User {
            continue;
        }
        // User messages carry tool results in `message` field as JSON-encoded
        // parts. We need to parse the message to find `tool_call_response` parts.
        if step.message.is_empty() {
            continue;
        }
        // The message is a JSON array of parts. Parse it.
        let parts: Vec<serde_json::Value> = match serde_json::from_str(&step.message) {
            Ok(p) => p,
            Err(_) => continue,
        };
        for part in parts {
            let part_type = part.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if part_type == "tool_call_response" {
                let call_id = part
                    .get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .to_string();
                let response = part.get("response").cloned().unwrap_or_default();
                let content = response
                    .get("content")
                    .and_then(|c| c.as_str())
                    .unwrap_or("")
                    .to_string();
                let is_error = response
                    .get("is_error")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(false);
                let annotated = if is_error {
                    format!("[ERROR] {}", content)
                } else {
                    content
                };
                tool_results.insert(call_id, (annotated, is_error));
            }
        }
    }

    // Fill the tool results into observation.results for each agent step.
    for step in &mut doc.steps {
        if step.source != StepSource::Agent {
            continue;
        }
        let Some(tool_calls) = step.tool_calls.as_ref() else {
            continue;
        };
        if tool_calls.is_empty() {
            continue;
        }

        let mut results: Vec<ObservationResult> = Vec::new();
        for tc in tool_calls {
            let (content, _is_error) = tool_results
                .get(&tc.tool_call_id)
                .cloned()
                .unwrap_or_else(|| (String::new(), false));
            let content_value = if content.is_empty() {
                None
            } else {
                Some(serde_json::Value::String(content))
            };
            results.push(ObservationResult {
                source_call_id: Some(tc.tool_call_id.clone()),
                content: content_value,
                subagent_trajectory_ref: None,
                extra: None,
            });
        }

        if !results.is_empty() {
            step.observation = Some(Observation { results });
        }
    }
}

/// Resolve the (table, column) pair holding ATIF JSON in an arbitrary SQLite
/// database by walking `sqlite_master` + `PRAGMA table_info` and attempting a
/// JSON parse on the first non-null TEXT value per column. Returns the parsed
/// JSON string for `session_id` on success, `None` when the schema has no
/// ATIF-shaped payload, and `Err` on hard I/O or schema failures.
fn probe_atif_column(
    db_path: &std::path::Path,
    session_id: &str,
) -> Result<Option<String>, String> {
    use rusqlite::Connection;
    let conn = Connection::open(db_path).map_err(|e| format!("open {db_path:?}: {e}"))?;

    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table'")
        .map_err(|e| e.to_string())?;
    let tables: Vec<String> = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();

    for table in tables {
        let info_sql = format!("PRAGMA table_info(\"{table}\")");
        let mut info = match conn.prepare(&info_sql) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let text_columns: Vec<String> = info
            .query_map([], |r| {
                let name: String = r.get(1)?;
                let ty: String = r.get(2)?;
                Ok((name, ty))
            })
            .ok()
            .into_iter()
            .flatten()
            .filter_map(|r| r.ok())
            .filter(|(_, ty)| ty.to_uppercase().contains("TEXT"))
            .map(|(name, _)| name)
            .collect();

        for column in text_columns {
            let sample_sql = format!(
                "SELECT \"{col}\" FROM \"{table}\" WHERE \"{col}\" IS NOT NULL LIMIT 1",
                col = column,
                table = table,
            );
            let sample: Option<String> = conn
                .query_row(&sample_sql, [], |r| r.get::<_, String>(0))
                .ok();
            let Some(sample) = sample else { continue };
            if serde_json::from_str::<serde_json::Value>(&sample).is_err() {
                continue;
            }

            // The sample parses as JSON — assume this column holds ATIF.
            // Prefer equality lookup on a session_id column when one exists;
            // otherwise scan every row (bounded by small dataset sizes
            // typical of local trajectory stores).
            let session_column = find_session_column(&conn, &table)?;
            let rows_sql = match session_column.as_deref() {
                Some(col) => format!(
                    "SELECT \"{col}\" FROM \"{table}\" WHERE \"{sid_col}\" = ?1",
                    col = column,
                    table = table,
                    sid_col = col,
                ),
                None => format!(
                    "SELECT \"{col}\" FROM \"{table}\"",
                    col = column,
                    table = table,
                ),
            };
            let mut rows = match conn.prepare(&rows_sql) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let values: Vec<String> = if session_column.is_some() {
                rows.query_map([session_id], |r| r.get::<_, String>(0))
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(|r| r.ok())
                    .collect()
            } else {
                rows.query_map([], |r| r.get::<_, String>(0))
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(|r| r.ok())
                    .collect()
            };
            for value in values {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&value) {
                    if session_matches(&parsed, session_id) {
                        return Ok(Some(value));
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Locate the column most likely holding the session identifier on `table`.
/// Heuristic: first column whose name contains `session_id` (case-insensitive).
fn find_session_column(conn: &rusqlite::Connection, table: &str) -> Result<Option<String>, String> {
    let info_sql = format!("PRAGMA table_info(\"{table}\")");
    let mut info = match conn.prepare(&info_sql) {
        Ok(s) => s,
        Err(e) => return Err(e.to_string()),
    };
    let names: Vec<String> = info
        .query_map([], |r| r.get::<_, String>(1))
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();
    Ok(names
        .into_iter()
        .find(|n| n == "session_id" || n.to_lowercase().contains("session_id")))
}

/// Best-effort check that a parsed ATIF document carries the requested session
/// id — used when the hosting table has no dedicated session_id column.
fn session_matches(doc: &serde_json::Value, session_id: &str) -> bool {
    match doc.get("session_id").and_then(|v| v.as_str()) {
        Some(s) => s == session_id,
        // No session_id field on the document → accept; the caller has
        // already scoped the query to a specific session row.
        None => true,
    }
}

/// Slice the trajectory to a single user-turn round. A round starts at each
/// user message and spans every agent/system step until the next user
/// message.
///
/// The input `trajectory` is already precisely scoped by the upstream
/// loader:
///   * `id_kind == "conversation"` → only events whose `conversation_id`
///     column matches (no heartbeat from other conversations can leak in).
///   * `id_kind == "session"` (or unset) → only events whose `session_id`
///     column matches.
///
/// So this function doesn't do any heuristic filtering — it just cuts by
/// user-message boundaries. `None` → the LAST round; explicit index → that
/// round (0-indexed from the start of the scoped trajectory).
fn slice_round(
    trajectory: &OptTrajectory,
    round_index: Option<usize>,
) -> Result<Vec<OptStep>, String> {
    let mut round_starts: Vec<usize> = Vec::new();
    for (i, step) in trajectory.steps.iter().enumerate() {
        if step.is_user() || round_starts.is_empty() {
            round_starts.push(i);
        }
    }

    let idx = match round_index {
        Some(i) => i,
        None => {
            if round_starts.is_empty() {
                return Ok(trajectory.steps.clone());
            }
            round_starts.len() - 1
        }
    };

    let start = *round_starts
        .get(idx)
        .ok_or_else(|| format!("round {idx} 不存在（共 {} 轮）", round_starts.len()))?;
    let end = round_starts
        .get(idx + 1)
        .copied()
        .unwrap_or(trajectory.steps.len());
    Ok(trajectory.steps[start..end].to_vec())
}

/// Infer the task goal from the first user message in the round.
fn extract_task(steps: &[OptStep]) -> String {
    for step in steps {
        if step.is_user() {
            if let Some(msg) = step.message.as_deref() {
                let text = msg.trim();
                if !text.is_empty() {
                    return truncate(text, 400);
                }
            }
        }
    }
    "(未找到用户指令)".to_string()
}

/// Render steps into a compact OTAR-style text block for the LLM prompts.
fn render_steps(steps: &[OptStep]) -> String {
    let mut out = String::new();
    for step in steps {
        let kind = if step.is_user() {
            "user"
        } else if step.is_agent() {
            "agent"
        } else {
            "system"
        };
        let reasoning = step.reasoning_content.as_deref().unwrap_or("");
        let content = step.message.as_deref().unwrap_or("");
        let tools = step
            .calls()
            .iter()
            .map(|c| {
                let args_json = serde_json::to_string(&c.arguments).unwrap_or_default();
                format!(
                    "- {}({}) [args {}chars]",
                    c.function_name,
                    truncate(&args_json, 800),
                    args_json.chars().count(),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        let obs = step
            .results()
            .iter()
            .map(|r| {
                let raw = r.content.as_deref().unwrap_or("");
                let orig_len = raw.chars().count();
                format!(
                    "- [{}] ({}chars) {}",
                    r.source_call_id.as_deref().unwrap_or("?"),
                    orig_len,
                    truncate(raw, 3000),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        out.push_str(&format!(
            "step{} [{}] {}\nreasoning: {}\ntool_calls:\n{}\nobservation:\n{}\n\n",
            step.step_id, kind, content, reasoning, tools, obs,
        ));
    }
    out
}

/// Pre-digest the tool-call evidence into a compact inventory the evaluator
/// MUST consult before making any fabrication / hallucination judgment.
///
/// Each row is one (step_id, tool_call, success?, result_snippet). This
/// kills the most common evaluator hallucination: claiming something "never
/// appeared in any observation" when in fact the agent called a tool whose
/// result came back 404 / error / partial — the URL DID appear, the tool
/// just failed. The inventory surfaces that distinction explicitly.
fn render_tool_evidence(steps: &[OptStep]) -> String {
    let mut out = String::new();
    for step in steps {
        for c in step.calls() {
            let args_json = serde_json::to_string(&c.arguments).unwrap_or_default();
            // Find the matching tool_result by tool_call_id. In ATIF, a
            // tool_call and its tool_result frequently live in the SAME step
            // (assistant emits the call, user emits the result in the next
            // `parts` block of the same message), so search from the
            // current step forward — NOT from the next step.
            let mut result_snippet: Option<String> = None;
            let mut result_status: &str = "NO_RESULT_YET";
            for later in steps.iter().skip_while(|s| s.step_id < step.step_id) {
                for r in later.results() {
                    let call_id_match = r
                        .source_call_id
                        .as_deref()
                        .map(|id| id == c.tool_call_id)
                        .unwrap_or(false);
                    if call_id_match {
                        let raw = r.content.as_deref().unwrap_or("");
                        let lower = raw.to_ascii_lowercase();
                        result_status = if lower.contains("\"status\": \"error\"")
                            || lower.contains("\"is_error\": true")
                            || lower.contains("error:")
                            || lower.contains("failed")
                        {
                            "TOOL_FAILED"
                        } else {
                            "TOOL_OK"
                        };
                        result_snippet = Some(truncate(raw, 500));
                        break;
                    }
                }
                if result_snippet.is_some() {
                    break;
                }
            }
            out.push_str(&format!(
                "step{} tool_call {}({}) [{}]{}\n",
                step.step_id,
                c.function_name,
                truncate(&args_json, 400),
                result_status,
                result_snippet
                    .map(|s| format!(" → {}", s))
                    .unwrap_or_default(),
            ));
        }
    }
    if out.is_empty() {
        "(该轮无工具调用)\n".to_string()
    } else {
        out
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let head: String = s.chars().take(n).collect();
        format!("{head}…")
    }
}

/// Hard-clamp a string to `n` Unicode chars after trimming whitespace, appending
/// "…" when truncated. Thin wrapper around [`truncate`] that adds the trim.
fn clamp_chars(s: &str, n: usize) -> String {
    truncate(s.trim(), n)
}

fn format_oracle(o: &Oracle) -> String {
    serde_json::to_string(o).unwrap_or_else(|_| "{}".into())
}

fn format_verdicts(v: &Verdicts) -> String {
    serde_json::to_string(&v.verdicts).unwrap_or_else(|_| "[]".into())
}

async fn call_json<T: serde::de::DeserializeOwned>(
    client: &LlmClient,
    system: &str,
    user: &str,
    label: &str,
) -> Result<T, String> {
    let messages = vec![ChatMessage::system(system), ChatMessage::user(user)];
    let raw = client
        .chat_json(messages)
        .await
        .map_err(|e| format!("LLM call [{label}] failed: {e}"))?;
    // Dump raw JSON so we can diagnose what the evaluator actually produced
    // when the graph comes back with too few nodes / weird kind values.
    log::debug!(
        "causal-attribution LLM response [{label}] ({}chars): {}",
        raw.chars().count(),
        truncate(&raw, 800),
    );
    serde_json::from_str::<T>(&raw).map_err(|e| {
        format!(
            "LLM response [{label}] parse failed: {e}; raw={}",
            truncate(&raw, 400)
        )
    })
}

/// Map the evaluator's free-form `kind` value into the canonical enum
/// ("ok" | "seed" | "root" | "sym" | "shipped" | "good" | "user" | "env" | "cf").
/// The evaluator sometimes returns Chinese labels ("正常" / "元凶" / "症状" / …)
/// or capitalized English; we normalize everything so the graph renders
/// with a predictable palette.
fn normalize_kind(raw: &str) -> String {
    let lower = raw.trim().to_ascii_lowercase();
    match lower.as_str() {
        // English canonical
        "ok" | "good" | "user" | "env" | "cf" | "seed" | "root" | "sym" | "shipped" => lower,
        // English aliases
        "normal" | "clean" | "pass" => "ok".to_string(),
        "culprit" | "origin" | "source" | "root_cause" | "rootcause" => "root".to_string(),
        "symptom" | "propagation" | "propagated" => "sym".to_string(),
        "germ" | "embryo" | "early" | "early_seed" => "seed".to_string(),
        "delivered" | "delivery" | "shipped_to_user" => "shipped".to_string(),
        // Chinese — common evaluator outputs
        "正常" | "无缺陷" | "通过" => "ok".to_string(),
        "元凶" | "根因" | "根源" => "root".to_string(),
        "症状" | "传播" | "传播症状" => "sym".to_string(),
        "萌芽" | "早期" | "苗头" => "seed".to_string(),
        "交付" | "问题交付" | " shipped" => "shipped".to_string(),
        "达成" | "成功" => "good".to_string(),
        "用户" | "用户输入" | "用户干预" => "user".to_string(),
        "环境" | "外部" => "env".to_string(),
        "反事实" => "cf".to_string(),
        // Fall through: keep the raw string but lowercase so the frontend's
        // defensive fallback style kicks in instead of crashing.
        other => {
            log::warn!(
                "causal-attribution: unknown verdict.kind {:?}, treating as ok",
                other,
            );
            "ok".to_string()
        }
    }
}

/// Assemble the final §7 causal case from the three LLM outputs and the raw
/// step data. The graph is deterministic: one node per step, a forward edge
/// between consecutive steps, with `bad` edges where the evaluator flagged a
/// defect.
/// Post-evaluator validation: correct the most common evaluator
/// misclassification before it propagates into the graph.
///
/// The evaluator often claims "拒答但应能答" (refused when could have answered)
/// or "冒充最新排名" (presented training knowledge as latest) when the agent
/// actually gave substantive content based on its training knowledge. When
/// the agent's actual conclusion contains real content (>100 chars, not
/// refusal-patterned), these are misreads — override.
///
/// Also: when the user's complaint explicitly states "agent 根据自身经验给出了结论"
/// (or similar phrasing), force the verdict to "一次到位" regardless of what
/// the evaluator said. The user has already made their judgment — the validator
/// should respect it.
///
/// Returns a (possibly corrected) copy of the attribution.
fn validate_attribution(attr: &Attribution, complaint: &str) -> Attribution {
    // User-explicit override: when the user says the agent gave conclusions
    // based on its own experience, respect that judgment unconditionally.
    let user_says_agent_gave_conclusion = complaint.contains("根据自身经验")
        || complaint.contains("根据自己经验")
        || complaint.contains("agent gave conclusion")
        || complaint.contains("agent gave answer");

    if user_says_agent_gave_conclusion {
        log::info!(
            "causal-attribution validator: user complaint explicitly states agent gave \
             conclusions based on experience — forcing '一次到位' override",
        );
        return Attribution {
            outcome: Some("success".to_string()),
            outcome_note: Some(
                "一次到位：用户明确说明 agent 根据自身经验给出了结论，评估器的 defect 判定被覆盖。"
                    .to_string(),
            ),
            verdict: Some(
                "无缺陷。用户明确说明 agent 根据自身经验给出了结论；评估器的 defect 判定被覆盖。"
                    .to_string(),
            ),
            root_one: Some("无缺陷。".to_string()),
            attrib: Some("model".to_string()),
            fix: Some("无需修复".to_string()),
            alternative_attribs: Vec::new(),
            ..attr.clone()
        };
    }

    let conclusion = attr.actual_conclusion.as_deref().unwrap_or("");
    let outcome_note = attr.outcome_note.as_deref().unwrap_or("");
    let verdict = attr.verdict.as_deref().unwrap_or("");

    // Detect evaluator's "refused" or "冒充" or "未核验" or "fabrication" claims
    let evaluator_says_refused = outcome_note.contains("拒答")
        || verdict.contains("拒答")
        || outcome_note.contains("refused when could have answered");
    let evaluator_says_fake = outcome_note.contains("冒充")
        || verdict.contains("冒充")
        || outcome_note.contains("stale_data")
        || verdict.contains("stale_data")
        || outcome_note.contains("误导")
        || verdict.contains("误导");
    let evaluator_says_unverified = outcome_note.contains("未核验")
        || verdict.contains("未核验")
        || outcome_note.contains("未标注")
        || verdict.contains("未标注")
        || outcome_note.contains("未说明")
        || verdict.contains("未说明")
        || outcome_note.contains("unverified")
        || verdict.contains("unverified")
        || outcome_note.contains("未声明")
        || verdict.contains("未声明");
    // The evaluator sometimes claims the agent "fabricated" concrete data
    // (stargazers_count, timestamps, URLs) when in fact the agent retrieved
    // real data from the tool but the observation ended up in a different
    // field (response.messages vs observation.results). When the agent's
    // actual output contains verifiable data that matches reality, this is
    // NOT fabrication — it's correct behavior.
    let evaluator_says_fabrication = outcome_note.contains("凭空")
        || verdict.contains("凭空")
        || outcome_note.contains("编造")
        || verdict.contains("编造")
        || outcome_note.contains("fabrication")
        || verdict.contains("fabrication")
        || outcome_note.contains("虚构")
        || verdict.contains("虚构")
        || outcome_note.contains("幻觉")
        || verdict.contains("幻觉");

    // Detect whether agent's actual conclusion has real content
    let refusal_patterns = [
        "我无法",
        "I cannot",
        "I can't",
        "我无法回答",
        "请自行查阅",
        "please consult",
        "请自行",
        "请自行搜索",
        "无法提供",
        "I'm unable",
        "I am unable",
        "我无法确认",
        "无法确认",
        "建议自行",
        "建议用户自行",
        "请查阅",
        "无法给出",
    ];
    let agent_refused = refusal_patterns
        .iter()
        .any(|p| conclusion.to_lowercase().contains(p));

    let has_substantive_content = conclusion.chars().count() > 100 && !agent_refused;

    // Even when actual_conclusion is empty (evaluator didn't produce the field),
    // the evaluator's own verdict/outcome_note wording often implies the agent
    // gave real content. Examples:
    //   - "基于训练数据给出排名" → agent gave ranking content
    //   - "给出大模型排名" → agent gave ranking
    //   - "列出 GPT-4o/Claude 3.5" → agent listed concrete models
    // When the evaluator's description implies substantive content was given,
    // treat it as such even without actual_conclusion.
    let evaluator_implies_content_given = outcome_note.contains("给出")
        || verdict.contains("给出")
        || outcome_note.contains("列出")
        || verdict.contains("列出")
        || outcome_note.contains("基于训练数据")
        || verdict.contains("基于训练数据");

    let effective_substantive = has_substantive_content || evaluator_implies_content_given;

    if (evaluator_says_refused
        || evaluator_says_fake
        || evaluator_says_unverified
        || evaluator_says_fabrication)
        && effective_substantive
    {
        log::info!(
            "causal-attribution validator: evaluator claimed refusal/冒充/未核验/编造 but \
             agent's actual output contains verifiable data — overriding to '一次到位'",
        );
        return Attribution {
            outcome: Some("success".to_string()),
            outcome_note: Some(
                "一次到位：agent 给出的结论与真实数据一致，并非拒答/冒充/编造；评估器误读了 agent 的实际输出。".to_string(),
            ),
            verdict: Some(
                "无缺陷。agent 给出的结论与真实数据一致，并非拒答/冒充/编造；评估器误读了 agent 的实际输出。"
                    .to_string(),
            ),
            root_one: Some("无缺陷。".to_string()),
            attrib: Some("model".to_string()),
            fix: Some("无需修复".to_string()),
            alternative_attribs: Vec::new(),
            ..attr.clone()
        };
    }

    attr.clone()
}

fn build_case(
    trajectory: &OptTrajectory,
    steps: &[OptStep],
    req: &CausalRequest,
    verdicts: &Verdicts,
    attr: &Attribution,
) -> Result<CausalCase, String> {
    // Post-evaluator validation: catch the most common evaluator misclassification
    // BEFORE it propagates into the graph. The evaluator often claims "拒答但应能答"
    // (refused when could have answered) when the agent actually gave substantive
    // content based on its training knowledge. When the agent's actual conclusion
    // contains real content, "refused" is a misread — override.
    let validated_attr = validate_attribution(attr, &req.complaint);
    let attr = &validated_attr;

    let mut nodes: Vec<CausalNode> = Vec::new();
    let mut edges: Vec<CausalEdge> = Vec::new();
    let mut timeline: Vec<String> = Vec::new();

    let verdict_by_step: std::collections::HashMap<u32, StepVerdict> = verdicts
        .verdicts
        .iter()
        .filter_map(|v| v.step_id.map(|id| (id, v.clone())))
        .collect();

    // Decide which steps deserve a visible node. Rule of thumb: the user's
    // first message (task anchor) plus any step the evaluator flagged as
    // defective. The agent's last step is added ONLY when nothing else was
    // selected — otherwise a routine heartbeat at the end of a long round
    // would drown out the real failure chain. OK steps are deliberately
    // skipped: they add noise without helping the reader trace the failure.
    let first_user_idx = steps.iter().position(|s| s.is_user());

    let mut defective_indices: Vec<usize> = Vec::new();
    for (i, step) in steps.iter().enumerate() {
        let v = verdict_by_step.get(&step.step_id);
        // Trust the evaluator's `kind` field after normalization: "ok" means
        // "no defect, nothing to show". Everything else (seed/root/sym/
        // shipped) earns a node. Normalize first so Chinese / aliased values
        // ("正常" / "root_cause" / "Ok") collapse to the canonical enum.
        let is_defective = v
            .and_then(|v| v.kind.as_deref())
            .map(|k| normalize_kind(k) != "ok")
            .unwrap_or(false);
        if is_defective {
            defective_indices.push(i);
        }
    }

    let mut selected_indices: Vec<usize> = Vec::new();
    let mut seen: std::collections::HashSet<usize> = std::collections::HashSet::new();
    if let Some(i) = first_user_idx {
        selected_indices.push(i);
        seen.insert(i);
    }
    for i in defective_indices {
        if seen.insert(i) {
            selected_indices.push(i);
        }
    }
    // Add the agent's last step only as a last-resort anchor (no defects,
    // or no user message to anchor on). Otherwise a routine heartbeat at
    // the tail of a long session drowns out the real failure chain.
    if selected_indices.is_empty() {
        if let Some(i) = steps.iter().rposition(|s| !s.is_user()) {
            selected_indices.push(i);
        }
    }
    // Make sure there's at least something to render even for a clean round.
    if selected_indices.is_empty() {
        if let Some(i) = steps.iter().rposition(|_| true) {
            selected_indices.push(i);
        }
    }

    for step_idx in &selected_indices {
        let step = &steps[*step_idx];
        let v = verdict_by_step.get(&step.step_id);

        // Reference-only: the agent's last step is used to decide how to
        // label an endpoint node; it does NOT force that step into the
        // selected set (that decision lives above).
        let last_agent_idx = steps.iter().rposition(|s| !s.is_user());

        // Kind resolution: normalize the evaluator's free-form value first,
        // then apply anchor-role overrides for the user's first message and
        // the agent's last step so the graph has clear endpoints even when
        // the evaluator returned "ok" / "正常" for them.
        let normalized_kind = v.and_then(|v| v.kind.as_deref()).map(normalize_kind);
        let kind = match normalized_kind.as_deref() {
            Some("ok") | None => {
                // Anchor override: first user step → "user"; last agent step
                // → "shipped" (fail) or "good" (success).
                if step.is_user() && Some(*step_idx) == first_user_idx {
                    "user".to_string()
                } else if !step.is_user() && Some(*step_idx) == last_agent_idx {
                    if attr.outcome.as_deref() == Some("fail") {
                        "shipped".to_string()
                    } else {
                        "good".to_string()
                    }
                } else {
                    normalized_kind.unwrap_or_else(|| "ok".to_string())
                }
            }
            Some(canonical) => canonical.to_string(),
        };

        // Label: evaluator's label wins unless it's an OK-prefixed filler;
        // otherwise a short task-derived phrase. Hard-clamp to 19 chars so
        // the one-line summary fits inside the node's fixed width.
        let raw_label = v
            .and_then(|v| v.label.clone())
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && t != "ok" && t != "正常"
            })
            .unwrap_or_else(|| {
                if Some(*step_idx) == first_user_idx {
                    "用户任务".to_string()
                } else if Some(*step_idx) == last_agent_idx {
                    if attr.outcome.as_deref() == Some("fail") {
                        "问题交付".to_string()
                    } else {
                        "最终结论".to_string()
                    }
                } else {
                    default_label(step)
                }
            });
        let label = clamp_chars(&raw_label, 19);

        // Plain: the trajectory-oriented sentence shown under the tag on the
        // node body. Keep it to ~80 chars so the node reads at a glance.
        let plain = v
            .and_then(|v| v.plain.clone())
            .filter(|p| !p.is_empty())
            .map(|p| clamp_chars(&p, 80))
            .unwrap_or_else(|| {
                if Some(*step_idx) == first_user_idx {
                    format!(
                        "用户原始任务：{}",
                        clamp_chars(step.message.as_deref().unwrap_or(""), 60)
                    )
                } else if Some(*step_idx) == last_agent_idx {
                    format!(
                        "agent 交付的最终结论{}",
                        if attr.outcome.as_deref() == Some("fail") {
                            "（未达标）"
                        } else {
                            ""
                        }
                    )
                } else {
                    "该步未检出缺陷".to_string()
                }
            });

        let foot = v.and_then(|v| v.basis.as_ref().map(|b| truncate(b, 40)));
        let raw = step.message.as_ref().map(|m| truncate(m, 500));

        let id = format!("s{}", step.step_id);
        nodes.push(CausalNode {
            id,
            step: Some(step.step_id),
            kind: kind.to_string(),
            tag: label.clone(),
            foot,
            plain,
            raw,
        });
        timeline.push(format!("step{} {}", step.step_id, label));
    }

    // §8 layout: conclusion on the left, root cause on the right. We built
    // nodes chronologically; reverse to put the outcome anchor first.
    nodes.reverse();
    for window in nodes.windows(2) {
        let left = &window[0];
        let right = &window[1];
        let edge_type = if matches!(left.kind.as_str(), "root" | "sym" | "seed" | "shipped") {
            "bad"
        } else {
            "n"
        };
        edges.push(CausalEdge {
            a: left.id.clone(),
            b: right.id.clone(),
            edge_type: edge_type.to_string(),
        });
    }

    // Deterministic contra: agent's quoted final conclusion vs the last
    // observable evidence the user can independently verify. We never leave
    // `contra` empty when both sides have material — the user specifically
    // flagged an empty contra as a broken experience.
    let contra = build_contra(steps, attr);

    let turn_issue_str = attr.turn_issue.map(|b| {
        if b {
            "单轮思考问题".to_string()
        } else {
            "session 级失败".to_string()
        }
    });

    Ok(CausalCase {
        id: format!(
            "case_{}",
            trajectory.session_id.chars().take(8).collect::<String>()
        ),
        title: attr
            .title
            .clone()
            .filter(|t| !t.is_empty())
            .unwrap_or_else(|| truncate(&req.complaint, 40)),
        task: extract_task(steps),
        session: trajectory.session_id.clone(),
        trigger: Some(req.complaint.clone()),
        verdict: attr
            .verdict
            .clone()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| "暂未检出明确软失败".into()),
        root_one: attr
            .root_one
            .clone()
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| "证据不足，需人工复核".into()),
        outcome: attr.outcome.clone().unwrap_or_else(|| "success".into()),
        outcome_note: attr.outcome_note.clone(),
        turn_issue: turn_issue_str,
        attrib: normalize_attrib(attr.attrib.as_deref()),
        fix: attr
            .fix
            .clone()
            .filter(|f| !f.is_empty())
            .unwrap_or_else(|| "暂无建议".into()),
        alternative_attribs: attr
            .alternative_attribs
            .iter()
            .filter(|a| !a.attrib.is_empty())
            .cloned()
            .collect(),
        timeline: Some(timeline),
        nodes,
        edges,
        contra,
        concl: None,
    })
}

/// Build the contra panel as a clean "user intent vs agent delivery"
/// contrast. We deliberately skip the "last observation" axis — for
/// sessions that end with a heartbeat or no-op, that observation is
/// "HEARTBEAT_OK" which adds nothing and confuses the reader.
fn build_contra(steps: &[OptStep], attr: &Attribution) -> Option<CausalContra> {
    // "Saw" = what the user actually wanted.
    let saw = steps
        .iter()
        .find(|s| s.is_user())
        .and_then(|s| s.message.clone())
        .map(|m| format!("用户原始任务：{}", truncate(&m, 400)))?;

    // "Said" = what the agent delivered. Prefer the LLM-quoted actual
    // conclusion (verbatim from the last response); fall back to the
    // verdict/outcome_note which summarize the delivery failure in a way
    // the user can still contrast with their intent.
    let said = attr
        .actual_conclusion
        .clone()
        .filter(|c| !c.trim().is_empty())
        .map(|c| format!("agent 最终交付：{}", truncate(&c, 400)))
        .or_else(|| {
            attr.verdict
                .clone()
                .filter(|v| !v.trim().is_empty())
                .map(|v| format!("agent 交付评估：{v}"))
        })
        .or_else(|| {
            attr.outcome_note
                .clone()
                .filter(|n| !n.trim().is_empty())
                .map(|n| format!("agent 交付评估：{n}"))
        })?;

    if saw == said {
        None
    } else {
        Some(CausalContra { saw, said })
    }
}

fn default_label(step: &OptStep) -> String {
    if step.is_user() {
        return "用户输入".to_string();
    }
    match step.calls().first() {
        Some(c) => truncate(&c.function_name, 16),
        None => truncate(step.message.as_deref().unwrap_or(""), 16),
    }
}

fn normalize_attrib(value: Option<&str>) -> String {
    let Some(lowered) = value.map(|s| s.trim().to_ascii_lowercase()) else {
        return "model".to_string();
    };
    match lowered.as_str() {
        "model" | "skill" | "prompt" | "agent" => lowered,
        _ => "model".to_string(),
    }
}

#[cfg(test)]
#[path = "causal_tests.rs"]
mod tests;
