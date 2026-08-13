use super::*;
use agentsight_atif::{Agent, AtifTrajectory, StepSource, ToolCall};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_atif_trajectory(steps: Vec<agentsight_atif::Step>) -> AtifTrajectory {
    AtifTrajectory {
        schema_version: "ATIF-v1.7".into(),
        agent: Agent {
            name: "test-agent".into(),
            version: "0.0.1".into(),
            model_name: None,
            tool_definitions: None,
            extra: None,
        },
        steps,
        session_id: Some("test-session".into()),
        trajectory_id: None,
        notes: None,
        final_metrics: None,
        continued_trajectory_ref: None,
        subagent_trajectories: None,
        extra: None,
    }
}

fn make_agent_step(step_id: usize, tool_calls: Vec<ToolCall>) -> agentsight_atif::Step {
    agentsight_atif::Step {
        step_id,
        source: StepSource::Agent,
        message: String::new(),
        timestamp: None,
        model_name: None,
        reasoning_effort: None,
        reasoning_content: None,
        tool_calls: Some(tool_calls),
        observation: None,
        metrics: None,
        extra: None,
        llm_call_count: None,
        is_copied_context: None,
    }
}

fn make_user_step(step_id: usize, message: &str) -> agentsight_atif::Step {
    agentsight_atif::Step {
        step_id,
        source: StepSource::User,
        message: message.to_string(),
        timestamp: None,
        model_name: None,
        reasoning_effort: None,
        reasoning_content: None,
        tool_calls: None,
        observation: None,
        metrics: None,
        extra: None,
        llm_call_count: None,
        is_copied_context: None,
    }
}

fn tool_call_response_part(id: &str, content: &str, is_error: bool) -> serde_json::Value {
    serde_json::json!({
        "type": "tool_call_response",
        "id": id,
        "response": {
            "content": content,
            "is_error": is_error
        }
    })
}

// ---------------------------------------------------------------------------
// enrich_tool_results
// ---------------------------------------------------------------------------

#[test]
fn enrich_fills_missing_observation_from_tool_call_response() {
    let tool_response_json = serde_json::to_string(&serde_json::json!([tool_call_response_part(
        "call_1",
        "stargazers_count=242391",
        false
    )]))
    .unwrap();

    let mut doc = make_atif_trajectory(vec![
        make_agent_step(
            1,
            vec![ToolCall {
                tool_call_id: "call_1".into(),
                function_name: "Bash".into(),
                arguments: serde_json::json!({}),
                extra: None,
            }],
        ),
        make_user_step(2, &tool_response_json),
    ]);

    enrich_tool_results(&mut doc);

    let obs = doc.steps[0].observation.as_ref().unwrap();
    assert_eq!(obs.results.len(), 1);
    assert_eq!(obs.results[0].source_call_id.as_deref(), Some("call_1"));
    assert_eq!(
        obs.results[0].content.as_ref().and_then(|v| v.as_str()),
        Some("stargazers_count=242391")
    );
}

#[test]
fn enrich_handles_empty_trajectory() {
    let mut doc = make_atif_trajectory(vec![]);
    enrich_tool_results(&mut doc);
    assert!(doc.steps.is_empty());
}

#[test]
fn enrich_skips_steps_without_tool_calls() {
    let mut doc = make_atif_trajectory(vec![agentsight_atif::Step {
        step_id: 1,
        source: StepSource::Agent,
        message: String::new(),
        timestamp: None,
        model_name: None,
        reasoning_effort: None,
        reasoning_content: None,
        tool_calls: None,
        observation: None,
        metrics: None,
        extra: None,
        llm_call_count: None,
        is_copied_context: None,
    }]);

    enrich_tool_results(&mut doc);
    assert!(doc.steps[0].observation.is_none());
}

#[test]
fn enrich_annotates_error_responses() {
    let tool_response_json = serde_json::to_string(&serde_json::json!([tool_call_response_part(
        "call_err",
        "file not found",
        true
    )]))
    .unwrap();

    let mut doc = make_atif_trajectory(vec![
        make_agent_step(
            1,
            vec![ToolCall {
                tool_call_id: "call_err".into(),
                function_name: "Read".into(),
                arguments: serde_json::json!({}),
                extra: None,
            }],
        ),
        make_user_step(2, &tool_response_json),
    ]);

    enrich_tool_results(&mut doc);

    let obs = doc.steps[0].observation.as_ref().unwrap();
    let content = obs.results[0]
        .content
        .as_ref()
        .and_then(|v| v.as_str())
        .unwrap();
    assert!(content.starts_with("[ERROR]"), "got: {content}");
    assert!(content.contains("file not found"));
}

#[test]
fn enrich_skips_non_json_user_messages() {
    let mut doc = make_atif_trajectory(vec![
        make_agent_step(
            1,
            vec![ToolCall {
                tool_call_id: "call_1".into(),
                function_name: "Bash".into(),
                arguments: serde_json::json!({}),
                extra: None,
            }],
        ),
        make_user_step(2, "just plain text, not JSON"),
    ]);

    enrich_tool_results(&mut doc);

    // Agent step should get an observation with empty content since
    // the tool_call_id doesn't match anything in the non-JSON user message.
    let obs = doc.steps[0].observation.as_ref().unwrap();
    assert_eq!(obs.results.len(), 1);
    assert!(obs.results[0].content.is_none());
}

#[test]
fn enrich_handles_multiple_tool_calls_per_step() {
    let tool_response_json = serde_json::to_string(&serde_json::json!([
        tool_call_response_part("call_a", "result A", false),
        tool_call_response_part("call_b", "result B", false),
    ]))
    .unwrap();

    let mut doc = make_atif_trajectory(vec![
        make_agent_step(
            1,
            vec![
                ToolCall {
                    tool_call_id: "call_a".into(),
                    function_name: "Read".into(),
                    arguments: serde_json::json!({}),
                    extra: None,
                },
                ToolCall {
                    tool_call_id: "call_b".into(),
                    function_name: "Bash".into(),
                    arguments: serde_json::json!({}),
                    extra: None,
                },
            ],
        ),
        make_user_step(2, &tool_response_json),
    ]);

    enrich_tool_results(&mut doc);

    let obs = doc.steps[0].observation.as_ref().unwrap();
    assert_eq!(obs.results.len(), 2);
    assert_eq!(
        obs.results[0].content.as_ref().and_then(|v| v.as_str()),
        Some("result A")
    );
    assert_eq!(
        obs.results[1].content.as_ref().and_then(|v| v.as_str()),
        Some("result B")
    );
}

// ---------------------------------------------------------------------------
// normalize_kind
// ---------------------------------------------------------------------------

#[test]
fn normalize_kind_english_canonical() {
    assert_eq!(normalize_kind("ok"), "ok");
    assert_eq!(normalize_kind("root"), "root");
    assert_eq!(normalize_kind("seed"), "seed");
    assert_eq!(normalize_kind("sym"), "sym");
    assert_eq!(normalize_kind("shipped"), "shipped");
    assert_eq!(normalize_kind("good"), "good");
    assert_eq!(normalize_kind("user"), "user");
    assert_eq!(normalize_kind("env"), "env");
    assert_eq!(normalize_kind("cf"), "cf");
}

#[test]
fn normalize_kind_chinese() {
    assert_eq!(normalize_kind("正常"), "ok");
    assert_eq!(normalize_kind("无缺陷"), "ok");
    assert_eq!(normalize_kind("元凶"), "root");
    assert_eq!(normalize_kind("根因"), "root");
    assert_eq!(normalize_kind("症状"), "sym");
    assert_eq!(normalize_kind("萌芽"), "seed");
    assert_eq!(normalize_kind("交付"), "shipped");
    assert_eq!(normalize_kind("达成"), "good");
    assert_eq!(normalize_kind("用户"), "user");
    assert_eq!(normalize_kind("环境"), "env");
    assert_eq!(normalize_kind("反事实"), "cf");
}

#[test]
fn normalize_kind_case_insensitive() {
    assert_eq!(normalize_kind("OK"), "ok");
    assert_eq!(normalize_kind("Root"), "root");
    assert_eq!(normalize_kind("SEED"), "seed");
    assert_eq!(normalize_kind("Normal"), "ok");
    assert_eq!(normalize_kind("CULPRIT"), "root");
}

#[test]
fn normalize_kind_unknown_defaults_to_ok() {
    assert_eq!(normalize_kind("banana"), "ok");
    assert_eq!(normalize_kind(""), "ok");
    assert_eq!(normalize_kind("unknown_kind"), "ok");
}

#[test]
fn normalize_kind_aliases() {
    assert_eq!(normalize_kind("normal"), "ok");
    assert_eq!(normalize_kind("clean"), "ok");
    assert_eq!(normalize_kind("pass"), "ok");
    assert_eq!(normalize_kind("culprit"), "root");
    assert_eq!(normalize_kind("origin"), "root");
    assert_eq!(normalize_kind("symptom"), "sym");
    assert_eq!(normalize_kind("propagation"), "sym");
    assert_eq!(normalize_kind("germ"), "seed");
    assert_eq!(normalize_kind("delivered"), "shipped");
}

// ---------------------------------------------------------------------------
// validate_attribution
// ---------------------------------------------------------------------------

#[test]
fn validate_user_says_agent_gave_conclusion_forces_success() {
    let attr = Attribution {
        outcome: Some("fail".into()),
        verdict: Some("拒答但应能答".into()),
        outcome_note: Some("agent refused".into()),
        ..Default::default()
    };

    let result = validate_attribution(&attr, "agent 根据自身经验给出了结论");

    assert_eq!(result.outcome.as_deref(), Some("success"));
    assert_eq!(result.fix.as_deref(), Some("无需修复"));
    assert!(result.verdict.as_deref().unwrap().contains("用户明确说明"));
}

#[test]
fn validate_corrects_refusal_when_agent_gave_content() {
    let long_conclusion = "根据我的训练数据，GPT-4o 在多模态能力上领先，Claude 3.5 Sonnet 在代码生成方面表现优秀，\
                           Gemini 2.0 Flash 在推理速度上有显著优势。这三个模型是目前最强的大语言模型。"
        .to_string();

    let attr = Attribution {
        outcome: Some("fail".into()),
        verdict: Some("拒答但应能答".into()),
        outcome_note: Some("agent 拒答但训练数据中有相关信息".into()),
        actual_conclusion: Some(long_conclusion),
        ..Default::default()
    };

    let result = validate_attribution(&attr, "这轮对话有问题吗");

    assert_eq!(result.outcome.as_deref(), Some("success"));
    assert!(result.outcome_note.as_deref().unwrap().contains("一次到位"));
}

#[test]
fn validate_passes_through_correct_attribution() {
    let attr = Attribution {
        outcome: Some("success".into()),
        verdict: Some("一次到位".into()),
        outcome_note: Some("agent 正确完成了任务".into()),
        attrib: Some("model".into()),
        ..Default::default()
    };

    let result = validate_attribution(&attr, "没有问题");

    assert_eq!(result.outcome.as_deref(), Some("success"));
    assert_eq!(result.verdict.as_deref(), Some("一次到位"));
}

#[test]
fn validate_corrects_fabrication_when_substantive_content_present() {
    let long_conclusion = "该仓库的 stargazers_count 为 242,391，forks_count 为 15,672，\
                           open_issues_count 为 234。这些数据来自 GitHub API 的实时查询结果。"
        .to_string();

    let attr = Attribution {
        outcome: Some("fail".into()),
        verdict: Some("凭空编造返回值".into()),
        outcome_note: Some("agent 编造了 stargazers_count".into()),
        actual_conclusion: Some(long_conclusion),
        ..Default::default()
    };

    let result = validate_attribution(&attr, "数据是编造的吗");

    assert_eq!(result.outcome.as_deref(), Some("success"));
    assert!(
        result
            .outcome_note
            .as_deref()
            .unwrap()
            .contains("并非拒答/冒充/编造")
    );
}

#[test]
fn validate_respects_genuine_refusal() {
    let attr = Attribution {
        outcome: Some("fail".into()),
        verdict: Some("拒答".into()),
        outcome_note: Some("agent refused to answer".into()),
        actual_conclusion: Some("我无法回答这个问题".into()),
        ..Default::default()
    };

    let result = validate_attribution(&attr, "为什么不回答");

    assert_eq!(result.outcome.as_deref(), Some("fail"));
    assert_eq!(result.verdict.as_deref(), Some("拒答"));
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

#[test]
fn truncate_preserves_short_strings() {
    assert_eq!(truncate("hello", 10), "hello");
    assert_eq!(truncate("", 5), "");
}

#[test]
fn truncate_adds_ellipsis_for_long() {
    assert_eq!(truncate("abcdefghijklmnop", 5), "abcde…");
}

#[test]
fn format_oracle_serializes_to_json() {
    let oracle = Oracle {
        goal: Some("test goal".into()),
        preconditions: Some(vec!["pre1".into()]),
        evidence: None,
        pass_criteria: Some(vec!["pass1".into()]),
    };

    let json = format_oracle(&oracle);
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["goal"], "test goal");
    assert_eq!(parsed["preconditions"][0], "pre1");
}

#[test]
fn oracle_and_verdicts_deserializes_complete_and_sparse() {
    // Complete response
    let full = serde_json::json!({
        "goal": "find bug",
        "preconditions": ["code exists"],
        "evidence": ["git log"],
        "pass_criteria": ["bug found"],
        "verdicts": [
            {
                "step_id": 1,
                "label": "引用去年数据",
                "kind": "root",
                "defect_type": "stale_data",
                "consequence": null,
                "basis": "used 2025 data",
                "plain": "searched old data",
                "confidence": 0.9
            }
        ]
    });
    let parsed: OracleAndVerdicts = serde_json::from_value(full).unwrap();
    assert_eq!(parsed.goal.as_deref(), Some("find bug"));
    assert_eq!(parsed.verdicts.len(), 1);
    assert_eq!(parsed.verdicts[0].step_id, Some(1));
    assert_eq!(parsed.verdicts[0].kind.as_deref(), Some("root"));

    // Sparse response — only empty verdicts
    let sparse = serde_json::json!({"verdicts": []});
    let parsed: OracleAndVerdicts = serde_json::from_value(sparse).unwrap();
    assert!(parsed.goal.is_none());
    assert!(parsed.preconditions.is_none());
    assert!(parsed.verdicts.is_empty());
}

#[test]
fn normalize_attrib_valid_values() {
    assert_eq!(normalize_attrib(Some("model")), "model");
    assert_eq!(normalize_attrib(Some("skill")), "skill");
    assert_eq!(normalize_attrib(Some("prompt")), "prompt");
    assert_eq!(normalize_attrib(Some("agent")), "agent");
}

#[test]
fn normalize_attrib_invalid_defaults_to_model() {
    assert_eq!(normalize_attrib(Some("banana")), "model");
    assert_eq!(normalize_attrib(None), "model");
}
