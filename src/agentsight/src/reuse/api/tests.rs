//! Tests for the shared reuse-label operations, run against real SQLite stores
//! so the skip-unchanged path and the filter translation are exercised end to
//! end rather than mocked.

use std::path::PathBuf;

use agentsight_trajectory_collector::{TrajectoryRecord, TrajectoryStore};

use super::*;
use crate::reuse::label::LabelAction;

fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("reuse-api-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Both stores as production opens them, so these tests also cover the
/// private-directory entry point rather than a test-only shortcut.
fn stores(tag: &str) -> (TrajectoryStore, ReuseStore) {
    let dir = tmp_dir(tag);
    let trajectories = TrajectoryStore::new_with_path(&dir.join("trajectories.db")).unwrap();
    let labels = ReuseStore::open_private(dir.join(".agentsight-private")).unwrap();
    (trajectories, labels)
}

/// A trivial one-shot exchange: no tools, one user turn, short answer.
fn trivial_atif() -> String {
    r#"{"schema_version": "ATIF-v1.7", "agent": {"name": "t"}, "steps": [
        {"step_id": 1, "source": "user", "message": "1+1"},
        {"step_id": 2, "source": "agent", "message": "2"}
    ]}"#
    .to_string()
}

/// A trajectory with a successful tool call, which cannot be `useless`.
fn substantive_atif() -> String {
    r#"{"schema_version": "ATIF-v1.7", "agent": {"name": "t"}, "steps": [
        {"step_id": 1, "source": "user", "message": "check the file"},
        {"step_id": 2, "source": "agent", "message": "looking",
         "tool_calls": [{"tool_call_id": "c1", "function_name": "bash", "arguments": "{}"}],
         "observation": {"results": [{"source_call_id": "c1", "content": "ok\nExit code 0"}]}}
    ]}"#
    .to_string()
}

/// A trajectory whose tool call reports a non-zero exit code. The rules cannot
/// tell whether the round still delivered, so it comes out `unknown`.
fn failing_atif() -> String {
    r#"{"schema_version": "ATIF-v1.7", "agent": {"name": "t"}, "steps": [
        {"step_id": 1, "source": "user", "message": "check the file"},
        {"step_id": 2, "source": "agent", "message": "looking",
         "tool_calls": [{"tool_call_id": "c1", "function_name": "bash", "arguments": "{}"}],
         "observation": {"results": [{"source_call_id": "c1", "content": "nope\nExit code 1"}]}}
    ]}"#
    .to_string()
}

/// Inserts a trajectory, asserting the fixture is valid ATIF first.
///
/// A malformed fixture would otherwise land in the `unparsable` bucket and the
/// test would carry on against zero rows, reporting whatever the caller happened
/// not to assert. Use [`insert_raw`] when the malformed payload is the point.
fn insert(store: &TrajectoryStore, session_id: &str, atif_json: &str) {
    serde_json::from_str::<agentsight_atif::AtifTrajectory>(atif_json)
        .unwrap_or_else(|e| panic!("fixture for {session_id} is not valid ATIF: {e}"));
    insert_raw(store, session_id, atif_json);
}

fn insert_raw(store: &TrajectoryStore, session_id: &str, atif_json: &str) {
    store
        .upsert_trajectory(&TrajectoryRecord {
            session_id: session_id.to_string(),
            schema_version: "ATIF-v1.7".to_string(),
            agent_name: "t".to_string(),
            model_name: None,
            num_steps: 2,
            total_prompt_tokens: None,
            total_completion_tokens: None,
            start_time: None,
            end_time: None,
            first_user_message: None,
            last_user_message: None,
            atif_json: atif_json.to_string(),
            project: "p".to_string(),
            source: "qoder".to_string(),
            is_subagent: false,
            file_path: format!("/tmp/{session_id}.jsonl"),
            file_size: 1,
            file_mtime_ns: 1,
        })
        .unwrap();
}

#[test]
fn triage_labels_every_trajectory_and_reports_the_split() {
    let (trajectories, labels) = stores("split");
    insert(&trajectories, "trivial", &trivial_atif());
    insert(&trajectories, "real", &substantive_atif());

    let report = run_triage(
        Some(&trajectories),
        &labels,
        &TriageQuery::default(),
        &TriageConfig::default(),
    )
    .unwrap();

    assert_eq!(report.examined, 2);
    assert_eq!(report.labelled, 2);
    assert_eq!(report.auto_useless, 1);
    assert_eq!(report.auto_good, 1);
    // Compared against the config rather than a literal: the point is that the
    // report records the version actually used, not which version that is today.
    assert_eq!(report.triage_version, TriageConfig::default().version());
    assert!(!report.truncated);
}

#[test]
fn a_second_run_over_unchanged_content_relabels_nothing() {
    // What makes the endpoint safe to poll: identical bytes under identical
    // rules cannot produce a different verdict, so the work is skipped.
    let (trajectories, labels) = stores("idempotent");
    insert(&trajectories, "s1", &substantive_atif());
    let config = TriageConfig::default();

    let first = run_triage(
        Some(&trajectories),
        &labels,
        &TriageQuery::default(),
        &config,
    )
    .unwrap();
    assert_eq!(first.labelled, 1);
    assert_eq!(first.unchanged, 0);

    let second = run_triage(
        Some(&trajectories),
        &labels,
        &TriageQuery::default(),
        &config,
    )
    .unwrap();
    assert_eq!(second.labelled, 0);
    assert_eq!(second.unchanged, 1);
}

#[test]
fn changing_the_threshold_forces_a_relabel() {
    let (trajectories, labels) = stores("recalibrate");
    insert(&trajectories, "s1", &trivial_atif());

    let strict = TriageConfig::default();
    run_triage(
        Some(&trajectories),
        &labels,
        &TriageQuery::default(),
        &strict,
    )
    .unwrap();

    // A threshold of one character no longer treats the short answer as
    // throwaway, and the version carries the threshold, so the row is recomputed
    // rather than left resting on the old cutoff.
    let loose = TriageConfig { max_agent_len: 1 };
    let report = run_triage(
        Some(&trajectories),
        &labels,
        &TriageQuery::default(),
        &loose,
    )
    .unwrap();
    assert_eq!(report.labelled, 1);
    assert_eq!(report.unchanged, 0);
    assert_eq!(report.auto_useless, 0);
}

#[test]
fn edited_content_forces_a_relabel() {
    let (trajectories, labels) = stores("recollect");
    insert(&trajectories, "s1", &trivial_atif());
    let config = TriageConfig::default();
    run_triage(
        Some(&trajectories),
        &labels,
        &TriageQuery::default(),
        &config,
    )
    .unwrap();

    // The user carried the topic forward, so the trajectory is no longer a
    // one-shot exchange and must not stay `useless`.
    insert(
        &trajectories,
        "s1",
        r#"{"schema_version": "ATIF-v1.7", "agent": {"name": "t"}, "steps": [
            {"step_id": 1, "source": "user", "message": "1+1"},
            {"step_id": 2, "source": "agent", "message": "2"},
            {"step_id": 3, "source": "user", "message": "now the real question"},
            {"step_id": 4, "source": "agent", "message": "here you go"}
        ]}"#,
    );
    let report = run_triage(
        Some(&trajectories),
        &labels,
        &TriageQuery::default(),
        &config,
    )
    .unwrap();
    assert_eq!(report.labelled, 1);
    assert_eq!(report.auto_useless, 0);
}

#[test]
fn a_human_decision_survives_a_relabel_and_is_reported() {
    // The canonical disagreement: the rules could not tell, a person looked and
    // said it was fine. Their verdict must stay in force and stay visible.
    let (trajectories, labels) = stores("human");
    insert(&trajectories, "s1", &failing_atif());
    let config = TriageConfig::default();
    let first = run_triage(
        Some(&trajectories),
        &labels,
        &TriageQuery::default(),
        &config,
    )
    .unwrap();
    assert_eq!(first.auto_unknown, 1);

    labels
        .apply_decision(
            "s1",
            LabelAction::Override(TrajectoryLabel::Good),
            "alice",
            Some("工具报错是预期的".to_string()),
        )
        .unwrap();

    // Reported on the skip path, not only when a row is rewritten.
    let repeat = run_triage(
        Some(&trajectories),
        &labels,
        &TriageQuery::default(),
        &config,
    )
    .unwrap();
    assert_eq!(repeat.unchanged, 1);
    assert_eq!(repeat.human_overrides_in_force, 1);

    // And on the recompute path, where the rules still disagree.
    let loose = TriageConfig { max_agent_len: 1 };
    let report = run_triage(
        Some(&trajectories),
        &labels,
        &TriageQuery::default(),
        &loose,
    )
    .unwrap();
    assert_eq!(report.labelled, 1);
    assert_eq!(report.human_overrides_in_force, 1);

    let view = &list_sessions(&labels, &SessionsQuery::default()).unwrap()[0];
    assert_eq!(view.effective_label, "good");
    // The rules' own verdict is still on the row, which is what the misfire
    // statistics are counted from.
    assert_eq!(view.auto_label, "unknown");
    assert_eq!(view.confirm_state, "overridden");
    assert!(view.human_backed);
}

#[test]
fn triage_can_target_one_trajectory() {
    let (trajectories, labels) = stores("targeted");
    insert(&trajectories, "wanted", &substantive_atif());
    insert(&trajectories, "other", &substantive_atif());

    let report = run_triage(
        Some(&trajectories),
        &labels,
        &TriageQuery {
            session_id: Some("wanted".to_string()),
            ..TriageQuery::default()
        },
        &TriageConfig::default(),
    )
    .unwrap();
    assert_eq!(report.examined, 1);
    assert!(labels.get_label("wanted").unwrap().is_some());
    assert!(labels.get_label("other").unwrap().is_none());
}

#[test]
fn a_targeted_run_on_a_missing_trajectory_is_reported_not_invented() {
    let (trajectories, labels) = stores("missing");
    let report = run_triage(
        Some(&trajectories),
        &labels,
        &TriageQuery {
            session_id: Some("gone".to_string()),
            ..TriageQuery::default()
        },
        &TriageConfig::default(),
    )
    .unwrap();
    assert_eq!(report.missing, 1);
    assert_eq!(report.labelled, 0);
    assert!(labels.get_label("gone").unwrap().is_none());
}

#[test]
fn unparsable_content_is_counted_and_skipped() {
    let (trajectories, labels) = stores("unparsable");
    insert_raw(&trajectories, "broken", "{not json");
    let report = run_triage(
        Some(&trajectories),
        &labels,
        &TriageQuery::default(),
        &TriageConfig::default(),
    )
    .unwrap();
    assert_eq!(report.unparsable, 1);
    assert_eq!(report.labelled, 0);
}

#[test]
fn a_missing_trajectory_store_is_reported_as_configuration_not_failure() {
    let (_trajectories, labels) = stores("nostore");
    let err = run_triage(
        None,
        &labels,
        &TriageQuery::default(),
        &TriageConfig::default(),
    )
    .unwrap_err();
    assert!(matches!(err, ReuseApiError::TrajectoriesUnavailable));
}

#[test]
fn listing_filters_on_the_effective_label() {
    let (trajectories, labels) = stores("filter");
    insert(&trajectories, "trivial", &trivial_atif());
    insert(&trajectories, "real", &substantive_atif());
    run_triage(
        Some(&trajectories),
        &labels,
        &TriageQuery::default(),
        &TriageConfig::default(),
    )
    .unwrap();

    let useless = list_sessions(
        &labels,
        &SessionsQuery {
            label: Some("useless".to_string()),
            ..SessionsQuery::default()
        },
    )
    .unwrap();
    assert_eq!(useless.len(), 1);
    assert_eq!(useless[0].session_id, "trivial");

    let both = list_sessions(
        &labels,
        &SessionsQuery {
            label: Some("useless, good".to_string()),
            ..SessionsQuery::default()
        },
    )
    .unwrap();
    assert_eq!(both.len(), 2);
}

#[test]
fn an_unknown_filter_value_is_rejected_rather_than_returning_nothing() {
    // Silently returning an empty list reads as "no such trajectories", which
    // sends the reader looking in the wrong place.
    let (_trajectories, labels) = stores("badparam");
    let err = list_sessions(
        &labels,
        &SessionsQuery {
            label: Some("goodish".to_string()),
            ..SessionsQuery::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ReuseApiError::BadParameter { field: "label", .. }
    ));

    let err = list_sessions(
        &labels,
        &SessionsQuery {
            confirm_state: Some("maybe".to_string()),
            ..SessionsQuery::default()
        },
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ReuseApiError::BadParameter {
            field: "confirm_state",
            ..
        }
    ));
}

#[test]
fn limits_are_clamped_not_trusted() {
    assert_eq!(clamp(None, 200, 2_000), 200);
    assert_eq!(clamp(Some(0), 200, 2_000), 200);
    assert_eq!(clamp(Some(-5), 200, 2_000), 200);
    assert_eq!(clamp(Some(50), 200, 2_000), 50);
    assert_eq!(clamp(Some(9_999), 200, 2_000), 2_000);
}

#[test]
fn the_content_hash_tracks_every_byte() {
    let a = content_hash("{\"a\":1}");
    assert_eq!(a, content_hash("{\"a\":1}"));
    // Whitespace the parser would ignore still changes the digest: a rule added
    // later may care, and treating any byte change as a change is the cheap
    // answer.
    assert_ne!(a, content_hash("{\"a\": 1}"));
    assert_eq!(a.len(), 64);
}
