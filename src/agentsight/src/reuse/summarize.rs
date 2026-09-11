//! Aggregates the deterministic grounding verdicts of a whole trajectory into
//! the summary the labelling rules consume.
//!
//! Grounding works a round at a time, because that is the unit causal
//! attribution reasons about and the unit its rules were calibrated on. A label
//! is about the whole trajectory, so this walks every round and folds the
//! results together: a trajectory is not sound just because its last round was.
//!
//! Round boundaries are computed the same way `server::causal` computes them, so
//! a label and an attribution run never disagree about where a round began.

use std::collections::BTreeSet;
use std::ops::Range;

use agentsight_atif::{AtifTrajectory, StepSource};

use super::triage::GroundingSummary;
use crate::grounding::evidence::{Aftermath, Finding, build_index};
use crate::grounding::outcome::CallStatus;

/// Folds every round's grounding verdicts into one trajectory-level summary.
///
/// Findings are summed: they are already scoped to their round by
/// `derive_findings`, so a problem in round 1 is still counted once when round 9
/// is examined. The call-derived flags are monotonic — one failed call anywhere
/// is enough to withhold a clean verdict.
pub fn summarize_trajectory(doc: &AtifTrajectory) -> GroundingSummary {
    let mut summary = GroundingSummary {
        all_calls_ok: true,
        ..GroundingSummary::default()
    };
    let mut rules: BTreeSet<String> = BTreeSet::new();

    for round in round_ranges(doc) {
        let index = build_index(doc, round);

        summary.total_findings += index.findings.len();
        summary.verdict_driving_findings += index
            .findings
            .iter()
            .filter(|finding| finding.may_drive_verdict() && stands_without_review(finding))
            .count();
        rules.extend(index.findings.iter().map(|f| finding_rule(f).to_string()));

        // `call_verdicts` covers every call up to the round's end, not just the
        // round's own, so entries from earlier rounds reappear here. That is
        // harmless for these three outputs — two are monotonic booleans and the
        // third is a set — but the filter keeps the intent explicit rather than
        // relying on that.
        for verdict in index
            .call_verdicts
            .iter()
            .filter(|v| v.step_id >= index.round_start_step)
        {
            let status = verdict.verdict.status;
            if !matches!(status, CallStatus::Ok | CallStatus::OkProbe) {
                summary.all_calls_ok = false;
            }
            if verdict.aftermath == Some(Aftermath::Persisted) {
                summary.has_persisted_failure = true;
            }
            // A plainly successful call is not a judgement anyone disputes;
            // everything else is one that a human overriding the label may be
            // disagreeing with.
            if status != CallStatus::Ok {
                rules.insert(verdict.verdict.matched_rule.to_string());
            }
        }
    }

    summary.rules = rules.into_iter().collect();
    summary
}

/// Whether a finding stands on its own without the semantic review the
/// attribution pipeline performs before an unplaced claim may accuse.
///
/// Labelling runs with no model, so it may only count findings that need none.
/// `causal::run_pipeline` calls `review_unplaced_claims` and `apply_review`
/// *before* consuming findings, with the comment "formatting variance is
/// unbounded, so a claim the string rules could not place gets one semantic
/// review before it is allowed to become a finding". Skipping that review and
/// counting the result anyway condemned every real trajectory measured: three of
/// three collected sessions came out `bad` purely on `ungrounded_onset`, because
/// agents paraphrase and summarise constantly and string matching cannot place a
/// reworded observation.
///
/// `FailureThenFabrication` rests on an unplaced claim too, but only together
/// with a call that failed deterministically at high confidence whose output
/// domain covers the claim's class. That conjunction is why the engine scores it
/// `L2` where an ungrounded assertion alone scores `L3`, and it is solid enough
/// to accuse without a model.
fn stands_without_review(finding: &Finding) -> bool {
    match finding {
        Finding::FailureThenFabrication { .. } => true,
        // Needs the review; see above.
        Finding::UngroundedOnset { .. } => false,
        // Never drives a verdict in the first place, so the question is moot.
        Finding::RepeatedIdenticalFailure { .. } => false,
    }
}

/// Stable identifier for a finding kind, used in the override statistics.
///
/// Spelled out rather than derived from the `Debug` output: these strings are
/// stored and aggregated across releases, so they must not shift when a variant
/// is renamed or reordered.
fn finding_rule(finding: &Finding) -> &'static str {
    match finding {
        Finding::UngroundedOnset { .. } => "ungrounded_onset",
        Finding::RepeatedIdenticalFailure { .. } => "repeated_identical_failure",
        Finding::FailureThenFabrication { .. } => "failure_then_fabrication",
    }
}

/// Index ranges of each round, mirroring `server::causal::slice_round`.
///
/// A round starts at every user step, and the first step always starts one even
/// when it is not the user's — otherwise a trajectory whose transcript opens
/// with a system prompt would have its opening steps fall outside every round.
fn round_ranges(doc: &AtifTrajectory) -> Vec<Range<usize>> {
    let mut starts: Vec<usize> = Vec::new();
    for (i, step) in doc.steps.iter().enumerate() {
        if step.source == StepSource::User || starts.is_empty() {
            starts.push(i);
        }
    }
    if starts.is_empty() {
        return Vec::new();
    }
    (0..starts.len())
        .map(|i| starts[i]..starts.get(i + 1).copied().unwrap_or(doc.steps.len()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trajectory(steps_json: &str) -> AtifTrajectory {
        let json = format!(
            r#"{{"schema_version": "ATIF-v1.7", "agent": {{"name": "t"}}, "steps": [{steps_json}]}}"#
        );
        serde_json::from_str(&json).expect("fixture should parse")
    }

    /// A tool call whose result carries a non-zero exit code, which rule R3
    /// treats as a failure regardless of the wording.
    fn failing_call(step_id: usize, call_id: &str) -> String {
        format!(
            r#"{{"step_id": {step_id}, "source": "agent", "message": "run",
                 "tool_calls": [{{"tool_call_id": "{call_id}", "function_name": "bash",
                                  "arguments": "{{}}"}}],
                 "observation": {{"results": [{{"source_call_id": "{call_id}",
                                               "content": "boom\nExit code 1"}}]}}}}"#
        )
    }

    /// A version assertion, the claim class most likely to go unplaced.
    fn version_claim() -> crate::grounding::claims::Claim {
        crate::grounding::claims::Claim {
            text: "1.0.0".to_string(),
            class: crate::grounding::claims::ClaimClass::Version,
            value: None,
        }
    }

    fn ok_call(step_id: usize, call_id: &str) -> String {
        format!(
            r#"{{"step_id": {step_id}, "source": "agent", "message": "run",
                 "tool_calls": [{{"tool_call_id": "{call_id}", "function_name": "bash",
                                  "arguments": "{{}}"}}],
                 "observation": {{"results": [{{"source_call_id": "{call_id}",
                                               "content": "done\nExit code 0"}}]}}}}"#
        )
    }

    #[test]
    fn a_tool_less_exchange_reports_a_clean_summary() {
        let doc = trajectory(
            r#"{"step_id": 1, "source": "user", "message": "hi"},
               {"step_id": 2, "source": "agent", "message": "hello"}"#,
        );
        let summary = summarize_trajectory(&doc);
        assert!(summary.all_calls_ok);
        assert!(!summary.has_persisted_failure);
        assert_eq!(summary.total_findings, 0);
        assert!(summary.rules.is_empty());
    }

    #[test]
    fn a_failed_call_withholds_the_clean_verdict_and_names_its_rule() {
        let doc = trajectory(&format!(
            r#"{{"step_id": 1, "source": "user", "message": "run it"}},
               {}"#,
            failing_call(2, "c1")
        ));
        let summary = summarize_trajectory(&doc);
        assert!(!summary.all_calls_ok);
        // The exit-code rule is the one a human would be disputing.
        assert!(
            summary.rules.iter().any(|r| r.contains("R3")),
            "expected an exit-code rule, got {:?}",
            summary.rules
        );
    }

    #[test]
    fn a_successful_call_contributes_no_disputable_rule() {
        let doc = trajectory(&format!(
            r#"{{"step_id": 1, "source": "user", "message": "run it"}},
               {}"#,
            ok_call(2, "c1")
        ));
        let summary = summarize_trajectory(&doc);
        assert!(summary.all_calls_ok);
        assert!(summary.rules.is_empty());
    }

    #[test]
    fn an_early_round_failure_is_not_forgotten_by_a_later_clean_round() {
        // The reason the summary walks every round: judging only the last one
        // would call this trajectory sound.
        let doc = trajectory(&format!(
            r#"{{"step_id": 1, "source": "user", "message": "first"}},
               {},
               {{"step_id": 3, "source": "user", "message": "second"}},
               {{"step_id": 4, "source": "agent", "message": "fine"}}"#,
            failing_call(2, "c1")
        ));
        assert_eq!(round_ranges(&doc), vec![0..2, 2..4]);
        assert!(!summarize_trajectory(&doc).all_calls_ok);
    }

    #[test]
    fn rules_are_deduplicated_across_rounds() {
        // The same rule firing in both rounds must not inflate the statistics.
        let doc = trajectory(&format!(
            r#"{{"step_id": 1, "source": "user", "message": "first"}},
               {},
               {{"step_id": 3, "source": "user", "message": "second"}},
               {}"#,
            failing_call(2, "c1"),
            failing_call(4, "c2")
        ));
        let summary = summarize_trajectory(&doc);
        let mut sorted = summary.rules.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, summary.rules);
    }

    #[test]
    fn round_ranges_cover_every_step_exactly_once() {
        let doc = trajectory(
            r#"{"step_id": 1, "source": "system", "message": "prompt"},
               {"step_id": 2, "source": "user", "message": "a"},
               {"step_id": 3, "source": "agent", "message": "b"},
               {"step_id": 4, "source": "user", "message": "c"}"#,
        );
        // The opening system step starts a round of its own rather than being
        // dropped, which is what `slice_round` does.
        assert_eq!(round_ranges(&doc), vec![0..1, 1..3, 3..4]);
    }

    #[test]
    fn an_empty_trajectory_yields_no_rounds_and_a_clean_summary() {
        let doc = trajectory("");
        assert!(round_ranges(&doc).is_empty());
        let summary = summarize_trajectory(&doc);
        assert!(summary.all_calls_ok);
        assert_eq!(summary.total_findings, 0);
    }

    #[test]
    fn an_unplaced_claim_alone_does_not_accuse_without_a_model() {
        // Found on real data: every collected session came out `bad` on
        // `ungrounded_onset` alone, because agents paraphrase and string matching
        // cannot place a reworded observation. The attribution pipeline gives such
        // a claim one semantic review before it may accuse; labelling has no
        // model, so it must not count it.
        assert!(!stands_without_review(&Finding::UngroundedOnset {
            step_id: 2,
            claim: version_claim(),
        }));
        assert!(stands_without_review(&Finding::FailureThenFabrication {
            failed_step_id: 2,
            function_name: "bash".to_string(),
            failure_quote: None,
            claim_step_id: 3,
            claim: version_claim(),
        }));
    }

    #[test]
    fn a_paraphrasing_agent_is_not_condemned() {
        // A trajectory whose only finding is an unplaced claim reports zero
        // verdict-driving findings, so the label lands on `unknown` rather than
        // `bad`. `total_findings` still counts it, which is what keeps the
        // trajectory from being called sound.
        let doc = trajectory(
            r#"{"step_id": 1, "source": "user", "message": "版本号是多少"},
               {"step_id": 2, "source": "agent", "message": "当前版本是 9.9.9 。"}"#,
        );
        let summary = summarize_trajectory(&doc);
        assert_eq!(summary.verdict_driving_findings, 0);
        assert!(summary.total_findings > 0, "the claim is still recorded");
    }

    #[test]
    fn summarizing_is_deterministic() {
        let doc = trajectory(&format!(
            r#"{{"step_id": 1, "source": "user", "message": "run"}},
               {}"#,
            failing_call(2, "c1")
        ));
        assert_eq!(summarize_trajectory(&doc), summarize_trajectory(&doc));
    }

    #[test]
    fn finding_rule_names_are_spelled_out_not_derived() {
        // Guards the stored identifiers against a variant rename.
        let claim = version_claim();
        assert_eq!(
            finding_rule(&Finding::UngroundedOnset {
                step_id: 1,
                claim: claim.clone(),
            }),
            "ungrounded_onset"
        );
        assert_eq!(
            finding_rule(&Finding::RepeatedIdenticalFailure {
                step_id: 1,
                function_name: "bash".to_string(),
                attempts: 3,
                quote: None,
            }),
            "repeated_identical_failure"
        );
        assert_eq!(
            finding_rule(&Finding::FailureThenFabrication {
                failed_step_id: 1,
                function_name: "bash".to_string(),
                failure_quote: None,
                claim_step_id: 2,
                claim,
            }),
            "failure_then_fabrication"
        );
    }
}
