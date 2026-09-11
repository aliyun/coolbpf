//! The trajectory label as the dashboard and the retrieval layer see it: an
//! automatic verdict, an optional human one, and the rule for which wins.
//!
//! The governing decision is that an unconfirmed automatic label is still a
//! usable label. Waiting for someone to click would leave every freshly
//! collected trajectory unusable, so the automatic verdict takes effect
//! immediately and confirmation only records that a human agrees. What
//! confirmation *does* buy is the right to be treated as top-priority
//! evidence — see [`SessionLabel::is_human_backed`].

use serde::{Deserialize, Serialize};

use super::triage::{TriageMetrics, TriageOutcome};

/// Verdict on a whole trajectory.
///
/// Deliberately about the trajectory and nothing finer: a user asked to judge
/// "was this analysis right" should not have to rule on individual findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrajectoryLabel {
    /// Produced something that held up; a source of positive candidates.
    Good,
    /// Contains a re-checkable problem. Not the same as worthless — this is
    /// where counterexamples come from.
    Bad,
    /// Carries nothing reusable, so it leaves the retrieval scope entirely.
    Useless,
    /// Not enough evidence to say. The default, and not a defect.
    Unknown,
}

impl TrajectoryLabel {
    pub const ALL: [TrajectoryLabel; 4] = [Self::Good, Self::Bad, Self::Useless, Self::Unknown];

    /// Wire and storage representation, matching the serde renaming.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Good => "good",
            Self::Bad => "bad",
            Self::Useless => "useless",
            Self::Unknown => "unknown",
        }
    }

    /// Parses a stored or query-parameter token. `None` for anything unknown so
    /// callers reject it rather than silently filtering on the wrong label.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "good" => Some(Self::Good),
            "bad" => Some(Self::Bad),
            "useless" => Some(Self::Useless),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }

    /// Whether artifacts from a trajectory with this label must be kept out of
    /// retrieval results altogether.
    ///
    /// Only `Useless` qualifies. `Bad` explicitly does not: a trajectory that
    /// went wrong is the raw material for counterexamples.
    pub fn excluded_from_retrieval(&self) -> bool {
        matches!(self, Self::Useless)
    }

    /// Labels a user may assign by hand.
    ///
    /// `Unknown` is absent on purpose: it means "the rules could not tell",
    /// which is not something a person asserts.
    pub fn user_assignable() -> [TrajectoryLabel; 3] {
        [Self::Good, Self::Bad, Self::Useless]
    }
}

/// Whether a human has weighed in on the automatic label, and how.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmState {
    /// Nobody has looked. The automatic label is in force regardless.
    Unconfirmed,
    /// A human agreed with the automatic label.
    Confirmed,
    /// A human replaced it.
    Overridden,
}

impl ConfirmState {
    /// Wire and storage representation, matching the serde renaming.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unconfirmed => "unconfirmed",
            Self::Confirmed => "confirmed",
            Self::Overridden => "overridden",
        }
    }

    /// Parses a stored token; `None` when unrecognised.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "unconfirmed" => Some(Self::Unconfirmed),
            "confirmed" => Some(Self::Confirmed),
            "overridden" => Some(Self::Overridden),
            _ => None,
        }
    }
}

/// A human's verdict on the automatic label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action", content = "label")]
pub enum LabelAction {
    /// Accept the automatic label as it stands.
    Confirm,
    /// Replace it.
    Override(TrajectoryLabel),
}

/// How a label row reached its current state, for the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LabelEventKind {
    Confirm,
    Override,
    /// The automatic verdict was recomputed, which never overwrites a human
    /// decision but is recorded so a later disagreement can be explained.
    AutoRetriage,
}

impl LabelEventKind {
    /// Wire and storage representation, matching the serde renaming.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Confirm => "confirm",
            Self::Override => "override",
            Self::AutoRetriage => "auto_retriage",
        }
    }

    /// Parses a stored token; `None` when unrecognised.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "confirm" => Some(Self::Confirm),
            "override" => Some(Self::Override),
            "auto_retriage" => Some(Self::AutoRetriage),
            _ => None,
        }
    }
}

/// The label of one trajectory: automatic verdict, human verdict, and the
/// bookkeeping needed to keep them straight.
///
/// Both verdicts are kept for the row's whole life. The automatic one is never
/// erased by a human decision because it is the only evidence available for
/// judging which rules misfire; the human one is never erased by a recompute
/// because that is the promise made when the user was asked to decide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLabel {
    pub session_id: String,
    pub auto_label: TrajectoryLabel,
    pub auto_reason: String,
    /// Rule identifiers behind `auto_label`; see
    /// [`crate::reuse::triage::GroundingSummary::rules`].
    pub auto_rules: Vec<String>,
    /// `None` until somebody decides. Set by both `Confirm` and `Override` so
    /// [`Self::effective_label`] has a single rule to follow.
    pub human_label: Option<TrajectoryLabel>,
    pub human_reason: Option<String>,
    pub confirm_state: ConfirmState,
    /// Who decided. `None` while unconfirmed.
    pub decided_by: Option<String>,
    pub decided_at_ns: Option<i64>,
    /// The automatic verdict changed after a human decided, and still disagrees
    /// with them — the trajectory grew new rounds, most likely. A prompt to
    /// take another look, never a reason to stop honouring the human label.
    pub auto_changed_since_decision: bool,
    pub metrics: TriageMetrics,
    /// Number of grounding findings behind `auto_label`; see
    /// [`crate::reuse::triage::TriageOutcome::n_findings`].
    pub n_findings: usize,
    /// Hash of the ATIF document the automatic verdict was computed from.
    pub source_content_hash: String,
    /// Version of the rules that produced `auto_label`, so a rule change can
    /// trigger a recompute without discarding human decisions.
    pub triage_version: String,
    pub created_at_ns: i64,
    pub updated_at_ns: i64,
}

impl SessionLabel {
    /// Builds an unconfirmed row from a fresh automatic verdict.
    pub fn from_outcome(
        session_id: impl Into<String>,
        outcome: TriageOutcome,
        source_content_hash: impl Into<String>,
        triage_version: impl Into<String>,
        now_ns: i64,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            auto_label: outcome.label,
            auto_reason: outcome.reason,
            auto_rules: outcome.rules,
            human_label: None,
            human_reason: None,
            confirm_state: ConfirmState::Unconfirmed,
            decided_by: None,
            decided_at_ns: None,
            auto_changed_since_decision: false,
            metrics: outcome.metrics,
            n_findings: outcome.n_findings,
            source_content_hash: source_content_hash.into(),
            triage_version: triage_version.into(),
            created_at_ns: now_ns,
            updated_at_ns: now_ns,
        }
    }

    /// The label every downstream consumer must obey.
    ///
    /// Falls back to the automatic verdict while unconfirmed, which is what
    /// makes a freshly collected trajectory immediately usable.
    pub fn effective_label(&self) -> TrajectoryLabel {
        self.human_label.unwrap_or(self.auto_label)
    }

    /// Whether a person actually signed off on this label.
    ///
    /// The gate needs this separately from [`Self::effective_label`]: an
    /// unconfirmed automatic label is good enough to filter retrieval by, but
    /// not good enough to count as the human confirmation that lets an artifact
    /// be promoted to verified. Conflating the two would let every trajectory
    /// arrive pre-blessed.
    pub fn is_human_backed(&self) -> bool {
        !matches!(self.confirm_state, ConfirmState::Unconfirmed)
    }

    /// Whether the human contradicted the rules, which is the signal
    /// `label-stats` aggregates against [`Self::auto_rules`].
    pub fn was_overridden(&self) -> bool {
        matches!(self.confirm_state, ConfirmState::Overridden)
    }

    /// Records a human decision and returns the event kind to audit.
    ///
    /// `Confirm` stores the automatic label as the human one as well. That
    /// keeps `effective_label` to a single rule and closes a hole: were the
    /// confirmed value left implicit, a later recompute would silently move the
    /// effective label out from under a decision somebody had already made.
    pub fn apply_decision(
        &mut self,
        action: LabelAction,
        by: impl Into<String>,
        reason: Option<String>,
        now_ns: i64,
    ) -> LabelEventKind {
        let (label, state, kind) = match action {
            LabelAction::Confirm => (
                self.auto_label,
                ConfirmState::Confirmed,
                LabelEventKind::Confirm,
            ),
            LabelAction::Override(label) => {
                (label, ConfirmState::Overridden, LabelEventKind::Override)
            }
        };
        self.human_label = Some(label);
        self.human_reason = reason;
        self.confirm_state = state;
        self.decided_by = Some(by.into());
        self.decided_at_ns = Some(now_ns);
        // A decision settles the current disagreement by definition.
        self.auto_changed_since_decision = false;
        self.updated_at_ns = now_ns;
        kind
    }

    /// Applies a recomputed automatic verdict, leaving any human decision
    /// untouched.
    ///
    /// Sets [`Self::auto_changed_since_decision`] only when the rules actually
    /// changed their mind *and* still disagree with the human — a recompute that
    /// merely comes round to the human's view is not worth interrupting them
    /// for, and flagging every recompute would make the marker meaningless on
    /// rows that were overridden precisely because the rules were wrong.
    pub fn apply_retriage(
        &mut self,
        outcome: TriageOutcome,
        source_content_hash: impl Into<String>,
        triage_version: impl Into<String>,
        now_ns: i64,
    ) {
        let previous_auto = self.auto_label;
        self.auto_label = outcome.label;
        self.auto_reason = outcome.reason;
        self.auto_rules = outcome.rules;
        self.metrics = outcome.metrics;
        self.n_findings = outcome.n_findings;
        self.source_content_hash = source_content_hash.into();
        self.triage_version = triage_version.into();
        if let Some(human) = self.human_label {
            if previous_auto != outcome.label && human != outcome.label {
                self.auto_changed_since_decision = true;
            }
        }
        self.updated_at_ns = now_ns;
    }
}

#[cfg(test)]
mod tests {
    use super::super::triage::TriageMetrics;
    use super::*;

    fn outcome(label: TrajectoryLabel) -> TriageOutcome {
        TriageOutcome {
            label,
            reason: "test".to_string(),
            metrics: TriageMetrics::default(),
            n_findings: 0,
            rules: vec!["R1".to_string()],
        }
    }

    fn row(label: TrajectoryLabel) -> SessionLabel {
        SessionLabel::from_outcome("s1", outcome(label), "hash-1", "triage-v1", 100)
    }

    #[test]
    fn an_unconfirmed_auto_label_is_still_in_force() {
        let label = row(TrajectoryLabel::Bad);
        assert_eq!(label.confirm_state, ConfirmState::Unconfirmed);
        assert_eq!(label.effective_label(), TrajectoryLabel::Bad);
    }

    #[test]
    fn unconfirmed_is_not_human_backed() {
        // The distinction the gate depends on: usable as a filter, not usable
        // as the human sign-off that promotes an artifact.
        assert!(!row(TrajectoryLabel::Good).is_human_backed());
    }

    #[test]
    fn confirming_pins_the_label_and_counts_as_human_backed() {
        let mut label = row(TrajectoryLabel::Good);
        let kind = label.apply_decision(LabelAction::Confirm, "alice", None, 200);
        assert_eq!(kind, LabelEventKind::Confirm);
        assert_eq!(label.confirm_state, ConfirmState::Confirmed);
        assert_eq!(label.human_label, Some(TrajectoryLabel::Good));
        assert!(label.is_human_backed());
        assert!(!label.was_overridden());
    }

    #[test]
    fn overriding_wins_over_the_auto_label() {
        let mut label = row(TrajectoryLabel::Bad);
        let kind = label.apply_decision(
            LabelAction::Override(TrajectoryLabel::Good),
            "alice",
            Some("工具报错是预期的".to_string()),
            200,
        );
        assert_eq!(kind, LabelEventKind::Override);
        assert_eq!(label.effective_label(), TrajectoryLabel::Good);
        // The automatic verdict survives for the misfire statistics.
        assert_eq!(label.auto_label, TrajectoryLabel::Bad);
        assert_eq!(label.auto_rules, vec!["R1".to_string()]);
        assert!(label.was_overridden());
    }

    #[test]
    fn retriage_never_overwrites_a_human_decision() {
        let mut label = row(TrajectoryLabel::Bad);
        label.apply_decision(
            LabelAction::Override(TrajectoryLabel::Good),
            "alice",
            None,
            200,
        );
        label.apply_retriage(
            outcome(TrajectoryLabel::Useless),
            "hash-2",
            "triage-v2",
            300,
        );
        assert_eq!(label.effective_label(), TrajectoryLabel::Good);
        assert_eq!(label.human_label, Some(TrajectoryLabel::Good));
        assert_eq!(label.auto_label, TrajectoryLabel::Useless);
    }

    #[test]
    fn a_confirmed_label_survives_the_auto_verdict_changing() {
        // The "1+1 that later got a real follow-up" case: the confirmed value
        // still governs, and the user is prompted rather than overruled.
        let mut label = row(TrajectoryLabel::Useless);
        label.apply_decision(LabelAction::Confirm, "alice", None, 200);
        label.apply_retriage(outcome(TrajectoryLabel::Good), "hash-2", "triage-v1", 300);
        assert_eq!(label.effective_label(), TrajectoryLabel::Useless);
        assert!(label.auto_changed_since_decision);
    }

    #[test]
    fn retriage_agreeing_with_the_human_raises_no_flag() {
        let mut label = row(TrajectoryLabel::Bad);
        label.apply_decision(
            LabelAction::Override(TrajectoryLabel::Good),
            "alice",
            None,
            200,
        );
        label.apply_retriage(outcome(TrajectoryLabel::Good), "hash-2", "triage-v1", 300);
        assert!(!label.auto_changed_since_decision);
    }

    #[test]
    fn retriage_that_changes_nothing_raises_no_flag_on_an_overridden_row() {
        // Without the "did the auto verdict actually change" clause this would
        // be flagged on every recompute, since an overridden row disagrees with
        // its automatic verdict by construction.
        let mut label = row(TrajectoryLabel::Bad);
        label.apply_decision(
            LabelAction::Override(TrajectoryLabel::Good),
            "alice",
            None,
            200,
        );
        label.apply_retriage(outcome(TrajectoryLabel::Bad), "hash-2", "triage-v1", 300);
        assert!(!label.auto_changed_since_decision);
    }

    #[test]
    fn retriage_on_an_undecided_row_raises_no_flag() {
        let mut label = row(TrajectoryLabel::Unknown);
        label.apply_retriage(outcome(TrajectoryLabel::Bad), "hash-2", "triage-v1", 300);
        assert!(!label.auto_changed_since_decision);
        assert_eq!(label.effective_label(), TrajectoryLabel::Bad);
    }

    #[test]
    fn deciding_again_clears_a_pending_disagreement() {
        let mut label = row(TrajectoryLabel::Useless);
        label.apply_decision(LabelAction::Confirm, "alice", None, 200);
        label.apply_retriage(outcome(TrajectoryLabel::Good), "hash-2", "triage-v1", 300);
        assert!(label.auto_changed_since_decision);
        label.apply_decision(LabelAction::Confirm, "alice", None, 400);
        assert!(!label.auto_changed_since_decision);
        assert_eq!(label.effective_label(), TrajectoryLabel::Good);
    }

    #[test]
    fn only_useless_leaves_the_retrieval_scope() {
        assert!(TrajectoryLabel::Useless.excluded_from_retrieval());
        // Bad is the source of counterexamples, so it must stay searchable.
        assert!(!TrajectoryLabel::Bad.excluded_from_retrieval());
        assert!(!TrajectoryLabel::Good.excluded_from_retrieval());
        assert!(!TrajectoryLabel::Unknown.excluded_from_retrieval());
    }

    #[test]
    fn unknown_is_not_offered_to_users() {
        assert!(!TrajectoryLabel::user_assignable().contains(&TrajectoryLabel::Unknown));
    }

    #[test]
    fn label_and_state_tokens_round_trip() {
        for label in TrajectoryLabel::ALL {
            assert_eq!(TrajectoryLabel::parse(label.as_str()), Some(label));
        }
        for state in [
            ConfirmState::Unconfirmed,
            ConfirmState::Confirmed,
            ConfirmState::Overridden,
        ] {
            assert_eq!(ConfirmState::parse(state.as_str()), Some(state));
        }
        for kind in [
            LabelEventKind::Confirm,
            LabelEventKind::Override,
            LabelEventKind::AutoRetriage,
        ] {
            assert_eq!(LabelEventKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(TrajectoryLabel::parse("nonsense"), None);
        assert_eq!(ConfirmState::parse(""), None);
    }
}
