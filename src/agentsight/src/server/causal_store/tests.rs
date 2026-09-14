//! Behaviour tests for [`super::CausalCaseStore`].
//!
//! The store exists for one promise: what was persisted comes back unchanged
//! after the process that wrote it is long gone. Everything else — key
//! distinctness, overwrite semantics — protects that promise from being
//! silently narrowed.

use std::path::PathBuf;

use super::{CaseKey, CausalCaseStore};

fn tmp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("causal-store-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn store_at(path: &std::path::Path) -> CausalCaseStore {
    CausalCaseStore::open_private(path).unwrap()
}

#[test]
fn a_case_round_trips_byte_for_byte() {
    // The stored value is replayed verbatim to the client, so even formatting
    // differences would be visible. Byte equality is the contract.
    let dir = tmp_dir("roundtrip");
    let store = store_at(&dir);
    let json = r#"{"title":"案例","verdict":"fail","nodes":[]}"#;
    store
        .put(
            CaseKey {
                session_key: "conv:s1",
                round: Some(2),
                complaint: "为什么失败",
            },
            json,
        )
        .unwrap();
    assert_eq!(
        store
            .get(CaseKey {
                session_key: "conv:s1",
                round: Some(2),
                complaint: "为什么失败"
            })
            .unwrap()
            .as_deref(),
        Some(json)
    );
}

#[test]
fn a_case_survives_reopening_the_database() {
    // The whole point: restart loses the memory cache, not the answer.
    let dir = tmp_dir("reopen");
    let json = r#"{"verdict":"success"}"#;
    {
        let store = store_at(&dir);
        store
            .put(
                CaseKey {
                    session_key: "sess:s1",
                    round: None,
                    complaint: "c",
                },
                json,
            )
            .unwrap();
    }
    let store = store_at(&dir);
    assert_eq!(
        store
            .get(CaseKey {
                session_key: "sess:s1",
                round: None,
                complaint: "c"
            })
            .unwrap()
            .as_deref(),
        Some(json)
    );
}

#[test]
fn a_rerun_replaces_the_stored_answer() {
    // `force` re-runs the pipeline; the stored case must reflect the newest
    // answer, not keep both and guess.
    let dir = tmp_dir("overwrite");
    let store = store_at(&dir);
    let key = CaseKey {
        session_key: "conv:s1",
        round: None,
        complaint: "c",
    };
    store.put(key, r#"{"run":1}"#).unwrap();
    store.put(key, r#"{"run":2}"#).unwrap();
    assert_eq!(store.get(key).unwrap().as_deref(), Some(r#"{"run":2}"#));
    assert_eq!(store.count().unwrap(), 1, "replacement, not accumulation");
}

#[test]
fn a_different_complaint_is_a_different_case() {
    // The memory cache requires an exact complaint match; the store must not
    // be looser, or a new question would resurrect an old answer.
    let dir = tmp_dir("complaints");
    let store = store_at(&dir);
    store
        .put(
            CaseKey {
                session_key: "conv:s1",
                round: None,
                complaint: "慢",
            },
            r#"{"a":1}"#,
        )
        .unwrap();
    store
        .put(
            CaseKey {
                session_key: "conv:s1",
                round: None,
                complaint: "错",
            },
            r#"{"a":2}"#,
        )
        .unwrap();
    assert_eq!(store.count().unwrap(), 2);
    assert_eq!(
        store
            .get(CaseKey {
                session_key: "conv:s1",
                round: None,
                complaint: "错"
            })
            .unwrap()
            .as_deref(),
        Some(r#"{"a":2}"#)
    );
}

#[test]
fn the_last_round_and_round_zero_are_distinct() {
    // `None` means "the last round" and is a different question from round 0,
    // because the last round moves as a session grows.
    let dir = tmp_dir("rounds");
    let store = store_at(&dir);
    store
        .put(
            CaseKey {
                session_key: "conv:s1",
                round: None,
                complaint: "c",
            },
            r#"{"r":"last"}"#,
        )
        .unwrap();
    store
        .put(
            CaseKey {
                session_key: "conv:s1",
                round: Some(0),
                complaint: "c",
            },
            r#"{"r":0}"#,
        )
        .unwrap();
    assert_eq!(store.count().unwrap(), 2);
    assert_eq!(
        store
            .get(CaseKey {
                session_key: "conv:s1",
                round: Some(0),
                complaint: "c"
            })
            .unwrap()
            .as_deref(),
        Some(r#"{"r":0}"#)
    );
}

#[test]
fn a_missing_case_is_none_not_an_error() {
    let store = store_at(&tmp_dir("missing"));
    assert!(
        store
            .get(CaseKey {
                session_key: "conv:ghost",
                round: None,
                complaint: "c"
            })
            .unwrap()
            .is_none()
    );
}
