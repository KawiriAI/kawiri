//! Per-WS token budget pre-check.
//!
//! The post-response guard in `server.rs` rejects the *next* request
//! once `budget_used >= cap`, but a single completion can overshoot
//! the cap by its full size. This pre-check looks at the client's
//! requested `max_tokens` / `max_completion_tokens` and rejects the
//! request *before* it hits the engine when it would push us past
//! the cap. Unit-testable; pure function of (body, cap, used).

/// Verdict returned by `check_budget`. The caller maps the reject
/// case to a `KawiriStreamChunk { event: "error", data: ... }` close.
#[derive(Debug, PartialEq, Eq)]
pub enum BudgetVerdict {
    /// Send the request to the engine.
    Allow,
    /// Refuse the request — it would exceed the per-WS cap. Carries
    /// the requested-vs-remaining numbers so the rejection message
    /// can be specific.
    Reject { requested: u64, remaining: u64 },
}

/// Look at the request body's `max_tokens` (or `max_completion_tokens`)
/// field against the per-WS cap. Returns `Allow` when:
///   - there's no cap (`budget_cap = None`),
///   - the body is `None`,
///   - the body has no `max_tokens` field, OR
///   - `requested + budget_used <= cap`.
///
/// Returns `Reject` only when the client explicitly named a
/// `max_tokens` that would push them past the cap. Missing
/// `max_tokens` falls through to the post-response guard — engine
/// defaults aren't always knowable from kawa.
pub fn check_budget(
    body: Option<&serde_json::Value>,
    budget_cap: Option<u64>,
    budget_used: u64,
) -> BudgetVerdict {
    let Some(cap) = budget_cap else {
        return BudgetVerdict::Allow;
    };
    let Some(body) = body else {
        return BudgetVerdict::Allow;
    };
    let requested = body
        .get("max_tokens")
        .and_then(|v| v.as_u64())
        .or_else(|| body.get("max_completion_tokens").and_then(|v| v.as_u64()));
    let Some(want) = requested else {
        return BudgetVerdict::Allow;
    };
    let remaining = cap.saturating_sub(budget_used);
    if want > remaining {
        BudgetVerdict::Reject {
            requested: want,
            remaining,
        }
    } else {
        BudgetVerdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn no_cap_always_allows() {
        let body = json!({ "max_tokens": 1_000_000 });
        assert_eq!(check_budget(Some(&body), None, 0), BudgetVerdict::Allow);
        assert_eq!(
            check_budget(Some(&body), None, 999_999),
            BudgetVerdict::Allow
        );
    }

    #[test]
    fn no_body_allows() {
        assert_eq!(check_budget(None, Some(100), 50), BudgetVerdict::Allow);
    }

    #[test]
    fn missing_max_tokens_allows() {
        // No max_tokens / max_completion_tokens field → fall through
        // to the post-response guard.
        let body = json!({ "messages": [{ "role": "user", "content": "hi" }] });
        assert_eq!(
            check_budget(Some(&body), Some(100), 50),
            BudgetVerdict::Allow
        );
    }

    #[test]
    fn under_remaining_allows() {
        let body = json!({ "max_tokens": 50 });
        assert_eq!(
            check_budget(Some(&body), Some(100), 40),
            BudgetVerdict::Allow
        );
        // Exactly at the limit is still allowed — the post-check fires
        // at >=, so equal usage closes on the next request rather than
        // rejecting this one.
        let body = json!({ "max_tokens": 60 });
        assert_eq!(
            check_budget(Some(&body), Some(100), 40),
            BudgetVerdict::Allow
        );
    }

    #[test]
    fn over_remaining_rejects() {
        let body = json!({ "max_tokens": 61 });
        assert_eq!(
            check_budget(Some(&body), Some(100), 40),
            BudgetVerdict::Reject {
                requested: 61,
                remaining: 60
            }
        );
    }

    #[test]
    fn used_exceeds_cap_zero_remaining() {
        // After post-response guard didn't fire (race), kawa got
        // called again with budget_used > cap. saturating_sub keeps
        // remaining at 0 (not underflow) and any nonzero request is
        // rejected.
        let body = json!({ "max_tokens": 1 });
        assert_eq!(
            check_budget(Some(&body), Some(100), 200),
            BudgetVerdict::Reject {
                requested: 1,
                remaining: 0
            }
        );
    }

    #[test]
    fn max_completion_tokens_alias() {
        // OpenAI's newer field name is `max_completion_tokens`; we
        // accept either form.
        let body = json!({ "max_completion_tokens": 200 });
        assert_eq!(
            check_budget(Some(&body), Some(100), 0),
            BudgetVerdict::Reject {
                requested: 200,
                remaining: 100
            }
        );
    }

    #[test]
    fn max_tokens_wins_over_max_completion_tokens() {
        // If both are present, prefer `max_tokens` (the historic
        // field). Document the behavior so callers know which one
        // matters.
        let body = json!({ "max_tokens": 50, "max_completion_tokens": 10_000 });
        // 50 fits in 100; allowed.
        assert_eq!(
            check_budget(Some(&body), Some(100), 0),
            BudgetVerdict::Allow
        );
    }

    #[test]
    fn non_integer_max_tokens_treated_as_missing() {
        // `as_u64()` returns None for strings, floats, etc. → falls
        // through to Allow.
        let body = json!({ "max_tokens": "many" });
        assert_eq!(
            check_budget(Some(&body), Some(100), 0),
            BudgetVerdict::Allow
        );
        let body = json!({ "max_tokens": 50.5 });
        assert_eq!(
            check_budget(Some(&body), Some(100), 0),
            BudgetVerdict::Allow
        );
    }
}
