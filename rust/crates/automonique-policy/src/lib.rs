// SPDX-License-Identifier: Elastic-2.0

//! Pure policy evaluation shared by product health surfaces.
//!
//! This crate classifies observations supplied by a caller. It deliberately
//! performs no filesystem, process, environment, or network access.

#![forbid(unsafe_code)]

pub mod peer;

/// How strongly a policy rule affects aggregate health.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Importance {
    /// Missing, unsupported, or violated evidence fails closed.
    Required,
    /// Missing, unsupported, or violated evidence degrades health.
    Advisory,
    /// The observation is reported without changing aggregate health.
    Informational,
}

/// Evidence observed by a product health probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Observation<'a> {
    Satisfied,
    Violated(&'a str),
    Unavailable(&'a str),
    Unsupported(&'a str),
}

/// The disposition of one evaluated rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disposition {
    Pass,
    Degraded,
    Fail,
    Informational,
}

/// A named policy rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rule<'a> {
    id: &'a str,
    importance: Importance,
}

impl<'a> Rule<'a> {
    #[must_use]
    pub const fn new(id: &'a str, importance: Importance) -> Self {
        Self { id, importance }
    }

    #[must_use]
    pub const fn id(self) -> &'a str {
        self.id
    }

    #[must_use]
    pub const fn importance(self) -> Importance {
        self.importance
    }

    /// Evaluates supplied evidence without acquiring any evidence itself.
    #[must_use]
    pub const fn evaluate(self, observation: Observation<'a>) -> Evaluation<'a> {
        let disposition = match (self.importance, observation) {
            (_, Observation::Satisfied) => Disposition::Pass,
            (Importance::Required, _) => Disposition::Fail,
            (Importance::Advisory, _) => Disposition::Degraded,
            (Importance::Informational, _) => Disposition::Informational,
        };
        Evaluation {
            rule: self,
            observation,
            disposition,
        }
    }
}

/// Result of evaluating one observation against one rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Evaluation<'a> {
    rule: Rule<'a>,
    observation: Observation<'a>,
    disposition: Disposition,
}

impl<'a> Evaluation<'a> {
    #[must_use]
    pub const fn rule(self) -> Rule<'a> {
        self.rule
    }

    #[must_use]
    pub const fn observation(self) -> Observation<'a> {
        self.observation
    }

    #[must_use]
    pub const fn disposition(self) -> Disposition {
        self.disposition
    }

    #[must_use]
    pub const fn reason(self) -> Option<&'a str> {
        match self.observation {
            Observation::Satisfied => None,
            Observation::Violated(reason)
            | Observation::Unavailable(reason)
            | Observation::Unsupported(reason) => Some(reason),
        }
    }
}

/// Aggregate product health after policy evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Health {
    Unknown,
    Healthy,
    Degraded,
    Unhealthy,
}

/// Counts and worst health state for a collection of evaluations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Summary {
    pub health: Health,
    pub total: usize,
    pub passed: usize,
    pub degraded: usize,
    pub failed: usize,
    pub informational: usize,
    pub unavailable: usize,
    pub unsupported: usize,
}

/// Summarizes evaluations. An empty collection is explicitly `Unknown`.
#[must_use]
pub fn summarize(evaluations: &[Evaluation<'_>]) -> Summary {
    let mut summary = Summary {
        health: if evaluations.is_empty() {
            Health::Unknown
        } else {
            Health::Healthy
        },
        total: evaluations.len(),
        passed: 0,
        degraded: 0,
        failed: 0,
        informational: 0,
        unavailable: 0,
        unsupported: 0,
    };

    for evaluation in evaluations {
        match evaluation.disposition {
            Disposition::Pass => summary.passed += 1,
            Disposition::Degraded => {
                summary.degraded += 1;
                if summary.health == Health::Healthy {
                    summary.health = Health::Degraded;
                }
            }
            Disposition::Fail => {
                summary.failed += 1;
                summary.health = Health::Unhealthy;
            }
            Disposition::Informational => summary.informational += 1,
        }
        match evaluation.observation {
            Observation::Unavailable(_) => summary.unavailable += 1,
            Observation::Unsupported(_) => summary.unsupported += 1,
            Observation::Satisfied | Observation::Violated(_) => {}
        }
    }

    summary
}
