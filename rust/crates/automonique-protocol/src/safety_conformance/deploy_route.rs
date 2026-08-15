// SPDX-License-Identifier: Elastic-2.0

//! Deployment notices reach a dedicated route or refuse. There is no third way.
//!
//! The property, from `docs/product-plan/requirements/deploy-notifications.md`:
//! a deployment notice is published to the **dedicated deploy route** and to
//! nothing else. If that route is unconfigured or unreachable, publication
//! **fails closed** — a typed refusal, durably recorded, plus an operator alert
//! — and the notice never reaches ticket intake.
//!
//! Ticket intake is the specific wrong answer this property exists to forbid,
//! which is why [`DeliveryTarget::TicketIntake`] is in the vocabulary at all: a
//! violation nothing can express is a violation no suite can catch. A
//! conforming subject never writes one.
//!
//! Fallback is the failure mode worth naming precisely. Nobody implements
//! "deploy notices go to the ticket queue"; it happens because a route lookup
//! returns nothing, a general-purpose send path is right there, and delivering
//! somewhere looks better than delivering nowhere. It is not better. A deploy
//! notice in the ticket queue is a notice in front of the wrong audience, and
//! the operator who needed to know the route was broken never finds out.
//!
//! ```
//! use automonique_protocol::safety_conformance::deploy_route::{
//!     DeployNotifications, DeployNotice, ReferenceDeployNotifier, RouteCondition,
//! };
//! let mut subject = ReferenceDeployNotifier::default();
//! subject.set_route(RouteCondition::Unconfigured);
//! let notice = DeployNotice::new("release-7", "candidate promoted").unwrap();
//! let refusal = subject.publish(&notice).unwrap_err();
//! assert_eq!(refusal.category(), "route_unconfigured");
//! ```

use crate::primitives::{BoundedString, ValueError};
use crate::safety_conformance::{CaseLog, SafetyProperty, SafetyReport, SafetyViolation};

/// Maximum UTF-8 byte length of a deployment identifier.
pub const MAX_DEPLOYMENT_ID_BYTES: usize = 128;

/// Maximum UTF-8 byte length of a notice summary.
pub const MAX_NOTICE_SUMMARY_BYTES: usize = 1024;

/// A deployment's identifier, bounded and control-free.
pub type DeploymentId = BoundedString<MAX_DEPLOYMENT_ID_BYTES>;

/// A notice summary, bounded and control-free.
pub type NoticeSummary = BoundedString<MAX_NOTICE_SUMMARY_BYTES>;

/// Condition of the dedicated deploy route, as the subject sees it.
///
/// The two failure conditions are distinct because the operator actions differ:
/// an unconfigured route needs configuration, an unreachable one needs
/// investigation. A subject that collapses them into one error tells the
/// operator to do the wrong thing half the time.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RouteCondition {
    /// A dedicated deploy route is configured and answers.
    Configured,
    /// No dedicated deploy route is configured.
    #[default]
    Unconfigured,
    /// A route is configured and the transport cannot reach it.
    Unreachable,
}

impl RouteCondition {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Unconfigured => "unconfigured",
            Self::Unreachable => "unreachable",
        }
    }
}

/// Where an outbound record was addressed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryTarget {
    /// The dedicated deploy route. The only admissible destination for a notice.
    DeployChannel,
    /// The operator alert path, used to report that the deploy route failed.
    OperatorAlert,
    /// Ticket intake.
    ///
    /// Present so that the forbidden delivery is representable and therefore
    /// detectable. A conforming subject never produces a record with this
    /// target; [`verify_deploy_route`] fails any subject that does.
    TicketIntake,
}

impl DeliveryTarget {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeployChannel => "deploy_channel",
            Self::OperatorAlert => "operator_alert",
            Self::TicketIntake => "ticket_intake",
        }
    }
}

/// One deployment notice awaiting publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeployNotice {
    deployment_id: DeploymentId,
    summary: NoticeSummary,
}

impl DeployNotice {
    /// Build a notice from a deployment identifier and a summary.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when either field is empty, over its ceiling, or
    /// carries a control character.
    pub fn new(
        deployment_id: impl Into<String>,
        summary: impl Into<String>,
    ) -> Result<Self, ValueError> {
        Ok(Self {
            deployment_id: DeploymentId::new(deployment_id)?,
            summary: NoticeSummary::new(summary)?,
        })
    }

    /// The deployment this notice reports.
    #[must_use]
    pub const fn deployment_id(&self) -> &DeploymentId {
        &self.deployment_id
    }

    /// What the notice says.
    #[must_use]
    pub const fn summary(&self) -> &NoticeSummary {
        &self.summary
    }
}

/// Proof that a notice reached the dedicated deploy route.
///
/// A receipt names no target, because there is only one target a receipt can
/// describe. "Delivered to intake" is therefore not a receipt a subject can
/// return; the closest it can do is return this receipt while writing an intake
/// record, which is exactly the case [`verify_deploy_route`] looks for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeployReceipt {
    deployment_id: DeploymentId,
}

impl DeployReceipt {
    /// Record that this deployment's notice reached the dedicated route.
    #[must_use]
    pub const fn delivered(deployment_id: DeploymentId) -> Self {
        Self { deployment_id }
    }

    /// The deployment the delivered notice reported.
    #[must_use]
    pub const fn deployment_id(&self) -> &DeploymentId {
        &self.deployment_id
    }

    /// The only target a receipt can attest to.
    #[must_use]
    pub const fn target(&self) -> DeliveryTarget {
        DeliveryTarget::DeployChannel
    }
}

/// Why a deployment notice was refused.
///
/// Every variant is a refusal to publish. None of them is a degraded
/// publication, and there is deliberately no variant meaning "published
/// somewhere else".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeployRefusal {
    /// No dedicated deploy route is configured.
    RouteUnconfigured,
    /// The configured route could not be reached after `attempts` attempts.
    RouteUnreachable {
        /// Delivery attempts made before the subject gave up.
        attempts: u32,
    },
}

impl DeployRefusal {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::RouteUnconfigured => "route_unconfigured",
            Self::RouteUnreachable { .. } => "route_unreachable",
        }
    }

    /// The route condition that produced this refusal.
    #[must_use]
    pub const fn condition(self) -> RouteCondition {
        match self {
            Self::RouteUnconfigured => RouteCondition::Unconfigured,
            Self::RouteUnreachable { .. } => RouteCondition::Unreachable,
        }
    }
}

/// What became of one addressed record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordOutcome {
    /// The record reached its target.
    Delivered,
    /// The subject refused to publish, for this reason.
    Refused(DeployRefusal),
}

/// One durable record the subject wrote while handling a notice.
///
/// The journal is the evidence. A refusal that is not recorded is a refusal
/// nobody can audit after the fact, and an operator alert that is not recorded
/// cannot be distinguished from one that was never sent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryRecord {
    target: DeliveryTarget,
    deployment_id: DeploymentId,
    outcome: RecordOutcome,
}

impl DeliveryRecord {
    /// Record a delivery to `target`.
    #[must_use]
    pub const fn delivered(target: DeliveryTarget, deployment_id: DeploymentId) -> Self {
        Self {
            target,
            deployment_id,
            outcome: RecordOutcome::Delivered,
        }
    }

    /// Record a refusal to publish to the dedicated route.
    #[must_use]
    pub const fn refused(deployment_id: DeploymentId, refusal: DeployRefusal) -> Self {
        Self {
            target: DeliveryTarget::DeployChannel,
            deployment_id,
            outcome: RecordOutcome::Refused(refusal),
        }
    }

    /// Where this record was addressed.
    #[must_use]
    pub const fn target(&self) -> DeliveryTarget {
        self.target
    }

    /// The deployment this record concerns.
    #[must_use]
    pub const fn deployment_id(&self) -> &DeploymentId {
        &self.deployment_id
    }

    /// What became of it.
    #[must_use]
    pub const fn outcome(&self) -> RecordOutcome {
        self.outcome
    }

    /// Whether this record is a refusal.
    #[must_use]
    pub const fn is_refusal(&self) -> bool {
        matches!(self.outcome, RecordOutcome::Refused(_))
    }
}

/// A subject that publishes deployment notices.
///
/// The trait is deliberately three methods wide. A conformance trait that grows
/// to cover an implementation's convenience becomes a description of that
/// implementation, and then it can only be passed by the code it was copied
/// from.
pub trait DeployNotifications {
    /// Put the dedicated deploy route into `condition`.
    ///
    /// This is the seam the suite drives. A daemon binds it to whatever makes
    /// its route unconfigured or unreachable in a test — an empty setting, a
    /// transport stub — and never to production configuration.
    fn set_route(&mut self, condition: RouteCondition);

    /// Publish one deployment notice to the dedicated deploy route.
    ///
    /// # Errors
    ///
    /// Returns a [`DeployRefusal`] when the route is unconfigured or
    /// unreachable. Returning an error is the *only* admissible response to
    /// those conditions.
    fn publish(&mut self, notice: &DeployNotice) -> Result<DeployReceipt, DeployRefusal>;

    /// Every record the subject has durably written, oldest first.
    fn journal(&self) -> Vec<DeliveryRecord>;
}

/// Case names this suite runs, in order.
pub const CASES: [&str; 7] = [
    CASE_FRESH_SUBJECT,
    CASE_CONFIGURED_ROUTE_DELIVERS_ONCE,
    CASE_UNCONFIGURED_ROUTE_REFUSES_AND_ALERTS,
    CASE_UNREACHABLE_ROUTE_REFUSES_AND_ALERTS,
    CASE_REPEATED_REFUSAL_NEVER_DRIFTS,
    CASE_ROUTE_RECOVERY_RESUMES_DELIVERY,
    CASE_INTAKE_IS_NEVER_A_DEPLOY_TARGET,
];

/// The suite requires a subject with an empty journal.
pub const CASE_FRESH_SUBJECT: &str = "the_subject_starts_with_an_empty_journal";
/// A configured route takes the notice, exactly once.
pub const CASE_CONFIGURED_ROUTE_DELIVERS_ONCE: &str = "a_configured_route_delivers_exactly_once";
/// An unconfigured route refuses by name and alerts an operator.
pub const CASE_UNCONFIGURED_ROUTE_REFUSES_AND_ALERTS: &str =
    "an_unconfigured_route_refuses_and_alerts";
/// An unreachable route refuses by name and alerts an operator.
pub const CASE_UNREACHABLE_ROUTE_REFUSES_AND_ALERTS: &str =
    "an_unreachable_route_refuses_and_alerts";
/// Repetition does not wear the property down.
pub const CASE_REPEATED_REFUSAL_NEVER_DRIFTS: &str = "repeated_refusal_never_drifts_into_intake";
/// A recovered route publishes again without operator intervention.
pub const CASE_ROUTE_RECOVERY_RESUMES_DELIVERY: &str = "a_recovered_route_resumes_delivery";
/// Nothing in the whole run was ever addressed to intake.
pub const CASE_INTAKE_IS_NEVER_A_DEPLOY_TARGET: &str = "intake_is_never_a_deploy_target";

/// How many times a refusing route is published to in the repetition case.
///
/// Three is enough to catch the two shapes of drift that matter — a subject
/// that falls back after N failures, and one that alerts only the first time —
/// without turning the suite into a load test.
pub const REPEATED_REFUSAL_ATTEMPTS: usize = 3;

/// Run the fail-closed deploy-route suite against `subject`.
///
/// The subject must be freshly constructed: the suite drives it from an empty
/// journal and reads the journal's growth as the record of what it did.
///
/// # Errors
///
/// Returns the first [`SafetyViolation`] the subject produces. A run stops at
/// the first failure, because the cases build on each other and a subject that
/// failed the first one produces uninterpretable evidence for the rest.
pub fn verify_deploy_route<S: DeployNotifications + ?Sized>(
    subject: &mut S,
) -> Result<SafetyReport, SafetyViolation> {
    let mut log = CaseLog::new(SafetyProperty::DeployRoute);

    log.require(
        CASE_FRESH_SUBJECT,
        subject.journal().is_empty(),
        "the subject already had records; the suite needs a freshly constructed subject",
    )?;
    log.passed(CASE_FRESH_SUBJECT);

    // A configured route delivers, once, to the deploy channel and nowhere else.
    subject.set_route(RouteCondition::Configured);
    let notice = fixture_notice(&log, CASE_CONFIGURED_ROUTE_DELIVERS_ONCE, "deploy-1")?;
    let before = subject.journal().len();
    match subject.publish(&notice) {
        Ok(receipt) => log.require(
            CASE_CONFIGURED_ROUTE_DELIVERS_ONCE,
            receipt.deployment_id() == notice.deployment_id(),
            "the receipt named a different deployment than the notice",
        )?,
        Err(refusal) => {
            return Err(log.failed(
                CASE_CONFIGURED_ROUTE_DELIVERS_ONCE,
                format!(
                    "a configured route refused with {}; a configured route publishes",
                    refusal.category()
                ),
            ));
        }
    }
    let written = written_since(subject, before);
    log.require(
        CASE_CONFIGURED_ROUTE_DELIVERS_ONCE,
        written.len() == 1,
        format!(
            "publishing to a configured route wrote {} records; exactly one delivery is expected",
            written.len()
        ),
    )?;
    log.require(
        CASE_CONFIGURED_ROUTE_DELIVERS_ONCE,
        written[0].target() == DeliveryTarget::DeployChannel
            && written[0].outcome() == RecordOutcome::Delivered,
        format!(
            "the delivery record targeted {} with outcome {:?}",
            written[0].target().as_str(),
            written[0].outcome()
        ),
    )?;
    log.passed(CASE_CONFIGURED_ROUTE_DELIVERS_ONCE);

    // The two fail-closed conditions, each refusing by its own name.
    for (case, condition, deployment, expected) in [
        (
            CASE_UNCONFIGURED_ROUTE_REFUSES_AND_ALERTS,
            RouteCondition::Unconfigured,
            "deploy-2",
            "route_unconfigured",
        ),
        (
            CASE_UNREACHABLE_ROUTE_REFUSES_AND_ALERTS,
            RouteCondition::Unreachable,
            "deploy-3",
            "route_unreachable",
        ),
    ] {
        subject.set_route(condition);
        let notice = fixture_notice(&log, case, deployment)?;
        let before = subject.journal().len();
        let refusal = match subject.publish(&notice) {
            Ok(_) => {
                return Err(log.failed(
                    case,
                    format!(
                        "publishing to an {} route succeeded; it must fail closed",
                        condition.as_str()
                    ),
                ));
            }
            Err(refusal) => refusal,
        };
        log.require(
            case,
            refusal.category() == expected,
            format!(
                "an {} route refused with {}; the refusal must name the condition",
                condition.as_str(),
                refusal.category()
            ),
        )?;
        let written = written_since(subject, before);
        log.require(
            case,
            written.iter().any(DeliveryRecord::is_refusal),
            "the refusal was not recorded; an unrecorded refusal cannot be audited",
        )?;
        log.require(
            case,
            written
                .iter()
                .filter(|record| record.target() == DeliveryTarget::OperatorAlert)
                .count()
                == 1,
            "a refusal raises exactly one operator alert",
        )?;
        log.require(
            case,
            !written
                .iter()
                .any(|record| record.target() == DeliveryTarget::TicketIntake),
            "the notice fell back to ticket intake",
        )?;
        log.require(
            case,
            !written.iter().any(|record| {
                record.target() == DeliveryTarget::DeployChannel
                    && record.outcome() == RecordOutcome::Delivered
            }),
            "a refused notice was also recorded as delivered",
        )?;
        log.passed(case);
    }

    // Repetition is where fallback usually appears: the second or third failure
    // is the one somebody decided to "handle".
    subject.set_route(RouteCondition::Unreachable);
    let before = subject.journal().len();
    for attempt in 0..REPEATED_REFUSAL_ATTEMPTS {
        let notice = fixture_notice(
            &log,
            CASE_REPEATED_REFUSAL_NEVER_DRIFTS,
            &format!("deploy-repeat-{attempt}"),
        )?;
        if subject.publish(&notice).is_ok() {
            return Err(log.failed(
                CASE_REPEATED_REFUSAL_NEVER_DRIFTS,
                format!("attempt {attempt} to an unreachable route succeeded"),
            ));
        }
    }
    let written = written_since(subject, before);
    log.require(
        CASE_REPEATED_REFUSAL_NEVER_DRIFTS,
        !written
            .iter()
            .any(|record| record.target() == DeliveryTarget::TicketIntake),
        "a repeated refusal fell back to ticket intake",
    )?;
    log.require(
        CASE_REPEATED_REFUSAL_NEVER_DRIFTS,
        written
            .iter()
            .filter(|record| record.target() == DeliveryTarget::OperatorAlert)
            .count()
            == REPEATED_REFUSAL_ATTEMPTS,
        "each refusal raises its own operator alert; alert suppression belongs to the alert transport",
    )?;
    log.passed(CASE_REPEATED_REFUSAL_NEVER_DRIFTS);

    // Fail-closed is not fail-stuck: a route that comes back is used again.
    subject.set_route(RouteCondition::Configured);
    let notice = fixture_notice(&log, CASE_ROUTE_RECOVERY_RESUMES_DELIVERY, "deploy-4")?;
    let before = subject.journal().len();
    if let Err(refusal) = subject.publish(&notice) {
        return Err(log.failed(
            CASE_ROUTE_RECOVERY_RESUMES_DELIVERY,
            format!(
                "a recovered route still refused with {}; fail-closed is not fail-stuck",
                refusal.category()
            ),
        ));
    }
    let written = written_since(subject, before);
    log.require(
        CASE_ROUTE_RECOVERY_RESUMES_DELIVERY,
        written.len() == 1 && written[0].outcome() == RecordOutcome::Delivered,
        "a recovered route did not record exactly one delivery",
    )?;
    log.passed(CASE_ROUTE_RECOVERY_RESUMES_DELIVERY);

    // The whole run, not just the windows the earlier cases looked at.
    let journal = subject.journal();
    log.require(
        CASE_INTAKE_IS_NEVER_A_DEPLOY_TARGET,
        !journal
            .iter()
            .any(|record| record.target() == DeliveryTarget::TicketIntake),
        "a deployment notice reached ticket intake at some point in the run",
    )?;
    log.passed(CASE_INTAKE_IS_NEVER_A_DEPLOY_TARGET);

    Ok(log.finish())
}

fn fixture_notice(
    log: &CaseLog,
    case: &'static str,
    deployment_id: &str,
) -> Result<DeployNotice, SafetyViolation> {
    DeployNotice::new(deployment_id, "deployment notice")
        .map_err(|error| log.failed(case, format!("the suite's own fixture is invalid: {error}")))
}

fn written_since<S: DeployNotifications + ?Sized>(
    subject: &S,
    before: usize,
) -> Vec<DeliveryRecord> {
    let mut journal = subject.journal();
    if before >= journal.len() {
        return Vec::new();
    }
    journal.split_off(before)
}

/// An in-memory implementation that satisfies [`verify_deploy_route`].
///
/// It exists to prove the suite is satisfiable and to document the intended
/// behaviour in code. It sends nothing: "delivery" is a row in a vector.
#[derive(Clone, Debug, Default)]
pub struct ReferenceDeployNotifier {
    condition: RouteCondition,
    journal: Vec<DeliveryRecord>,
}

impl ReferenceDeployNotifier {
    /// Attempts the reference model makes before declaring a route unreachable.
    pub const DELIVERY_ATTEMPTS: u32 = 3;

    /// Every record written so far, oldest first.
    #[must_use]
    pub fn records(&self) -> &[DeliveryRecord] {
        &self.journal
    }
}

impl DeployNotifications for ReferenceDeployNotifier {
    fn set_route(&mut self, condition: RouteCondition) {
        self.condition = condition;
    }

    fn publish(&mut self, notice: &DeployNotice) -> Result<DeployReceipt, DeployRefusal> {
        let deployment_id = notice.deployment_id().clone();
        match self.condition {
            RouteCondition::Configured => {
                self.journal.push(DeliveryRecord::delivered(
                    DeliveryTarget::DeployChannel,
                    deployment_id.clone(),
                ));
                Ok(DeployReceipt::delivered(deployment_id))
            }
            RouteCondition::Unconfigured => {
                Err(self.refuse(deployment_id, DeployRefusal::RouteUnconfigured))
            }
            RouteCondition::Unreachable => Err(self.refuse(
                deployment_id,
                DeployRefusal::RouteUnreachable {
                    attempts: Self::DELIVERY_ATTEMPTS,
                },
            )),
        }
    }

    fn journal(&self) -> Vec<DeliveryRecord> {
        self.journal.clone()
    }
}

impl ReferenceDeployNotifier {
    /// Record the refusal, then the alert. Order matters: the alert says a
    /// refusal happened, so the refusal is durable before anything claims it.
    fn refuse(&mut self, deployment_id: DeploymentId, refusal: DeployRefusal) -> DeployRefusal {
        self.journal
            .push(DeliveryRecord::refused(deployment_id.clone(), refusal));
        self.journal.push(DeliveryRecord::delivered(
            DeliveryTarget::OperatorAlert,
            deployment_id,
        ));
        refusal
    }
}
