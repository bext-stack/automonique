// SPDX-License-Identifier: Elastic-2.0

//! M2 #13 verification: the three chat-surface safety properties.
//!
//! Each property is checked twice. Once against its reference model, which must
//! pass every case — that is what makes the suite a satisfiable gate rather than
//! an impossible one. And once against a family of **mutants**: subjects built
//! by taking the reference model and breaking exactly one thing. A mutant must
//! fail, and it must fail at the *named case* that describes what was broken.
//!
//! The mutants are the point. A conformance suite nothing can fail is
//! indistinguishable from no suite at all, and the specific way these properties
//! fail in the wild — a fallback that "handles" a broken route, an announcement
//! that authorizes every later change, an approval reused for a second deletion
//! — are the mutants written down.
//!
//! The fourth property, the scheduler core, is verified in
//! `automonique-core/tests/scheduler_conformance.rs`, where its substrate lives.

use std::path::Path;

use automonique_protocol::primitives::EpochMillis;
use automonique_protocol::safety_conformance::deletion_authority::{
    Approval, ApprovalClass, ApprovalId, AuthorityRecord, AuthorityRefusal, CredentialClass,
    DeletionAuthority, DeletionCredential, DeletionGrant, EffectReceipt, OrdinaryCredential,
    ResourceRef, Verb,
};
use automonique_protocol::safety_conformance::deploy_route::{
    DeliveryRecord, DeliveryTarget, DeployNotice, DeployNotifications, DeployReceipt,
    DeployRefusal, ReferenceDeployNotifier, RouteCondition,
};
use automonique_protocol::safety_conformance::mutation_announcement::{
    AnnouncedMutations, Announcement, AnnouncementId, AnnouncementRecord, AnnouncementRefusal,
    MIN_STOP_CHECK_WINDOW_MILLIS, MutationReceipt, MutationRefusal, MutationRequest,
    MutationTarget, ReferenceAnnouncer, StopCheckWindow, StopRefusal,
};
use automonique_protocol::safety_conformance::{
    PENDING_BINDINGS, SAFETY_CONFORMANCE_SCHEMA_V1, SafetyProperty, deletion_authority,
    deploy_route, mutation_announcement,
};

mod roster {
    use super::*;

    #[test]
    fn the_four_properties_are_named_once_each_and_spell_themselves() {
        assert_eq!(SafetyProperty::ALL.len(), 4);
        assert_eq!(
            SAFETY_CONFORMANCE_SCHEMA_V1,
            "automonique.safety-conformance/v1"
        );
        let mut spellings: Vec<&str> = SafetyProperty::ALL
            .iter()
            .map(|property| property.as_str())
            .collect();
        let total = spellings.len();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), total, "two properties share a spelling");
        for property in SafetyProperty::ALL {
            assert_eq!(
                SafetyProperty::from_spelling(property.as_str()),
                Some(property)
            );
            assert_eq!(property.to_string(), property.as_str());
        }
        assert_eq!(SafetyProperty::from_spelling("deploy"), None);
    }

    /// A citation nobody checks is a citation that rots. These four documents
    /// are the properties' semantics; the code is only their gate.
    #[test]
    fn every_property_cites_a_requirement_document_that_exists() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        for property in SafetyProperty::ALL {
            let path = property.requirement_path();
            assert!(
                path.starts_with("docs/product-plan/requirements/"),
                "{property} cites {path}, which is outside the requirements corpus"
            );
            assert!(
                root.join(path).is_file(),
                "{property} cites {path}, which does not exist"
            );
        }
    }

    /// Passing a suite proves a trait implementation has a property. It proves
    /// nothing about the daemon until something binds them, and this is the
    /// list of what has not been bound.
    #[test]
    fn every_property_names_its_outstanding_binding() {
        assert_eq!(PENDING_BINDINGS.len(), SafetyProperty::ALL.len());
        for (binding, property) in PENDING_BINDINGS.iter().zip(SafetyProperty::ALL) {
            assert_eq!(binding.property, property);
            assert!(!binding.surface.is_empty());
            assert!(
                binding.tracked_at.starts_with("docs/"),
                "{property}'s binding is tracked at {}, which is not a document in this tree",
                binding.tracked_at
            );
        }
    }
}

mod deploy {
    use super::*;

    /// One reference model, one broken thing at a time.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Fault {
        /// Refuses, then posts the notice to ticket intake anyway.
        FallsBackToIntake,
        /// Refuses in silence: no alert, so nobody learns the route is down.
        NeverAlerts,
        /// Holds out for two refusals and falls back on the third.
        DriftsAfter(usize),
        /// Fails closed and stays closed, even once the route is back.
        NeverRecovers,
    }

    struct MutantNotifier {
        inner: ReferenceDeployNotifier,
        fault: Fault,
        refusals: usize,
        intake: Vec<DeliveryRecord>,
        broken_once: bool,
        recovered: bool,
    }

    impl MutantNotifier {
        fn new(fault: Fault) -> Self {
            Self {
                inner: ReferenceDeployNotifier::default(),
                fault,
                refusals: 0,
                intake: Vec::new(),
                broken_once: false,
                recovered: false,
            }
        }
    }

    impl DeployNotifications for MutantNotifier {
        fn set_route(&mut self, condition: RouteCondition) {
            // "Never recovers" has to mean *after* a failure, or the mutant
            // would fail the suite's very first case instead of the one it is
            // built to fail.
            if condition == RouteCondition::Configured {
                self.recovered = self.broken_once;
            } else {
                self.broken_once = true;
                self.recovered = false;
            }
            self.inner.set_route(condition);
        }

        fn publish(&mut self, notice: &DeployNotice) -> Result<DeployReceipt, DeployRefusal> {
            if self.fault == Fault::NeverRecovers && self.recovered {
                return Err(DeployRefusal::RouteUnconfigured);
            }
            let outcome = self.inner.publish(notice);
            let Err(refusal) = outcome else {
                return outcome;
            };
            self.refusals += 1;
            let fall_back = match self.fault {
                Fault::FallsBackToIntake => true,
                Fault::DriftsAfter(patience) => self.refusals > patience,
                Fault::NeverAlerts | Fault::NeverRecovers => false,
            };
            if fall_back {
                self.intake.push(DeliveryRecord::delivered(
                    DeliveryTarget::TicketIntake,
                    notice.deployment_id().clone(),
                ));
                return Ok(DeployReceipt::delivered(notice.deployment_id().clone()));
            }
            Err(refusal)
        }

        fn journal(&self) -> Vec<DeliveryRecord> {
            let mut journal = self.inner.journal();
            if self.fault == Fault::NeverAlerts {
                journal.retain(|record| record.target() != DeliveryTarget::OperatorAlert);
            }
            journal.extend(self.intake.iter().cloned());
            journal
        }
    }

    #[test]
    fn the_reference_notifier_passes_every_case() {
        let mut subject = ReferenceDeployNotifier::default();
        let report = deploy_route::verify_deploy_route(&mut subject).expect("reference conforms");
        assert_eq!(report.property(), SafetyProperty::DeployRoute);
        assert_eq!(report.cases(), deploy_route::CASES.as_slice());
        assert_eq!(deploy_route::CASES.len(), 7);
    }

    #[test]
    fn a_refusal_records_itself_and_one_alert_and_no_intake() {
        let mut subject = ReferenceDeployNotifier::default();
        subject.set_route(RouteCondition::Unreachable);
        let notice = DeployNotice::new("deploy-a", "candidate promoted").expect("valid notice");
        let refusal = subject
            .publish(&notice)
            .expect_err("an unreachable route refuses");
        assert_eq!(refusal.category(), "route_unreachable");
        assert_eq!(refusal.condition(), RouteCondition::Unreachable);

        let records = subject.records();
        assert_eq!(
            records.len(),
            2,
            "a refusal writes its record and one alert"
        );
        assert!(
            records[0].is_refusal(),
            "the refusal is durable before the alert claims it"
        );
        assert_eq!(records[1].target(), DeliveryTarget::OperatorAlert);
        assert!(
            !records
                .iter()
                .any(|record| record.target() == DeliveryTarget::TicketIntake),
            "a refused notice reached intake"
        );
    }

    /// The receipt type cannot name a target, so a subject cannot claim a
    /// delivery to intake. It can only make one, which the journal shows.
    #[test]
    fn a_receipt_can_only_attest_to_the_deploy_channel() {
        let mut subject = ReferenceDeployNotifier::default();
        subject.set_route(RouteCondition::Configured);
        let notice = DeployNotice::new("deploy-b", "candidate promoted").expect("valid notice");
        let receipt = subject
            .publish(&notice)
            .expect("a configured route delivers");
        assert_eq!(receipt.target(), DeliveryTarget::DeployChannel);
        assert_eq!(receipt.deployment_id(), notice.deployment_id());
    }

    #[test]
    fn a_notice_is_bounded_and_control_free() {
        assert!(DeployNotice::new("", "summary").is_err());
        assert!(DeployNotice::new("deploy", "line\nbreak").is_err());
        assert!(
            DeployNotice::new("d".repeat(deploy_route::MAX_DEPLOYMENT_ID_BYTES + 1), "s").is_err()
        );
    }

    #[test]
    fn a_subject_that_falls_back_to_intake_fails_the_unconfigured_case() {
        let mut subject = MutantNotifier::new(Fault::FallsBackToIntake);
        let violation = deploy_route::verify_deploy_route(&mut subject)
            .expect_err("falling back to intake is not conformance");
        assert_eq!(
            violation.case(),
            deploy_route::CASE_UNCONFIGURED_ROUTE_REFUSES_AND_ALERTS
        );
        assert_eq!(violation.property(), SafetyProperty::DeployRoute);
    }

    #[test]
    fn a_subject_that_refuses_in_silence_fails_the_alert_case() {
        let mut subject = MutantNotifier::new(Fault::NeverAlerts);
        let violation = deploy_route::verify_deploy_route(&mut subject)
            .expect_err("a refusal nobody hears is not conformance");
        assert_eq!(
            violation.case(),
            deploy_route::CASE_UNCONFIGURED_ROUTE_REFUSES_AND_ALERTS
        );
        assert!(violation.detail().contains("operator alert"));
    }

    /// The realistic failure: the first refusals are honest, and the fallback
    /// was added for the case where the route "stays" broken.
    #[test]
    fn a_subject_that_drifts_after_a_few_refusals_fails_the_repetition_case() {
        let mut subject = MutantNotifier::new(Fault::DriftsAfter(3));
        let violation = deploy_route::verify_deploy_route(&mut subject)
            .expect_err("drifting into intake is not conformance");
        assert_eq!(
            violation.case(),
            deploy_route::CASE_REPEATED_REFUSAL_NEVER_DRIFTS
        );
    }

    #[test]
    fn a_subject_that_never_recovers_fails_the_recovery_case() {
        let mut subject = MutantNotifier::new(Fault::NeverRecovers);
        let violation = deploy_route::verify_deploy_route(&mut subject)
            .expect_err("fail-closed is not fail-stuck");
        assert_eq!(
            violation.case(),
            deploy_route::CASE_ROUTE_RECOVERY_RESUMES_DELIVERY
        );
    }
}

mod announcement {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Fault {
        /// Mutates without any announcement at all.
        MutatesUnannounced,
        /// Announces, then does not wait.
        IgnoresTheWindow,
        /// Treats an announcement as standing permission.
        ReusesAnnouncements,
        /// Accepts an announcement for a neighbouring target.
        IgnoresTargetMismatch,
        /// Lets a stopped announcement come back once the window elapses.
        ForgetsStops,
        /// Announces to a channel and calls that durable.
        NeverJournals,
    }

    struct MutantAnnouncer {
        inner: ReferenceAnnouncer,
        fault: Fault,
    }

    impl MutantAnnouncer {
        fn new(fault: Fault) -> Self {
            Self {
                inner: ReferenceAnnouncer::default(),
                fault,
            }
        }

        fn forge(request: &MutationRequest) -> MutationReceipt {
            MutationReceipt::new(
                request.announcement().unwrap_or(AnnouncementId::new(0)),
                request.target().clone(),
            )
        }
    }

    impl AnnouncedMutations for MutantAnnouncer {
        fn stop_check_window(&self) -> StopCheckWindow {
            self.inner.stop_check_window()
        }

        fn now(&self) -> EpochMillis {
            self.inner.now()
        }

        fn advance_clock(&mut self, millis: i64) {
            self.inner.advance_clock(millis);
        }

        fn announce(
            &mut self,
            target: &MutationTarget,
        ) -> Result<Announcement, AnnouncementRefusal> {
            self.inner.announce(target)
        }

        fn stop(&mut self, announcement: AnnouncementId) -> Result<(), StopRefusal> {
            self.inner.stop(announcement)
        }

        fn mutate(
            &mut self,
            request: &MutationRequest,
        ) -> Result<MutationReceipt, MutationRefusal> {
            match self.inner.mutate(request) {
                Ok(receipt) => Ok(receipt),
                Err(refusal) => {
                    let excused = matches!(
                        (self.fault, refusal),
                        (Fault::MutatesUnannounced, MutationRefusal::NotAnnounced)
                            | (
                                Fault::IgnoresTheWindow,
                                MutationRefusal::StopCheckWindowOpen { .. }
                            )
                            | (Fault::ReusesAnnouncements, MutationRefusal::AlreadyConsumed)
                            | (
                                Fault::IgnoresTargetMismatch,
                                MutationRefusal::TargetMismatch
                            )
                            | (Fault::ForgetsStops, MutationRefusal::Stopped)
                    );
                    if excused {
                        Ok(Self::forge(request))
                    } else {
                        Err(refusal)
                    }
                }
            }
        }

        fn journal(&self) -> Vec<AnnouncementRecord> {
            if self.fault == Fault::NeverJournals {
                return Vec::new();
            }
            self.inner.journal()
        }
    }

    #[test]
    fn the_reference_announcer_passes_every_case() {
        let mut subject = ReferenceAnnouncer::default();
        let report = mutation_announcement::verify_mutation_announcement(&mut subject)
            .expect("reference conforms");
        assert_eq!(report.property(), SafetyProperty::MutationAnnouncement);
        assert_eq!(report.cases(), mutation_announcement::CASES.as_slice());
        assert_eq!(mutation_announcement::CASES.len(), 10);
    }

    /// "About to update all the sites" is not a target anyone can act on.
    #[test]
    fn a_target_that_names_a_class_is_not_a_target() {
        for (scope, resource) in [
            ("workspace", "*"),
            ("workspace", "all"),
            ("ALL", "site-1"),
            ("workspace", "site-?"),
            ("workspace", "site-%"),
        ] {
            let refused = MutationTarget::exact(scope, resource)
                .expect_err("a pattern is not an exact target");
            assert_eq!(refused.category(), "target_not_exact");
        }
        // A word that merely contains a class word is a name, not a pattern.
        assert!(MutationTarget::exact("workspace", "smallest").is_ok());
        assert!(MutationTarget::exact("workspace", "site-1").is_ok());
    }

    #[test]
    fn a_window_below_the_floor_is_not_a_window() {
        let refused =
            StopCheckWindow::new(MIN_STOP_CHECK_WINDOW_MILLIS - 1).expect_err("below the floor");
        assert!(matches!(
            refused,
            mutation_announcement::WindowError::BelowFloor { .. }
        ));
        assert_eq!(
            StopCheckWindow::new(MIN_STOP_CHECK_WINDOW_MILLIS)
                .expect("the floor itself is a window")
                .millis(),
            MIN_STOP_CHECK_WINDOW_MILLIS
        );
    }

    /// The window is for stopping. Once it has closed, stopping is refused and
    /// the operator is told why rather than told nothing.
    #[test]
    fn a_stop_after_the_window_is_refused_by_name() {
        let mut subject = ReferenceAnnouncer::default();
        let target = MutationTarget::exact("workspace-a", "site-9").expect("valid target");
        let announcement = subject.announce(&target).expect("announce");
        subject.advance_clock(MIN_STOP_CHECK_WINDOW_MILLIS * 2);
        assert_eq!(
            subject.stop(announcement.id()),
            Err(StopRefusal::WindowClosed)
        );
        assert_eq!(
            subject.stop(AnnouncementId::new(u64::MAX)),
            Err(StopRefusal::UnknownAnnouncement)
        );
    }

    #[test]
    fn a_second_open_announcement_for_one_target_is_refused() {
        let mut subject = ReferenceAnnouncer::default();
        let target = MutationTarget::exact("workspace-a", "site-8").expect("valid target");
        let first = subject.announce(&target).expect("announce");
        let refusal = subject
            .announce(&target)
            .expect_err("one open announcement per target");
        assert_eq!(
            refusal,
            AnnouncementRefusal::AlreadyOpen {
                announcement: first.id()
            }
        );
        assert_eq!(refusal.category(), "announcement_already_open");
    }

    #[test]
    fn a_subject_that_mutates_unannounced_fails_the_first_case() {
        let mut subject = MutantAnnouncer::new(Fault::MutatesUnannounced);
        let violation = mutation_announcement::verify_mutation_announcement(&mut subject)
            .expect_err("an unannounced mutation is not conformance");
        assert_eq!(
            violation.case(),
            mutation_announcement::CASE_UNANNOUNCED_MUTATION_REFUSED
        );
    }

    #[test]
    fn a_subject_that_does_not_wait_fails_the_window_case() {
        let mut subject = MutantAnnouncer::new(Fault::IgnoresTheWindow);
        let violation = mutation_announcement::verify_mutation_announcement(&mut subject)
            .expect_err("announcing and acting at once is not a stop-check");
        assert_eq!(
            violation.case(),
            mutation_announcement::CASE_MUTATION_INSIDE_THE_WINDOW_REFUSED
        );
    }

    #[test]
    fn a_subject_that_reuses_announcements_fails_the_consumption_case() {
        let mut subject = MutantAnnouncer::new(Fault::ReusesAnnouncements);
        let violation = mutation_announcement::verify_mutation_announcement(&mut subject)
            .expect_err("a standing permission is not an announcement");
        assert_eq!(
            violation.case(),
            mutation_announcement::CASE_ONE_ANNOUNCEMENT_ONE_MUTATION
        );
    }

    #[test]
    fn a_subject_that_accepts_the_wrong_target_fails_the_exactness_case() {
        let mut subject = MutantAnnouncer::new(Fault::IgnoresTargetMismatch);
        let violation = mutation_announcement::verify_mutation_announcement(&mut subject)
            .expect_err("announcing one thing and changing another is not conformance");
        assert_eq!(
            violation.case(),
            mutation_announcement::CASE_ANNOUNCEMENT_BINDS_ITS_EXACT_TARGET
        );
    }

    #[test]
    fn a_subject_that_forgets_a_stop_fails_the_stop_case() {
        let mut subject = MutantAnnouncer::new(Fault::ForgetsStops);
        let violation = mutation_announcement::verify_mutation_announcement(&mut subject)
            .expect_err("a stop that expires is not a stop");
        assert_eq!(
            violation.case(),
            mutation_announcement::CASE_STOPPED_ANNOUNCEMENT_NEVER_AUTHORIZES
        );
    }

    #[test]
    fn a_subject_that_does_not_journal_fails_the_durability_case() {
        let mut subject = MutantAnnouncer::new(Fault::NeverJournals);
        let violation = mutation_announcement::verify_mutation_announcement(&mut subject)
            .expect_err("an announcement nobody recorded is not durable");
        assert_eq!(
            violation.case(),
            mutation_announcement::CASE_ANNOUNCEMENT_IS_DURABLE_FIRST
        );
    }
}

mod deletion {
    use super::*;
    use automonique_protocol::safety_conformance::deletion_authority::ReferenceDeletionAuthority;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Fault {
        /// The ordinary credential deletes, because the API was right there.
        OrdinaryDeletes,
        /// Any approval will do, as long as there is one.
        AnyApprovalDeletes,
        /// An approval for one message deletes its neighbour.
        IgnoresTheSubject,
        /// One approval, many deletions.
        ReplaysApprovals,
    }

    struct MutantAuthority {
        inner: ReferenceDeletionAuthority,
        fault: Fault,
    }

    impl MutantAuthority {
        fn new(fault: Fault) -> Self {
            Self {
                inner: ReferenceDeletionAuthority::default(),
                fault,
            }
        }

        fn forge(verb: Verb, subject: &ResourceRef, approval: &Approval) -> EffectReceipt {
            EffectReceipt::new(
                verb,
                match verb {
                    Verb::Delete => CredentialClass::Deletion,
                    Verb::Post | Verb::Update => CredentialClass::Ordinary,
                },
                subject.clone(),
                approval.id(),
            )
        }
    }

    impl DeletionAuthority for MutantAuthority {
        fn ordinary_credential(&self) -> OrdinaryCredential {
            self.inner.ordinary_credential()
        }

        fn deletion_credential(&self) -> DeletionCredential {
            self.inner.deletion_credential()
        }

        fn perform_ordinary(
            &mut self,
            credential: &OrdinaryCredential,
            verb: Verb,
            subject: &ResourceRef,
            approval: &Approval,
        ) -> Result<EffectReceipt, AuthorityRefusal> {
            if self.fault == Fault::OrdinaryDeletes && verb == Verb::Delete {
                return Ok(Self::forge(verb, subject, approval));
            }
            self.inner
                .perform_ordinary(credential, verb, subject, approval)
        }

        fn delete(
            &mut self,
            credential: &DeletionCredential,
            subject: &ResourceRef,
            approval: &Approval,
        ) -> Result<EffectReceipt, AuthorityRefusal> {
            match self.inner.delete(credential, subject, approval) {
                Ok(receipt) => Ok(receipt),
                Err(refusal) => {
                    let excused = matches!(
                        (self.fault, refusal),
                        (
                            Fault::AnyApprovalDeletes,
                            AuthorityRefusal::ApprovalClassMismatch { .. }
                        ) | (
                            Fault::IgnoresTheSubject,
                            AuthorityRefusal::ApprovalSubjectMismatch
                        ) | (
                            Fault::ReplaysApprovals,
                            AuthorityRefusal::ApprovalAlreadyConsumed
                        )
                    );
                    if excused {
                        Ok(Self::forge(Verb::Delete, subject, approval))
                    } else {
                        Err(refusal)
                    }
                }
            }
        }

        fn journal(&self) -> Vec<AuthorityRecord> {
            self.inner.journal()
        }
    }

    #[test]
    fn the_reference_authority_passes_every_case() {
        let mut subject = ReferenceDeletionAuthority::default();
        let report = deletion_authority::verify_deletion_authority(&mut subject)
            .expect("reference conforms");
        assert_eq!(report.property(), SafetyProperty::DeletionAuthority);
        assert_eq!(report.cases(), deletion_authority::CASES.as_slice());
        assert_eq!(deletion_authority::CASES.len(), 8);
    }

    /// "Separately held" is a property of the type, not a rule an
    /// implementation is asked to remember: there is one constructor and it
    /// refuses a grant issued to the ordinary credential's holder.
    #[test]
    fn a_deletion_credential_cannot_be_minted_for_the_ordinary_holder() {
        let ordinary = OrdinaryCredential::held_by("one-principal").expect("valid holder");
        let same = DeletionGrant::held_by("one-principal").expect("valid holder");
        assert_eq!(
            DeletionCredential::separately_held(same, &ordinary),
            Err(AuthorityRefusal::CredentialNotSeparatelyHeld)
        );

        let separate = DeletionGrant::held_by("another-principal").expect("valid holder");
        let credential =
            DeletionCredential::separately_held(separate, &ordinary).expect("distinct holders");
        assert_ne!(credential.holder(), ordinary.holder());
    }

    /// The refusal does not depend on how good the approval is, which is why
    /// this is checked with the strongest approval the caller could present.
    #[test]
    fn the_ordinary_delete_verb_refuses_even_with_a_deletion_approval() {
        let mut subject = ReferenceDeletionAuthority::default();
        let ordinary = subject.ordinary_credential();
        let resource = ResourceRef::new("chat", "message-1").expect("valid resource");
        let approval = Approval::new(
            ApprovalId::new(1),
            ApprovalClass::Deletion,
            resource.clone(),
        );
        assert_eq!(
            subject.perform_ordinary(&ordinary, Verb::Delete, &resource, &approval),
            Err(AuthorityRefusal::DeleteVerbUnavailable)
        );
        let journal = subject.journal();
        assert_eq!(journal.len(), 1, "the refused attempt is recorded");
        assert!(!journal[0].performed());
        assert_eq!(journal[0].verb(), Verb::Delete);
        assert_eq!(journal[0].credential(), CredentialClass::Ordinary);
    }

    #[test]
    fn an_unrecognised_credential_is_refused_by_name() {
        let mut subject = ReferenceDeletionAuthority::default();
        let stranger = OrdinaryCredential::held_by("someone-else").expect("valid holder");
        let resource = ResourceRef::new("chat", "message-2").expect("valid resource");
        let approval = Approval::new(
            ApprovalId::new(2),
            ApprovalClass::Ordinary,
            resource.clone(),
        );
        assert_eq!(
            subject.perform_ordinary(&stranger, Verb::Post, &resource, &approval),
            Err(AuthorityRefusal::UnknownCredential)
        );
    }

    #[test]
    fn a_subject_whose_ordinary_credential_deletes_fails_the_first_case() {
        let mut subject = MutantAuthority::new(Fault::OrdinaryDeletes);
        let violation = deletion_authority::verify_deletion_authority(&mut subject)
            .expect_err("one credential for everything is not conformance");
        assert_eq!(
            violation.case(),
            deletion_authority::CASE_ORDINARY_DELETE_REFUSES
        );
    }

    #[test]
    fn a_subject_that_accepts_any_approval_fails_the_class_case() {
        let mut subject = MutantAuthority::new(Fault::AnyApprovalDeletes);
        let violation = deletion_authority::verify_deletion_authority(&mut subject)
            .expect_err("deletion is a distinct approval class");
        assert_eq!(
            violation.case(),
            deletion_authority::CASE_DELETION_NEEDS_A_DELETION_APPROVAL
        );
    }

    #[test]
    fn a_subject_that_ignores_the_approved_subject_fails_the_binding_case() {
        let mut subject = MutantAuthority::new(Fault::IgnoresTheSubject);
        let violation = deletion_authority::verify_deletion_authority(&mut subject)
            .expect_err("an approval names one resource");
        assert_eq!(
            violation.case(),
            deletion_authority::CASE_APPROVAL_BINDS_ONE_SUBJECT
        );
    }

    #[test]
    fn a_subject_that_replays_approvals_fails_the_consumption_case() {
        let mut subject = MutantAuthority::new(Fault::ReplaysApprovals);
        let violation = deletion_authority::verify_deletion_authority(&mut subject)
            .expect_err("one approval authorizes one effect");
        assert_eq!(
            violation.case(),
            deletion_authority::CASE_APPROVAL_IS_CONSUMED_ONCE
        );
    }
}
