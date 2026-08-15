// SPDX-License-Identifier: Elastic-2.0

//! Deleting is not a verb the ordinary credential has.
//!
//! The property, from `docs/product-plan/requirements/deletion-authority.md`:
//! deletion is a **distinct approval class** exercised under a **separately
//! held credential**, and the ordinary credential's delete verb **refuses**.
//!
//! This is the one of the four properties with an observable reference
//! behaviour rather than an invented one. The legacy system already enforced it
//! with two credentials rather than one policy check
//! (`docs/product-plan/reference/legacy-inventory.md` § Configuration surface),
//! and `feature-parity.md:101` records the split as the thing to preserve. What
//! is being re-specified is the *contract*, not the decision.
//!
//! Two credentials matter more than one flag because a flag is a branch in code
//! that a bug can take, and a credential the process does not hold is a
//! capability the process does not have. The type shape says the same thing:
//! [`DeletionAuthority::perform_ordinary`] takes an [`OrdinaryCredential`] and a
//! [`Verb`], and refuses [`Verb::Delete`]; [`DeletionAuthority::delete`] takes a
//! [`DeletionCredential`] and no verb at all, because deleting is the only thing
//! that credential is for.
//!
//! ```
//! use automonique_protocol::safety_conformance::deletion_authority::{
//!     DeletionCredential, DeletionGrant, OrdinaryCredential,
//! };
//! let ordinary = OrdinaryCredential::held_by("bot").unwrap();
//! let grant = DeletionGrant::held_by("bot").unwrap();
//! let refused = DeletionCredential::separately_held(grant, &ordinary);
//! assert_eq!(refused.unwrap_err().category(), "credential_not_separately_held");
//! ```

use crate::primitives::{BoundedString, ValueError};
use crate::safety_conformance::{CaseLog, SafetyProperty, SafetyReport, SafetyViolation};

/// Maximum UTF-8 byte length of a credential holder identifier.
pub const MAX_HOLDER_BYTES: usize = 128;

/// Maximum UTF-8 byte length of either half of a resource reference.
pub const MAX_RESOURCE_COMPONENT_BYTES: usize = 192;

/// Who holds a credential. Never the credential itself.
///
/// A holder is a coordinate — which principal, which vault entry — and this
/// module never carries secret material. `crate::primitives::SecretText` is
/// where a value that must not be printed goes; nothing here needs one, because
/// conformance is about which credential was used, not what it was.
pub type HolderId = BoundedString<MAX_HOLDER_BYTES>;

/// One half of a resource reference.
pub type ResourceComponent = BoundedString<MAX_RESOURCE_COMPONENT_BYTES>;

/// The credential ordinary work runs under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrdinaryCredential {
    holder: HolderId,
}

impl OrdinaryCredential {
    /// Name the holder of the ordinary credential.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when the holder is empty, too long, or carries a
    /// control character.
    pub fn held_by(holder: impl Into<String>) -> Result<Self, ValueError> {
        Ok(Self {
            holder: HolderId::new(holder)?,
        })
    }

    /// Who holds it.
    #[must_use]
    pub const fn holder(&self) -> &HolderId {
        &self.holder
    }
}

/// An authorization to mint a deletion credential.
///
/// Separate from [`DeletionCredential`] so that minting one is an act with a
/// precondition rather than a constructor call.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionGrant {
    holder: HolderId,
}

impl DeletionGrant {
    /// Name the holder the grant is issued to.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when the holder is empty, too long, or carries a
    /// control character.
    pub fn held_by(holder: impl Into<String>) -> Result<Self, ValueError> {
        Ok(Self {
            holder: HolderId::new(holder)?,
        })
    }

    /// Who the grant is issued to.
    #[must_use]
    pub const fn holder(&self) -> &HolderId {
        &self.holder
    }
}

/// The credential deletion runs under, and nothing else.
///
/// [`DeletionCredential::separately_held`] is its only constructor, and it
/// refuses a grant issued to the ordinary credential's holder. "Separately
/// held" is therefore a property of the type rather than a rule an
/// implementation is asked to remember.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeletionCredential {
    holder: HolderId,
}

impl DeletionCredential {
    /// Mint a deletion credential from a grant held apart from `ordinary`.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityRefusal::CredentialNotSeparatelyHeld`] when the grant
    /// names the same holder as the ordinary credential. One principal holding
    /// both is one compromise away from holding neither separately, which is the
    /// arrangement this property exists to prevent.
    pub fn separately_held(
        grant: DeletionGrant,
        ordinary: &OrdinaryCredential,
    ) -> Result<Self, AuthorityRefusal> {
        if grant.holder() == ordinary.holder() {
            return Err(AuthorityRefusal::CredentialNotSeparatelyHeld);
        }
        Ok(Self {
            holder: grant.holder.clone(),
        })
    }

    /// Who holds it.
    #[must_use]
    pub const fn holder(&self) -> &HolderId {
        &self.holder
    }
}

/// What an ordinary credential may be asked to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verb {
    /// Create a new externally visible item.
    Post,
    /// Change an item this principal authored.
    Update,
    /// Remove an item.
    ///
    /// In the vocabulary because it must be refusable. An ordinary credential
    /// that simply has no way to express deletion would pass every test here and
    /// still fail the day a caller reaches for a general-purpose API.
    Delete,
}

impl Verb {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Post => "post",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }
}

/// Which credential a journal row was written under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialClass {
    /// The ordinary credential.
    Ordinary,
    /// The separately held deletion credential.
    Deletion,
}

impl CredentialClass {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Deletion => "deletion",
        }
    }
}

/// The class of decision an approval records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalClass {
    /// An approval of ordinary work.
    Ordinary,
    /// An approval of a deletion, specifically.
    Deletion,
}

impl ApprovalClass {
    /// Stable lowercase wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Deletion => "deletion",
        }
    }
}

/// An approval's identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ApprovalId(u64);

impl ApprovalId {
    /// Name an approval.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The underlying value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The exact thing an effect acts on.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceRef {
    surface: ResourceComponent,
    id: ResourceComponent,
}

impl ResourceRef {
    /// Name one resource on one surface.
    ///
    /// # Errors
    ///
    /// Returns [`ValueError`] when either half is empty, too long, or carries a
    /// control character.
    pub fn new(surface: impl Into<String>, id: impl Into<String>) -> Result<Self, ValueError> {
        Ok(Self {
            surface: ResourceComponent::new(surface)?,
            id: ResourceComponent::new(id)?,
        })
    }

    /// Which surface the resource is on.
    #[must_use]
    pub const fn surface(&self) -> &ResourceComponent {
        &self.surface
    }

    /// Which resource on that surface.
    #[must_use]
    pub const fn id(&self) -> &ResourceComponent {
        &self.id
    }
}

/// One recorded approval decision.
///
/// An approval names its class *and* its subject. Both bindings matter: a
/// deletion approved for one message is not an approval to delete a different
/// one, and an approval of ordinary work is not an approval to delete anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Approval {
    id: ApprovalId,
    class: ApprovalClass,
    subject: ResourceRef,
}

impl Approval {
    /// Record one approval.
    #[must_use]
    pub const fn new(id: ApprovalId, class: ApprovalClass, subject: ResourceRef) -> Self {
        Self { id, class, subject }
    }

    /// The approval's identifier.
    #[must_use]
    pub const fn id(&self) -> ApprovalId {
        self.id
    }

    /// What class of act it approves.
    #[must_use]
    pub const fn class(&self) -> ApprovalClass {
        self.class
    }

    /// The exact resource it approves that act on.
    #[must_use]
    pub const fn subject(&self) -> &ResourceRef {
        &self.subject
    }
}

/// Proof that one authorized effect happened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectReceipt {
    verb: Verb,
    credential: CredentialClass,
    subject: ResourceRef,
    approval: ApprovalId,
}

impl EffectReceipt {
    /// Record a performed effect.
    #[must_use]
    pub const fn new(
        verb: Verb,
        credential: CredentialClass,
        subject: ResourceRef,
        approval: ApprovalId,
    ) -> Self {
        Self {
            verb,
            credential,
            subject,
            approval,
        }
    }

    /// What was done.
    #[must_use]
    pub const fn verb(&self) -> Verb {
        self.verb
    }

    /// Under which credential.
    #[must_use]
    pub const fn credential(&self) -> CredentialClass {
        self.credential
    }

    /// To what.
    #[must_use]
    pub const fn subject(&self) -> &ResourceRef {
        &self.subject
    }

    /// On whose approval.
    #[must_use]
    pub const fn approval(&self) -> ApprovalId {
        self.approval
    }
}

/// Why an effect was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityRefusal {
    /// The ordinary credential was asked to delete.
    DeleteVerbUnavailable,
    /// The presented approval was of the wrong class for this act.
    ApprovalClassMismatch {
        /// The class this act requires.
        required: ApprovalClass,
        /// The class presented.
        presented: ApprovalClass,
    },
    /// The presented approval named a different resource.
    ApprovalSubjectMismatch,
    /// The presented approval already authorized its one effect.
    ApprovalAlreadyConsumed,
    /// A deletion credential was minted for the ordinary credential's holder.
    CredentialNotSeparatelyHeld,
    /// The subject does not recognise the presented credential.
    UnknownCredential,
}

impl AuthorityRefusal {
    /// Stable machine-readable category.
    #[must_use]
    pub const fn category(self) -> &'static str {
        match self {
            Self::DeleteVerbUnavailable => "delete_verb_unavailable",
            Self::ApprovalClassMismatch { .. } => "approval_class_mismatch",
            Self::ApprovalSubjectMismatch => "approval_subject_mismatch",
            Self::ApprovalAlreadyConsumed => "approval_already_consumed",
            Self::CredentialNotSeparatelyHeld => "credential_not_separately_held",
            Self::UnknownCredential => "unknown_credential",
        }
    }
}

/// What became of one attempted effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityOutcome {
    /// The effect happened.
    Performed,
    /// It was refused, for this reason.
    Refused(AuthorityRefusal),
}

/// One durable row: what was attempted, under what, and what happened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRecord {
    verb: Verb,
    credential: CredentialClass,
    subject: ResourceRef,
    approval: ApprovalId,
    approval_class: ApprovalClass,
    outcome: AuthorityOutcome,
}

impl AuthorityRecord {
    /// Record one attempt.
    #[must_use]
    pub const fn new(
        verb: Verb,
        credential: CredentialClass,
        subject: ResourceRef,
        approval: ApprovalId,
        approval_class: ApprovalClass,
        outcome: AuthorityOutcome,
    ) -> Self {
        Self {
            verb,
            credential,
            subject,
            approval,
            approval_class,
            outcome,
        }
    }

    /// What was attempted.
    #[must_use]
    pub const fn verb(&self) -> Verb {
        self.verb
    }

    /// Under which credential.
    #[must_use]
    pub const fn credential(&self) -> CredentialClass {
        self.credential
    }

    /// To what.
    #[must_use]
    pub const fn subject(&self) -> &ResourceRef {
        &self.subject
    }

    /// The approval presented.
    #[must_use]
    pub const fn approval(&self) -> ApprovalId {
        self.approval
    }

    /// The class of the approval presented.
    #[must_use]
    pub const fn approval_class(&self) -> ApprovalClass {
        self.approval_class
    }

    /// What happened.
    #[must_use]
    pub const fn outcome(&self) -> AuthorityOutcome {
        self.outcome
    }

    /// Whether this row records a performed effect.
    #[must_use]
    pub const fn performed(&self) -> bool {
        matches!(self.outcome, AuthorityOutcome::Performed)
    }
}

/// A subject that separates deletion from ordinary work.
pub trait DeletionAuthority {
    /// The ordinary credential this subject honours.
    fn ordinary_credential(&self) -> OrdinaryCredential;

    /// The deletion credential this subject honours.
    fn deletion_credential(&self) -> DeletionCredential;

    /// Perform ordinary work.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityRefusal::DeleteVerbUnavailable`] for [`Verb::Delete`],
    /// whatever else is true of the request. The refusal is unconditional: it is
    /// not "delete needs a better approval", it is "this credential does not
    /// delete".
    fn perform_ordinary(
        &mut self,
        credential: &OrdinaryCredential,
        verb: Verb,
        subject: &ResourceRef,
        approval: &Approval,
    ) -> Result<EffectReceipt, AuthorityRefusal>;

    /// Delete, under the separately held credential.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorityRefusal`] when the approval is of the wrong class,
    /// names a different subject, or has already been consumed.
    fn delete(
        &mut self,
        credential: &DeletionCredential,
        subject: &ResourceRef,
        approval: &Approval,
    ) -> Result<EffectReceipt, AuthorityRefusal>;

    /// Every attempt the subject has recorded, oldest first.
    fn journal(&self) -> Vec<AuthorityRecord>;
}

/// Case names this suite runs, in order.
pub const CASES: [&str; 8] = [
    CASE_FRESH_SUBJECT,
    CASE_CREDENTIALS_ARE_SEPARATELY_HELD,
    CASE_ORDINARY_DELETE_REFUSES,
    CASE_ORDINARY_VERBS_STILL_WORK,
    CASE_DELETION_NEEDS_A_DELETION_APPROVAL,
    CASE_APPROVAL_BINDS_ONE_SUBJECT,
    CASE_APPROVAL_IS_CONSUMED_ONCE,
    CASE_EVERY_DELETION_CITES_A_DELETION_APPROVAL,
];

/// The suite requires a subject with an empty journal.
pub const CASE_FRESH_SUBJECT: &str = "the_subject_starts_with_an_empty_journal";
/// The two credentials are held by different principals.
pub const CASE_CREDENTIALS_ARE_SEPARATELY_HELD: &str = "the_two_credentials_are_separately_held";
/// The ordinary credential's delete verb refuses.
pub const CASE_ORDINARY_DELETE_REFUSES: &str = "the_ordinary_credential_refuses_the_delete_verb";
/// Refusing to delete does not break ordinary work.
pub const CASE_ORDINARY_VERBS_STILL_WORK: &str = "the_ordinary_credential_still_posts_and_updates";
/// Deletion is a distinct approval class.
pub const CASE_DELETION_NEEDS_A_DELETION_APPROVAL: &str =
    "a_deletion_requires_a_deletion_class_approval";
/// An approval covers the resource it names and no other.
pub const CASE_APPROVAL_BINDS_ONE_SUBJECT: &str = "an_approval_authorizes_only_its_exact_subject";
/// An approval authorizes one effect.
pub const CASE_APPROVAL_IS_CONSUMED_ONCE: &str = "an_approval_authorizes_exactly_one_effect";
/// Nothing in the run deleted on anything but a deletion approval.
pub const CASE_EVERY_DELETION_CITES_A_DELETION_APPROVAL: &str =
    "every_performed_deletion_cites_a_deletion_class_approval";

/// Run the deletion-authority suite against `subject`.
///
/// The subject must be freshly constructed, and must honour the credentials it
/// returns from [`DeletionAuthority::ordinary_credential`] and
/// [`DeletionAuthority::deletion_credential`] — the suite presents those and no
/// others, so a subject is never asked to accept a credential it has not been
/// configured with.
///
/// # Errors
///
/// Returns the first [`SafetyViolation`] the subject produces.
pub fn verify_deletion_authority<S: DeletionAuthority + ?Sized>(
    subject: &mut S,
) -> Result<SafetyReport, SafetyViolation> {
    let mut log = CaseLog::new(SafetyProperty::DeletionAuthority);

    log.require(
        CASE_FRESH_SUBJECT,
        subject.journal().is_empty(),
        "the subject already had records; the suite needs a freshly constructed subject",
    )?;
    log.passed(CASE_FRESH_SUBJECT);

    let ordinary = subject.ordinary_credential();
    let deletion = subject.deletion_credential();
    // The type has one constructor and that constructor refuses a shared
    // holder, so this cannot fail today. It is checked anyway: a second
    // constructor added later would make it possible, and this is the assertion
    // that would notice.
    log.require(
        CASE_CREDENTIALS_ARE_SEPARATELY_HELD,
        ordinary.holder() != deletion.holder(),
        "one principal holds both the ordinary and the deletion credential",
    )?;
    log.passed(CASE_CREDENTIALS_ARE_SEPARATELY_HELD);

    let first = resource(&log, CASE_ORDINARY_DELETE_REFUSES, "message-1")?;

    // The delete verb under the ordinary credential, presented with the best
    // approval it could possibly have. It still refuses.
    let deletion_approval =
        Approval::new(ApprovalId::new(1), ApprovalClass::Deletion, first.clone());
    match subject.perform_ordinary(&ordinary, Verb::Delete, &first, &deletion_approval) {
        Ok(_) => {
            return Err(log.failed(
                CASE_ORDINARY_DELETE_REFUSES,
                "the ordinary credential performed a deletion",
            ));
        }
        Err(refusal) => log.require(
            CASE_ORDINARY_DELETE_REFUSES,
            refusal == AuthorityRefusal::DeleteVerbUnavailable,
            format!(
                "the ordinary delete verb refused with {}; it must refuse as an unavailable verb",
                refusal.category()
            ),
        )?,
    }
    log.require(
        CASE_ORDINARY_DELETE_REFUSES,
        !subject.journal().iter().any(AuthorityRecord::performed),
        "a refused deletion left a performed record",
    )?;
    log.passed(CASE_ORDINARY_DELETE_REFUSES);

    // Ordinary work is unaffected. A property that shuts the surface down
    // instead of narrowing it is a different, worse property.
    for (index, verb) in [Verb::Post, Verb::Update].into_iter().enumerate() {
        let subject_ref = resource(
            &log,
            CASE_ORDINARY_VERBS_STILL_WORK,
            &format!("message-ordinary-{index}"),
        )?;
        let approval = Approval::new(
            ApprovalId::new(10 + index as u64),
            ApprovalClass::Ordinary,
            subject_ref.clone(),
        );
        let receipt = subject
            .perform_ordinary(&ordinary, verb, &subject_ref, &approval)
            .map_err(|refusal| {
                log.failed(
                    CASE_ORDINARY_VERBS_STILL_WORK,
                    format!(
                        "the ordinary credential refused {} with {}",
                        verb.as_str(),
                        refusal.category()
                    ),
                )
            })?;
        log.require(
            CASE_ORDINARY_VERBS_STILL_WORK,
            receipt.verb() == verb && receipt.credential() == CredentialClass::Ordinary,
            "the receipt did not record the verb and credential it acted under",
        )?;
    }
    log.passed(CASE_ORDINARY_VERBS_STILL_WORK);

    // Deletion under the right credential but an ordinary approval.
    let second = resource(&log, CASE_DELETION_NEEDS_A_DELETION_APPROVAL, "message-2")?;
    let ordinary_approval =
        Approval::new(ApprovalId::new(20), ApprovalClass::Ordinary, second.clone());
    match subject.delete(&deletion, &second, &ordinary_approval) {
        Ok(_) => {
            return Err(log.failed(
                CASE_DELETION_NEEDS_A_DELETION_APPROVAL,
                "a deletion proceeded on an ordinary-class approval",
            ));
        }
        Err(refusal) => log.require(
            CASE_DELETION_NEEDS_A_DELETION_APPROVAL,
            refusal
                == AuthorityRefusal::ApprovalClassMismatch {
                    required: ApprovalClass::Deletion,
                    presented: ApprovalClass::Ordinary,
                },
            format!(
                "a deletion on an ordinary approval refused with {}",
                refusal.category()
            ),
        )?,
    }
    // The same deletion, correctly approved, proceeds.
    let approved = Approval::new(ApprovalId::new(21), ApprovalClass::Deletion, second.clone());
    let receipt = subject
        .delete(&deletion, &second, &approved)
        .map_err(|refusal| {
            log.failed(
                CASE_DELETION_NEEDS_A_DELETION_APPROVAL,
                format!(
                    "a correctly approved deletion refused with {}",
                    refusal.category()
                ),
            )
        })?;
    log.require(
        CASE_DELETION_NEEDS_A_DELETION_APPROVAL,
        receipt.verb() == Verb::Delete
            && receipt.credential() == CredentialClass::Deletion
            && receipt.approval() == approved.id(),
        "the deletion receipt did not cite the deletion credential and its approval",
    )?;
    log.passed(CASE_DELETION_NEEDS_A_DELETION_APPROVAL);

    // An approval for one resource does not authorize deleting its neighbour.
    let third = resource(&log, CASE_APPROVAL_BINDS_ONE_SUBJECT, "message-3")?;
    let fourth = resource(&log, CASE_APPROVAL_BINDS_ONE_SUBJECT, "message-4")?;
    let for_third = Approval::new(ApprovalId::new(30), ApprovalClass::Deletion, third);
    match subject.delete(&deletion, &fourth, &for_third) {
        Ok(_) => {
            return Err(log.failed(
                CASE_APPROVAL_BINDS_ONE_SUBJECT,
                "an approval for one resource authorized deleting another",
            ));
        }
        Err(refusal) => log.require(
            CASE_APPROVAL_BINDS_ONE_SUBJECT,
            refusal == AuthorityRefusal::ApprovalSubjectMismatch,
            format!("a mismatched subject refused with {}", refusal.category()),
        )?,
    }
    log.passed(CASE_APPROVAL_BINDS_ONE_SUBJECT);

    // The approval that authorized the earlier deletion cannot authorize
    // another one.
    match subject.delete(&deletion, &second, &approved) {
        Ok(_) => {
            return Err(log.failed(
                CASE_APPROVAL_IS_CONSUMED_ONCE,
                "a consumed approval authorized a second deletion",
            ));
        }
        Err(refusal) => log.require(
            CASE_APPROVAL_IS_CONSUMED_ONCE,
            refusal == AuthorityRefusal::ApprovalAlreadyConsumed,
            format!("a replayed approval refused with {}", refusal.category()),
        )?,
    }
    log.passed(CASE_APPROVAL_IS_CONSUMED_ONCE);

    // The whole run, not just the windows the earlier cases inspected.
    let journal = subject.journal();
    log.require(
        CASE_EVERY_DELETION_CITES_A_DELETION_APPROVAL,
        journal
            .iter()
            .filter(|record| record.performed() && record.verb() == Verb::Delete)
            .all(|record| {
                record.credential() == CredentialClass::Deletion
                    && record.approval_class() == ApprovalClass::Deletion
            }),
        "a performed deletion was recorded without a deletion credential and approval",
    )?;
    log.require(
        CASE_EVERY_DELETION_CITES_A_DELETION_APPROVAL,
        journal
            .iter()
            .filter(|record| record.performed() && record.verb() == Verb::Delete)
            .count()
            == 1,
        "the run performed a number of deletions other than the one it authorized",
    )?;
    log.passed(CASE_EVERY_DELETION_CITES_A_DELETION_APPROVAL);

    Ok(log.finish())
}

fn resource(log: &CaseLog, case: &'static str, id: &str) -> Result<ResourceRef, SafetyViolation> {
    ResourceRef::new("chat", id)
        .map_err(|error| log.failed(case, format!("the suite's own fixture is invalid: {error}")))
}

/// An in-memory implementation that satisfies [`verify_deletion_authority`].
///
/// It deletes nothing: an "effect" is a row. The two credentials are minted at
/// construction, which is the only place in this module where the separateness
/// precondition is actually exercised.
#[derive(Clone, Debug)]
pub struct ReferenceDeletionAuthority {
    ordinary: OrdinaryCredential,
    deletion: DeletionCredential,
    journal: Vec<AuthorityRecord>,
    consumed: Vec<ApprovalId>,
}

impl Default for ReferenceDeletionAuthority {
    fn default() -> Self {
        let ordinary = OrdinaryCredential::held_by("ordinary-holder")
            .expect("the reference model's own holder name is valid");
        let grant = DeletionGrant::held_by("deletion-holder")
            .expect("the reference model's own holder name is valid");
        let deletion = DeletionCredential::separately_held(grant, &ordinary)
            .expect("the reference model's two holders differ");
        Self {
            ordinary,
            deletion,
            journal: Vec::new(),
            consumed: Vec::new(),
        }
    }
}

impl ReferenceDeletionAuthority {
    fn record(
        &mut self,
        verb: Verb,
        credential: CredentialClass,
        subject: &ResourceRef,
        approval: &Approval,
        outcome: AuthorityOutcome,
    ) {
        self.journal.push(AuthorityRecord::new(
            verb,
            credential,
            subject.clone(),
            approval.id(),
            approval.class(),
            outcome,
        ));
    }

    /// Check the bindings every authorized effect needs, whatever its class.
    fn check_approval(
        &self,
        required: ApprovalClass,
        subject: &ResourceRef,
        approval: &Approval,
    ) -> Result<(), AuthorityRefusal> {
        if approval.class() != required {
            return Err(AuthorityRefusal::ApprovalClassMismatch {
                required,
                presented: approval.class(),
            });
        }
        if approval.subject() != subject {
            return Err(AuthorityRefusal::ApprovalSubjectMismatch);
        }
        if self.consumed.contains(&approval.id()) {
            return Err(AuthorityRefusal::ApprovalAlreadyConsumed);
        }
        Ok(())
    }
}

impl DeletionAuthority for ReferenceDeletionAuthority {
    fn ordinary_credential(&self) -> OrdinaryCredential {
        self.ordinary.clone()
    }

    fn deletion_credential(&self) -> DeletionCredential {
        self.deletion.clone()
    }

    fn perform_ordinary(
        &mut self,
        credential: &OrdinaryCredential,
        verb: Verb,
        subject: &ResourceRef,
        approval: &Approval,
    ) -> Result<EffectReceipt, AuthorityRefusal> {
        let refusal = if credential != &self.ordinary {
            Some(AuthorityRefusal::UnknownCredential)
        } else if verb == Verb::Delete {
            // Checked before the approval, deliberately. The answer does not
            // depend on how good the approval is.
            Some(AuthorityRefusal::DeleteVerbUnavailable)
        } else {
            self.check_approval(ApprovalClass::Ordinary, subject, approval)
                .err()
        };
        if let Some(refusal) = refusal {
            self.record(
                verb,
                CredentialClass::Ordinary,
                subject,
                approval,
                AuthorityOutcome::Refused(refusal),
            );
            return Err(refusal);
        }
        self.consumed.push(approval.id());
        self.record(
            verb,
            CredentialClass::Ordinary,
            subject,
            approval,
            AuthorityOutcome::Performed,
        );
        Ok(EffectReceipt::new(
            verb,
            CredentialClass::Ordinary,
            subject.clone(),
            approval.id(),
        ))
    }

    fn delete(
        &mut self,
        credential: &DeletionCredential,
        subject: &ResourceRef,
        approval: &Approval,
    ) -> Result<EffectReceipt, AuthorityRefusal> {
        let refusal = if credential == &self.deletion {
            self.check_approval(ApprovalClass::Deletion, subject, approval)
                .err()
        } else {
            Some(AuthorityRefusal::UnknownCredential)
        };
        if let Some(refusal) = refusal {
            self.record(
                Verb::Delete,
                CredentialClass::Deletion,
                subject,
                approval,
                AuthorityOutcome::Refused(refusal),
            );
            return Err(refusal);
        }
        self.consumed.push(approval.id());
        self.record(
            Verb::Delete,
            CredentialClass::Deletion,
            subject,
            approval,
            AuthorityOutcome::Performed,
        );
        Ok(EffectReceipt::new(
            Verb::Delete,
            CredentialClass::Deletion,
            subject.clone(),
            approval.id(),
        ))
    }

    fn journal(&self) -> Vec<AuthorityRecord> {
        self.journal.clone()
    }
}
