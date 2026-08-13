// SPDX-License-Identifier: Elastic-2.0

//! Capability probe and mode selection.
//!
//! Two kinds of test live here. The first kind runs the real probe against this
//! host and asserts its findings are internally consistent and cross-check
//! against the kernel files and APIs they claim to describe; those assertions
//! are written as logical invariants so they hold on a host with delegation,
//! Landlock, and user namespaces just as well as on one with none of them. The
//! second kind drives the selector over a synthetic matrix of hosts this
//! machine is not, which is the only way to test the branches this host cannot
//! reach.

use automonique_runner::capability::{
    BoundaryProperty, ContainmentFinding, ContainmentUnavailable, EnforcementMode,
    HostCapabilities, LANDLOCK_ABI_FILESYSTEM, LANDLOCK_ABI_HIGHEST_KNOWN, LANDLOCK_ABI_TCP,
    LandlockAbi, LandlockFinding, Mechanism, ModeRefusal, SeccompFinding, SeccompUnavailable,
    UnsatisfiedCause, UserNamespaceDenial, UserNamespaceFinding,
};
use automonique_runner::{ContainmentDomain, ContainmentError};
use landlock::{
    ABI, Access as _, AccessFs, AccessNet, CompatLevel, Compatible as _, Ruleset, RulesetAttr as _,
    Scope,
};

// ---------------------------------------------------------------------------
// Synthetic host matrix
// ---------------------------------------------------------------------------

fn containment_finding(index: usize) -> ContainmentFinding {
    match index {
        0 => ContainmentFinding::Delegated,
        1 => ContainmentFinding::Unusable(ContainmentError::DomainNotDelegated),
        _ => ContainmentFinding::Unusable(ContainmentError::NotUnifiedCgroupV2),
    }
}

const CONTAINMENT_CASES: usize = 3;

const LANDLOCK_CASES: [LandlockFinding; 5] = [
    LandlockFinding::Unsupported,
    LandlockFinding::Enforceable(abi(1)),
    LandlockFinding::Enforceable(abi(3)),
    LandlockFinding::Enforceable(abi(4)),
    LandlockFinding::Enforceable(abi(9)),
];

const USER_NAMESPACE_CASES: [UserNamespaceFinding; 3] = [
    UserNamespaceFinding::NoObservedDenial,
    UserNamespaceFinding::Denied(UserNamespaceDenial::ApparmorRestricted),
    UserNamespaceFinding::Denied(UserNamespaceDenial::NoKernelSupport),
];

const SECCOMP_CASES: [SeccompFinding; 3] = [
    SeccompFinding::FilterAvailable,
    SeccompFinding::Unavailable(SeccompUnavailable::NoInterface),
    SeccompFinding::Unavailable(SeccompUnavailable::StrictModeOnly),
];

const fn abi(level: u8) -> LandlockAbi {
    match LandlockAbi::from_level(level) {
        Some(abi) => abi,
        None => panic!("test fixture uses an ABI level outside the known range"),
    }
}

/// Every combination of findings, including combinations this host is not.
fn synthetic_hosts() -> Vec<HostCapabilities> {
    let mut hosts = Vec::new();
    for containment in 0..CONTAINMENT_CASES {
        for landlock in LANDLOCK_CASES {
            for user_namespace in USER_NAMESPACE_CASES {
                for seccomp in SECCOMP_CASES {
                    hosts.push(HostCapabilities::from_findings(
                        containment_finding(containment),
                        landlock,
                        user_namespace,
                        seccomp,
                    ));
                }
            }
        }
    }
    hosts
}

/// Every subset of the property set, as requirement lists.
fn requirement_subsets() -> Vec<Vec<BoundaryProperty>> {
    (0..(1_u32 << BoundaryProperty::ALL.len()))
        .map(|mask| {
            BoundaryProperty::ALL
                .into_iter()
                .enumerate()
                .filter(|(index, _)| mask & (1 << index) != 0)
                .map(|(_, property)| property)
                .collect()
        })
        .collect()
}

fn full_host() -> HostCapabilities {
    HostCapabilities::from_findings(
        ContainmentFinding::Delegated,
        LandlockFinding::Enforceable(abi(LANDLOCK_ABI_HIGHEST_KNOWN)),
        UserNamespaceFinding::NoObservedDenial,
        SeccompFinding::FilterAvailable,
    )
}

// ---------------------------------------------------------------------------
// The real probe on this host
// ---------------------------------------------------------------------------

fn status_field(field: &str) -> Option<String> {
    std::fs::read_to_string("/proc/self/status")
        .ok()?
        .lines()
        .find_map(|line| {
            line.strip_prefix(field)
                .map(|value| value.trim().to_owned())
        })
}

/// A probe that restricted the calling process would be worse than useless: the
/// supervisor would silently inherit the boundary it was only asking about, and
/// nothing could undo it. This pins the observable process state that each
/// forbidden operation would change.
#[test]
fn probing_does_not_restrict_the_calling_process() {
    let before = (
        status_field("NoNewPrivs:"),
        status_field("Seccomp:"),
        status_field("Seccomp_filters:"),
        std::fs::read_link("/proc/self/ns/user").ok(),
        std::fs::read_link("/proc/self/ns/mnt").ok(),
        std::fs::read_link("/proc/self/ns/net").ok(),
        std::fs::read_to_string("/proc/self/cgroup").ok(),
    );

    let host = HostCapabilities::probe();

    let after = (
        status_field("NoNewPrivs:"),
        status_field("Seccomp:"),
        status_field("Seccomp_filters:"),
        std::fs::read_link("/proc/self/ns/user").ok(),
        std::fs::read_link("/proc/self/ns/mnt").ok(),
        std::fs::read_link("/proc/self/ns/net").ok(),
        std::fs::read_to_string("/proc/self/cgroup").ok(),
    );
    assert_eq!(
        before, after,
        "probing changed this process's own no_new_privs, seccomp, namespace, or cgroup state"
    );

    // A Landlock ruleset applied to this process would deny this read, and a
    // cgroup created by the probe would appear beneath the domain.
    assert!(
        std::fs::read_dir("/").is_ok(),
        "probing restricted this process's filesystem view"
    );

    // A probe with side effects would not answer the same way twice.
    let again = HostCapabilities::probe();
    assert_eq!(host.landlock(), again.landlock());
    assert_eq!(host.user_namespace(), again.user_namespace());
    assert_eq!(host.seccomp(), again.seccomp());
    assert_eq!(
        host.containment().is_delegated(),
        again.containment().is_delegated()
    );
}

/// Findings must not contradict themselves: a reported capability must carry
/// the concrete value that makes it usable, and a reported denial must carry the
/// reason that makes it actionable.
#[test]
fn probe_findings_are_internally_consistent() {
    let host = HostCapabilities::probe();

    match host.landlock() {
        LandlockFinding::Enforceable(measured) => {
            assert!(
                (LANDLOCK_ABI_FILESYSTEM..=LANDLOCK_ABI_HIGHEST_KNOWN).contains(&measured.level()),
                "enforceable Landlock reported an ABI outside the known range: {measured}"
            );
            assert!(
                measured.restricts_filesystem(),
                "enforceable Landlock must define filesystem access rights"
            );
            assert_eq!(measured.denies_tcp(), measured.level() >= LANDLOCK_ABI_TCP);
            assert_eq!(host.landlock().abi(), Some(measured));
        }
        LandlockFinding::Unsupported => {
            assert_eq!(
                host.landlock().abi(),
                None,
                "unsupported Landlock must carry no ABI"
            );
        }
    }

    match host.containment().denial() {
        None => assert!(host.containment().is_delegated()),
        Some(reason) => {
            assert!(!host.containment().is_delegated());
            let ContainmentFinding::Unusable(error) = host.containment() else {
                panic!("a denied containment finding must carry the typed discovery error");
            };
            assert!(
                !error.to_string().is_empty(),
                "the carried containment error must explain itself"
            );
            assert!(!reason.as_str().is_empty());
        }
    }

    match host.user_namespace() {
        UserNamespaceFinding::NoObservedDenial => {
            assert_eq!(host.user_namespace().denial(), None);
        }
        UserNamespaceFinding::Denied(denial) => {
            assert_eq!(host.user_namespace().denial(), Some(denial));
            assert!(!denial.to_string().is_empty());
        }
    }

    assert_eq!(
        host.seccomp().denial().is_none(),
        host.seccomp() == SeccompFinding::FilterAvailable
    );
}

/// The Landlock finding is re-derived here straight from the `landlock` crate,
/// so a hardcoded level, an off-by-one floor, or a probe that stopped measuring
/// would disagree with this test on any host.
#[test]
fn landlock_finding_matches_an_independent_measurement() {
    fn kernel_hard_requires(level: u8) -> bool {
        let target = ABI::from(i32::from(level));
        let filesystem = AccessFs::from_all(target);
        if filesystem.is_empty() {
            return false;
        }
        let Ok(ruleset) = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(filesystem)
        else {
            return false;
        };
        let network = AccessNet::from_all(target);
        let ruleset = if network.is_empty() {
            ruleset
        } else {
            match ruleset.handle_access(network) {
                Ok(ruleset) => ruleset,
                Err(_) => return false,
            }
        };
        let scope = Scope::from_all(target);
        if scope.is_empty() {
            return true;
        }
        ruleset.scope(scope).is_ok()
    }

    match HostCapabilities::probe().landlock() {
        LandlockFinding::Enforceable(measured) => {
            assert!(
                kernel_hard_requires(measured.level()),
                "the probe reported {measured} but the kernel rejects its access rights"
            );
            if measured.level() < LANDLOCK_ABI_HIGHEST_KNOWN {
                assert!(
                    !kernel_hard_requires(measured.level() + 1),
                    "the probe reported {measured} but the kernel accepts the next level too"
                );
            }
        }
        LandlockFinding::Unsupported => assert!(
            !kernel_hard_requires(LANDLOCK_ABI_FILESYSTEM),
            "the probe reported no Landlock but the kernel accepts ABI 1 access rights"
        ),
    }
}

/// A delegation claim is checked against the module that actually hands out
/// domains, so the probe cannot report a domain the runner could not create in.
#[test]
fn containment_finding_matches_independent_discovery() {
    let finding = ContainmentFinding::probe();
    let discovered = ContainmentDomain::discover();
    assert_eq!(
        finding.is_delegated(),
        discovered.is_ok(),
        "the probe and ContainmentDomain::discover disagree about delegation"
    );
    if let Err(error) = discovered {
        let expected = match error {
            ContainmentError::NotUnifiedCgroupV2 => ContainmentUnavailable::NoUnifiedHierarchy,
            ContainmentError::DomainNotDelegated => ContainmentUnavailable::NotDelegated,
            ContainmentError::MissingAtomicKill => ContainmentUnavailable::NoAtomicKill,
            _ => ContainmentUnavailable::Unreadable,
        };
        assert_eq!(finding.denial(), Some(expected));
    }
}

/// Each user-namespace denial names the kernel file it came from. Re-reading
/// that file here catches a probe that reports a plausible denial it did not
/// actually observe.
#[test]
fn user_namespace_denial_matches_the_kernel_file_it_names() {
    let finding = UserNamespaceFinding::probe();
    match finding.denial() {
        None => {
            assert!(
                std::fs::read_link("/proc/self/ns/user").is_ok(),
                "no denial was reported without a user-namespace identity"
            );
            for path in [
                "/proc/sys/user/max_user_namespaces",
                "/proc/sys/kernel/unprivileged_userns_clone",
            ] {
                if let Ok(text) = std::fs::read_to_string(path) {
                    assert_ne!(
                        text.trim().parse::<u64>().ok(),
                        Some(0),
                        "{path} forbids creation but no denial was reported"
                    );
                }
            }
            if let Ok(text) =
                std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
            {
                assert_eq!(
                    text.trim().parse::<u64>().ok(),
                    Some(0),
                    "AppArmor restricts user namespaces but no denial was reported"
                );
            }
        }
        Some(UserNamespaceDenial::NoKernelSupport) => {
            assert!(
                std::fs::read_link("/proc/self/ns/user").is_err(),
                "kernel support was denied although the namespace identity exists"
            );
        }
        Some(denial) => {
            let path = denial
                .evidence_path()
                .expect("a policy denial must name the kernel file it read");
            let text = std::fs::read_to_string(path)
                .unwrap_or_else(|_| panic!("{path} was named as evidence but cannot be read"));
            let value = text.trim().parse::<u64>().ok();
            let observed = match denial {
                UserNamespaceDenial::ApparmorRestricted => value.is_some_and(|value| value != 0),
                _ => value == Some(0),
            };
            assert!(
                observed,
                "{path} does not carry the denial the probe reported"
            );
        }
    }
}

/// Seccomp availability is claimed only from the kernel's own action list, and
/// only when that list contains an action that can refuse a syscall.
#[test]
fn seccomp_finding_matches_the_published_action_list() {
    let actions = std::fs::read_to_string("/proc/sys/kernel/seccomp/actions_avail").ok();
    match SeccompFinding::probe() {
        SeccompFinding::FilterAvailable => {
            let actions = actions.expect("filter mode was claimed without a published action list");
            assert!(
                actions.split_ascii_whitespace().any(|action| [
                    "kill_process",
                    "kill_thread",
                    "kill",
                    "errno",
                    "trap"
                ]
                .contains(&action)),
                "filter mode was claimed although no action can refuse a syscall: {actions}"
            );
        }
        SeccompFinding::Unavailable(SeccompUnavailable::NoDenyingAction) => {
            let actions = actions.expect("this reason requires a published action list");
            assert!(!actions.split_ascii_whitespace().any(|action| {
                ["kill_process", "kill_thread", "kill", "errno", "trap"].contains(&action)
            }));
        }
        SeccompFinding::Unavailable(_) => assert!(
            actions.is_none(),
            "seccomp was refused although the kernel publishes filter actions"
        ),
    }
}

// ---------------------------------------------------------------------------
// Selection: refusal
// ---------------------------------------------------------------------------

/// Without a delegated domain there is no mode at all, whatever else the host
/// offers: a workload that cannot be bounded and killed can carry any other
/// boundary out through a fork.
#[test]
fn a_host_without_a_containment_domain_has_no_mode_at_all() {
    let host = HostCapabilities::from_findings(
        ContainmentFinding::Unusable(ContainmentError::DomainNotDelegated),
        LandlockFinding::Enforceable(abi(LANDLOCK_ABI_HIGHEST_KNOWN)),
        UserNamespaceFinding::NoObservedDenial,
        SeccompFinding::FilterAvailable,
    );
    assert!(host.available_modes().is_empty());
    for required in [
        Vec::new(),
        vec![BoundaryProperty::DescendantContainment],
        BoundaryProperty::ALL.to_vec(),
    ] {
        assert_eq!(
            host.select_mode(&required),
            Err(ModeRefusal::NoEnforceableMode(
                ContainmentUnavailable::NotDelegated
            )),
            "a host with no domain named a mode for {required:?}"
        );
    }
}

/// A refusal must name the property that cannot be enforced and every mechanism
/// that would have provided it, not merely report failure.
#[test]
fn refusal_names_the_unsatisfiable_property_and_every_blocked_mechanism() {
    let host = HostCapabilities::from_findings(
        ContainmentFinding::Delegated,
        LandlockFinding::Unsupported,
        UserNamespaceFinding::Denied(UserNamespaceDenial::ApparmorRestricted),
        SeccompFinding::FilterAvailable,
    );
    let refusal = host
        .select_mode(&[
            BoundaryProperty::DescendantContainment,
            BoundaryProperty::FilesystemRestriction,
        ])
        .expect_err("a host with neither Landlock nor namespaces cannot restrict a filesystem");

    let ModeRefusal::Unenforceable(properties) = &refusal else {
        panic!("a host with a domain must refuse per property, not wholesale: {refusal:?}");
    };
    let named = properties
        .iter()
        .map(|entry| entry.property())
        .collect::<Vec<_>>();
    assert_eq!(named, [BoundaryProperty::FilesystemRestriction]);
    assert!(
        !named.contains(&BoundaryProperty::DescendantContainment),
        "a satisfiable requirement must not appear in the refusal"
    );

    let blocked = properties[0]
        .blocked_mechanisms()
        .iter()
        .map(|entry| (entry.mechanism(), entry.cause()))
        .collect::<Vec<_>>();
    assert!(blocked.contains(&(Mechanism::Landlock, UnsatisfiedCause::LandlockUnsupported)));
    assert!(blocked.contains(&(
        Mechanism::UserNamespace,
        UnsatisfiedCause::UserNamespaceDenied(UserNamespaceDenial::ApparmorRestricted)
    )));

    let rendered = refusal.to_string();
    assert!(
        rendered.contains(BoundaryProperty::FilesystemRestriction.as_str()),
        "the refusal must name the property in its message: {rendered}"
    );
    assert!(
        rendered.contains(Mechanism::Landlock.as_str()),
        "the refusal must name the blocked mechanism in its message: {rendered}"
    );
}

/// The measured ABI floor decides which Landlock properties are reachable, and
/// a shortfall must name the exact level it fell short of.
#[test]
fn landlock_below_abi_four_drops_tcp_denial_naming_the_needed_level() {
    let observed = abi(LANDLOCK_ABI_TCP - 1);
    let host = HostCapabilities::from_findings(
        ContainmentFinding::Delegated,
        LandlockFinding::Enforceable(observed),
        UserNamespaceFinding::Denied(UserNamespaceDenial::ApparmorRestricted),
        SeccompFinding::FilterAvailable,
    );

    let selection = host
        .select_mode(&[BoundaryProperty::FilesystemRestriction])
        .expect("ABI 3 still restricts a filesystem");
    let tcp = selection
        .dropped()
        .iter()
        .find(|entry| entry.property() == BoundaryProperty::TcpDenial)
        .expect("TCP denial is unreachable below ABI 4 and must be reported dropped");
    assert!(tcp.blocked_mechanisms().iter().any(|entry| entry.cause()
        == UnsatisfiedCause::LandlockAbiBelow {
            observed,
            needed: LANDLOCK_ABI_TCP,
        }));

    assert!(
        host.select_mode(&[BoundaryProperty::TcpDenial]).is_err(),
        "TCP denial must be refused, not silently downgraded to a filesystem restriction"
    );
}

// ---------------------------------------------------------------------------
// Selection: degradation
// ---------------------------------------------------------------------------

/// A weaker mode is only acceptable if the caller is told precisely what it
/// cost. This host can restrict a filesystem and deny TCP, and cannot separate
/// uids or deny UDP; both shortfalls must be in the returned value.
#[test]
fn a_degraded_mode_records_every_guarantee_it_dropped() {
    let host = HostCapabilities::from_findings(
        ContainmentFinding::Delegated,
        LandlockFinding::Enforceable(abi(LANDLOCK_ABI_TCP)),
        UserNamespaceFinding::Denied(UserNamespaceDenial::ApparmorRestricted),
        SeccompFinding::FilterAvailable,
    );
    let selection = host
        .select_mode(&[
            BoundaryProperty::DescendantContainment,
            BoundaryProperty::FilesystemRestriction,
            BoundaryProperty::TcpDenial,
        ])
        .expect("Landlock at ABI 4 covers every requested property");

    assert_eq!(selection.mode(), EnforcementMode::KernelRestricted);
    assert!(
        !selection.is_complete(),
        "a mode without namespaces cannot be complete"
    );

    let dropped = selection
        .dropped()
        .iter()
        .map(|entry| entry.property())
        .collect::<Vec<_>>();
    assert_eq!(
        dropped,
        [
            BoundaryProperty::CompleteNetworkDenial,
            BoundaryProperty::UidSeparation
        ],
        "Landlock denies TCP only and changes no uid; both gaps must be reported"
    );
    for entry in selection.dropped() {
        assert_eq!(
            entry
                .blocked_mechanisms()
                .iter()
                .map(|blocked| blocked.cause())
                .collect::<Vec<_>>(),
            [UnsatisfiedCause::UserNamespaceDenied(
                UserNamespaceDenial::ApparmorRestricted
            )]
        );
    }
    assert!(
        selection
            .to_string()
            .contains(BoundaryProperty::CompleteNetworkDenial.as_str()),
        "the rendered selection must name what it dropped"
    );
}

/// The strongest mode on a host that has everything must drop nothing, so a
/// non-empty degradation record always means a real host limitation.
#[test]
fn a_complete_host_selects_the_native_mode_and_drops_nothing() {
    let host = full_host();
    let selection = host
        .select_mode(&BoundaryProperty::ALL)
        .expect("a host with every mechanism enforces every property");
    assert_eq!(selection.mode(), EnforcementMode::NamespacedIsolation);
    assert_eq!(selection.enforced(), BoundaryProperty::ALL);
    assert!(selection.dropped().is_empty());
    assert!(selection.is_complete());
}

/// Seccomp is the only mechanism for a syscall allowlist, so removing it must
/// cost exactly that property and nothing else.
#[test]
fn losing_seccomp_costs_exactly_the_syscall_restriction() {
    let host = HostCapabilities::from_findings(
        ContainmentFinding::Delegated,
        LandlockFinding::Enforceable(abi(LANDLOCK_ABI_HIGHEST_KNOWN)),
        UserNamespaceFinding::NoObservedDenial,
        SeccompFinding::Unavailable(SeccompUnavailable::StrictModeOnly),
    );
    let selection = host.select_mode(&[]).expect("every other mechanism works");
    assert_eq!(selection.mode(), EnforcementMode::NamespacedIsolation);
    assert_eq!(
        selection
            .dropped()
            .iter()
            .map(|entry| entry.property())
            .collect::<Vec<_>>(),
        [BoundaryProperty::SyscallRestriction]
    );
    assert_eq!(
        selection.dropped()[0].blocked_mechanisms()[0].cause(),
        UnsatisfiedCause::SeccompFilterUnavailable(SeccompUnavailable::StrictModeOnly)
    );
    assert!(
        host.select_mode(&[BoundaryProperty::SyscallRestriction])
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// Selection: exhaustive invariants over the synthetic matrix
// ---------------------------------------------------------------------------

/// The central safety property: a returned mode is installable and enforces
/// every requirement, and its enforced set is exactly what its mechanisms give
/// on that host. A selector that reached for a stronger mode than the host
/// supports, or that returned a mode covering only some requirements, fails
/// here on the first host that cannot back the claim.
#[test]
fn a_selected_mode_is_installable_and_enforces_every_requirement() {
    for host in synthetic_hosts() {
        for required in requirement_subsets() {
            let Ok(selection) = host.select_mode(&required) else {
                continue;
            };
            assert!(
                selection.mode().is_available_on(&host),
                "selected {} on a host that cannot install it: {host:?}",
                selection.mode()
            );
            assert_eq!(
                selection.enforced(),
                selection.mode().provides_on(&host),
                "the enforced set does not match what {} actually provides",
                selection.mode()
            );
            for property in &required {
                assert!(
                    selection.enforced().contains(property),
                    "selected {} for {required:?} without enforcing {property}",
                    selection.mode()
                );
                assert!(
                    selection
                        .dropped()
                        .iter()
                        .all(|entry| entry.property() != *property),
                    "{property} was both required and reported dropped"
                );
            }
        }
    }
}

/// Selection is not allowed to prefer a weaker mode: on any host the strongest
/// installable mode is the one returned, so nothing enforceable is left unused.
#[test]
fn selection_returns_the_strongest_installable_mode() {
    for host in synthetic_hosts() {
        let Some(strongest) = host.available_modes().first().copied() else {
            continue;
        };
        for required in requirement_subsets() {
            if let Ok(selection) = host.select_mode(&required) {
                assert_eq!(
                    selection.mode(),
                    strongest,
                    "a weaker mode than {strongest} was selected for {required:?}"
                );
            }
        }
    }
}

/// A refusal must be justified: every property it names is genuinely out of
/// reach of every installable mode, it names only properties the caller asked
/// for, and it never comes back empty.
#[test]
fn a_refusal_names_only_properties_no_installable_mode_can_enforce() {
    for host in synthetic_hosts() {
        let available = host.available_modes();
        let reachable = available
            .iter()
            .flat_map(|mode| mode.provides_on(&host))
            .collect::<Vec<_>>();
        for required in requirement_subsets() {
            let Err(refusal) = host.select_mode(&required) else {
                continue;
            };
            match &refusal {
                ModeRefusal::NoEnforceableMode(reason) => {
                    assert!(available.is_empty());
                    assert_eq!(host.containment().denial(), Some(*reason));
                }
                ModeRefusal::Unenforceable(properties) => {
                    assert!(
                        !properties.is_empty(),
                        "a refusal that names nothing explains nothing"
                    );
                    for entry in properties {
                        assert!(
                            required.contains(&entry.property()),
                            "{} was refused but never required",
                            entry.property()
                        );
                        assert!(
                            !reachable.contains(&entry.property()),
                            "{} was refused although an installable mode enforces it",
                            entry.property()
                        );
                    }
                }
            }
        }
    }
}

/// Every gap reported anywhere must be explained by at least one blocked
/// mechanism, and every blocked mechanism must be one a mode would really have
/// used for that property.
#[test]
fn every_reported_gap_names_a_mechanism_that_would_have_provided_it() {
    for host in synthetic_hosts() {
        let mut gaps = Vec::new();
        if let Ok(selection) = host.select_mode(&[]) {
            gaps.extend(selection.dropped().iter().cloned());
        }
        if let Err(refusal) = host.select_mode(&BoundaryProperty::ALL) {
            gaps.extend(refusal.unenforceable().iter().cloned());
        }
        for gap in gaps {
            assert!(
                !gap.blocked_mechanisms().is_empty(),
                "{} was reported unenforceable without naming a cause",
                gap.property()
            );
            for blocked in gap.blocked_mechanisms() {
                assert!(
                    EnforcementMode::LADDER
                        .into_iter()
                        .any(|mode| mode.mechanism_for(gap.property()) == Some(blocked.mechanism())),
                    "{} blamed {}, which no mode uses for it",
                    gap.property(),
                    blocked.mechanism()
                );
            }
        }
    }
}

/// The ladder must really be a ladder. If it ever stopped being one, a caller
/// could be handed the strongest installable mode while a weaker one enforced
/// something the strongest did not.
#[test]
fn the_mode_ladder_is_monotone_among_installable_modes() {
    for host in synthetic_hosts() {
        let available = host.available_modes();
        for (rank, stronger) in available.iter().enumerate() {
            let provided = stronger.provides_on(&host);
            for weaker in &available[rank + 1..] {
                for property in weaker.provides_on(&host) {
                    assert!(
                        provided.contains(&property),
                        "{weaker} enforces {property} but the stronger {stronger} does not"
                    );
                }
            }
        }
    }
}

/// A mode that cannot be installed enforces nothing. Reporting otherwise would
/// let an uninstallable mode look like an enforced boundary.
#[test]
fn an_uninstallable_mode_enforces_nothing() {
    for host in synthetic_hosts() {
        for mode in EnforcementMode::LADDER {
            if !mode.is_available_on(&host) {
                assert!(
                    mode.provides_on(&host).is_empty(),
                    "{mode} claimed enforcement on a host that cannot install it"
                );
            }
        }
    }
}

/// Landlock can never provide complete network denial or a separate uid, on any
/// host and at any ABI. Wiring either to Landlock would make a Landlock-only
/// host appear to isolate a network it can still reach over UDP.
#[test]
fn landlock_is_never_credited_with_namespace_only_properties() {
    for property in [
        BoundaryProperty::CompleteNetworkDenial,
        BoundaryProperty::UidSeparation,
    ] {
        for mode in EnforcementMode::LADDER {
            assert_ne!(
                mode.mechanism_for(property),
                Some(Mechanism::Landlock),
                "{mode} would use Landlock for {property}"
            );
        }
    }

    let landlock_only = HostCapabilities::from_findings(
        ContainmentFinding::Delegated,
        LandlockFinding::Enforceable(abi(LANDLOCK_ABI_HIGHEST_KNOWN)),
        UserNamespaceFinding::Denied(UserNamespaceDenial::ApparmorRestricted),
        SeccompFinding::FilterAvailable,
    );
    for property in [
        BoundaryProperty::CompleteNetworkDenial,
        BoundaryProperty::UidSeparation,
    ] {
        assert!(
            landlock_only.select_mode(&[property]).is_err(),
            "a Landlock-only host claimed {property}"
        );
    }
}

/// Reported ABI levels are floors, so the accessors derived from them must line
/// up with the published thresholds at every level.
#[test]
fn landlock_abi_accessors_track_the_published_thresholds() {
    assert_eq!(LandlockAbi::from_level(0), None);
    assert_eq!(
        LandlockAbi::from_level(LANDLOCK_ABI_HIGHEST_KNOWN + 1),
        None
    );
    for level in LANDLOCK_ABI_FILESYSTEM..=LANDLOCK_ABI_HIGHEST_KNOWN {
        let measured = abi(level);
        assert_eq!(measured.level(), level);
        assert!(measured.restricts_filesystem());
        assert_eq!(measured.denies_tcp(), level >= LANDLOCK_ABI_TCP);
    }
}
