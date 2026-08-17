// SPDX-License-Identifier: Elastic-2.0

//! R1-04 verification contract.
//!
//! Each module corresponds to one row of the check table in
//! `docs/product-plan/requirements/operations-and-governance.md`.

use automonique_policy::peer::{
    Admission, EntryMetadata, MODE_IMMUTABLE_SPEC, MODE_PRIVATE_DIRECTORY, MODE_PRIVATE_FILE,
    PeerCredential, PeerPolicy, PeerPolicyError, PeerRefusal, check_entry, check_relative_path,
};

const OWNER: u32 = 1000;

fn policy() -> PeerPolicy {
    PeerPolicy::new(&[OWNER]).expect("non-empty admitted set")
}

fn peer(uid: u32) -> PeerCredential {
    PeerCredential::new(uid, OWNER, 4242)
}

mod credential_construction {
    use super::*;

    #[test]
    fn credentials_require_explicit_components() {
        let credential = PeerCredential::new(1000, 1000, 77);
        assert_eq!(credential.uid(), 1000);
        assert_eq!(credential.gid(), 1000);
        assert_eq!(credential.pid(), 77);
    }

    /// `PeerCredential` deliberately has no `Default`; the doc test on the type
    /// proves the absence at compile time. This pins the positive half: the
    /// only constructor takes all three components.
    #[test]
    fn credentials_carry_exactly_what_the_kernel_supplies() {
        let credential = PeerCredential::new(0, 0, 1);
        assert_eq!(
            (credential.uid(), credential.gid(), credential.pid()),
            (0, 0, 1)
        );
    }
}

mod decision_totality {
    use super::*;

    #[test]
    fn an_admitted_peer_yields_an_admission_naming_the_user() {
        let admission: Admission = policy().evaluate(Some(peer(OWNER))).expect("admitted");
        assert_eq!(admission.uid(), OWNER);
    }

    #[test]
    fn unavailable_credentials_refuse_rather_than_default_admit() {
        assert_eq!(
            policy()
                .evaluate(None)
                .expect_err("no credentials, no entry"),
            PeerRefusal::CredentialsUnavailable
        );
    }

    #[test]
    fn unavailable_is_distinct_from_not_admitted() {
        let unavailable = policy().evaluate(None).expect_err("unavailable");
        let refused = policy()
            .evaluate(Some(peer(1234)))
            .expect_err("not admitted");
        assert_ne!(unavailable, refused);
        assert_ne!(unavailable.category(), refused.category());
    }

    #[test]
    fn every_refusal_names_exactly_one_reason() {
        // The decision returns a single `PeerRefusal`, not a collection, so a
        // caller cannot receive an ambiguous verdict. Exercise each reachable
        // reason through `evaluate`.
        let gated = policy().requiring_gids(&[42]);
        let cases = [
            (None, PeerRefusal::CredentialsUnavailable),
            (
                Some(PeerCredential::new(1234, 42, 1)),
                PeerRefusal::UidNotAdmitted { uid: 1234 },
            ),
            (
                Some(PeerCredential::new(0, 42, 1)),
                PeerRefusal::RootNotAdmitted,
            ),
            (
                Some(PeerCredential::new(OWNER, 7, 1)),
                PeerRefusal::GidNotAdmitted { gid: 7 },
            ),
        ];
        for (credential, expected) in cases {
            assert_eq!(gated.evaluate(credential).expect_err("refused"), expected);
        }
    }
}

mod uid_and_gid_policy {
    use super::*;

    #[test]
    fn an_empty_admitted_set_is_refused_at_construction() {
        assert_eq!(
            PeerPolicy::new(&[]).expect_err("a policy admitting nobody is a mistake"),
            PeerPolicyError::NoAdmittedUsers
        );
    }

    #[test]
    fn root_is_not_implicitly_trusted() {
        assert!(!policy().admits_root());
        assert_eq!(
            policy()
                .evaluate(Some(peer(0)))
                .expect_err("root is refused"),
            PeerRefusal::RootNotAdmitted
        );
    }

    #[test]
    fn root_is_admitted_only_when_listed_explicitly() {
        let permissive = PeerPolicy::new(&[0]).expect("explicit root");
        assert!(permissive.admits_root());
        assert_eq!(
            permissive
                .evaluate(Some(PeerCredential::new(0, 0, 1)))
                .expect("explicitly admitted root")
                .uid(),
            0
        );
        // Admitting root does not admit anyone else.
        assert_eq!(
            permissive
                .evaluate(Some(peer(OWNER)))
                .expect_err("other users are still refused"),
            PeerRefusal::UidNotAdmitted { uid: OWNER }
        );
    }

    #[test]
    fn a_group_requirement_is_enforced_only_when_declared() {
        let ungated = policy();
        ungated
            .evaluate(Some(PeerCredential::new(OWNER, 999, 1)))
            .expect("no group requirement was declared");

        let gated = policy().requiring_gids(&[42, 43]);
        gated
            .evaluate(Some(PeerCredential::new(OWNER, 43, 1)))
            .expect("group is admitted");
        assert_eq!(
            gated
                .evaluate(Some(PeerCredential::new(OWNER, 44, 1)))
                .expect_err("group is not admitted"),
            PeerRefusal::GidNotAdmitted { gid: 44 }
        );
    }

    #[test]
    fn duplicate_entries_do_not_change_the_admitted_set() {
        let deduped = PeerPolicy::new(&[OWNER, OWNER, OWNER]).expect("valid");
        assert_eq!(deduped, policy());
    }
}

mod pid_is_not_authority {
    use super::*;

    #[test]
    fn the_decision_is_independent_of_pid() {
        // Every PID must produce the same verdict for the same uid/gid, so no
        // admission path can depend on a value the kernel may reuse.
        for pid in [i32::MIN, -1, 0, 1, 4242, i32::MAX] {
            assert_eq!(
                policy()
                    .evaluate(Some(PeerCredential::new(OWNER, OWNER, pid)))
                    .expect("admitted regardless of pid")
                    .uid(),
                OWNER
            );
            assert_eq!(
                policy()
                    .evaluate(Some(PeerCredential::new(1234, OWNER, pid)))
                    .expect_err("refused regardless of pid"),
                PeerRefusal::UidNotAdmitted { uid: 1234 }
            );
        }
    }

    #[test]
    fn an_admission_carries_no_pid() {
        // `Admission` exposes only the admitted user, so a later stage cannot
        // read a PID back out of the decision and treat it as authority.
        let admission = policy().evaluate(Some(peer(OWNER))).expect("admitted");
        assert_eq!(admission.uid(), OWNER);
    }
}

mod mode_and_ownership {
    use super::*;

    fn clean(mode: u32) -> EntryMetadata {
        EntryMetadata::new(mode, OWNER, false, false)
    }

    #[test]
    fn the_exact_required_mode_passes() {
        for mode in [
            MODE_PRIVATE_DIRECTORY,
            MODE_PRIVATE_FILE,
            MODE_IMMUTABLE_SPEC,
        ] {
            check_entry(clean(mode), mode, OWNER).expect("exact mode is accepted");
        }
    }

    #[test]
    fn a_more_permissive_mode_is_refused() {
        for (required, observed) in [
            (MODE_PRIVATE_DIRECTORY, 0o755),
            (MODE_PRIVATE_FILE, 0o644),
            (MODE_PRIVATE_FILE, 0o666),
            (MODE_IMMUTABLE_SPEC, 0o600),
        ] {
            assert_eq!(
                check_entry(clean(observed), required, OWNER).expect_err("more permissive"),
                PeerRefusal::ModeMorePermissive { required, observed },
                "{observed:04o} against {required:04o}"
            );
        }
    }

    #[test]
    fn a_stricter_or_otherwise_differing_mode_is_also_refused() {
        // Drift is visible in both directions: an entry stricter than declared
        // is still not the entry the layout describes.
        assert_eq!(
            check_entry(clean(0o400), MODE_PRIVATE_FILE, OWNER).expect_err("stricter"),
            PeerRefusal::ModeMismatch {
                required: MODE_PRIVATE_FILE,
                observed: 0o400,
            }
        );
        assert_eq!(
            check_entry(clean(0o000), MODE_PRIVATE_DIRECTORY, OWNER).expect_err("stricter"),
            PeerRefusal::ModeMismatch {
                required: MODE_PRIVATE_DIRECTORY,
                observed: 0o000,
            }
        );
    }

    #[test]
    fn an_unexpected_owner_is_refused() {
        assert_eq!(
            check_entry(
                EntryMetadata::new(MODE_PRIVATE_FILE, 0, false, false),
                MODE_PRIVATE_FILE,
                OWNER
            )
            .expect_err("wrong owner"),
            PeerRefusal::UnexpectedOwner {
                expected: OWNER,
                observed: 0,
            }
        );
    }
}

mod path_safety {
    use super::*;

    #[test]
    fn a_symlinked_component_is_refused() {
        assert_eq!(
            check_entry(
                EntryMetadata::new(MODE_PRIVATE_FILE, OWNER, true, false),
                MODE_PRIVATE_FILE,
                OWNER
            )
            .expect_err("symlink"),
            PeerRefusal::SymlinkComponent
        );
    }

    #[test]
    fn a_writable_parent_is_refused() {
        assert_eq!(
            check_entry(
                EntryMetadata::new(MODE_PRIVATE_FILE, OWNER, false, true),
                MODE_PRIVATE_FILE,
                OWNER
            )
            .expect_err("writable parent"),
            PeerRefusal::WritableParent
        );
    }

    #[test]
    fn each_path_rule_has_its_own_category() {
        let cases = [
            ("hosts/h-1\0/control.sock", PeerRefusal::EmbeddedNul),
            ("/run/automonique/control.sock", PeerRefusal::AbsolutePath),
            ("", PeerRefusal::NonCanonicalPath),
            ("hosts//control.sock", PeerRefusal::NonCanonicalPath),
            ("hosts/./control.sock", PeerRefusal::NonCanonicalPath),
            ("../../etc/passwd", PeerRefusal::PathEscape),
            ("hosts/../../etc/passwd", PeerRefusal::PathEscape),
        ];
        for (path, expected) in cases {
            assert_eq!(
                check_relative_path(path).expect_err("refused"),
                expected,
                "path {path:?}"
            );
        }
    }

    #[test]
    fn a_canonical_runtime_relative_path_is_accepted() {
        for path in [
            "hosts/h-1/control.sock",
            "hosts/h-1/attempts/a-1/spec.json",
            "status.json",
            "hosts/h-1/nested/../sibling",
        ] {
            check_relative_path(path).expect("canonical relative path");
        }
    }
}

mod refusal_hygiene {
    use super::*;

    /// One value of every `PeerRefusal` variant. A new variant must be added
    /// here, which the exhaustive match below enforces at compile time.
    fn every_refusal() -> Vec<PeerRefusal> {
        vec![
            PeerRefusal::CredentialsUnavailable,
            PeerRefusal::UidNotAdmitted { uid: 1234 },
            PeerRefusal::RootNotAdmitted,
            PeerRefusal::GidNotAdmitted { gid: 44 },
            PeerRefusal::ModeMorePermissive {
                required: 0o600,
                observed: 0o666,
            },
            PeerRefusal::ModeMismatch {
                required: 0o600,
                observed: 0o400,
            },
            PeerRefusal::UnexpectedOwner {
                expected: 1000,
                observed: 0,
            },
            PeerRefusal::SymlinkComponent,
            PeerRefusal::WritableParent,
            PeerRefusal::EmbeddedNul,
            PeerRefusal::AbsolutePath,
            PeerRefusal::PathEscape,
            PeerRefusal::NonCanonicalPath,
        ]
    }

    #[test]
    fn every_category_is_distinct_and_the_set_is_exhaustive() {
        let refusals = every_refusal();
        for refusal in &refusals {
            match refusal {
                PeerRefusal::CredentialsUnavailable
                | PeerRefusal::UidNotAdmitted { .. }
                | PeerRefusal::RootNotAdmitted
                | PeerRefusal::GidNotAdmitted { .. }
                | PeerRefusal::ModeMorePermissive { .. }
                | PeerRefusal::ModeMismatch { .. }
                | PeerRefusal::UnexpectedOwner { .. }
                | PeerRefusal::SymlinkComponent
                | PeerRefusal::WritableParent
                | PeerRefusal::EmbeddedNul
                | PeerRefusal::AbsolutePath
                | PeerRefusal::PathEscape
                | PeerRefusal::NonCanonicalPath => {}
            }
        }
        let mut categories: Vec<&str> = refusals.iter().map(|r| r.category()).collect();
        let total = categories.len();
        categories.sort_unstable();
        categories.dedup();
        assert_eq!(categories.len(), total, "two refusals share a category");
    }

    #[test]
    fn no_refusal_mentions_a_socket_path_or_command_line() {
        let socket = "/run/user/1000/automonique/hosts/h-1/control.sock";
        let command = "/usr/bin/curl --header authorization:secret";

        // Refusals produced from inputs containing both must not echo them.
        let from_path = check_relative_path(&format!("{socket}\0")).expect_err("embedded NUL");
        assert!(!from_path.to_string().contains(socket));
        let absolute = check_relative_path(socket).expect_err("absolute");
        assert!(!absolute.to_string().contains(socket));

        for refusal in every_refusal() {
            let rendered = refusal.to_string();
            assert!(!rendered.is_empty());
            assert!(
                !rendered.contains(socket),
                "{rendered} leaked the socket path"
            );
            assert!(
                !rendered.contains(command),
                "{rendered} leaked a command line"
            );
            assert!(!rendered.contains("secret"));
        }
    }
}
