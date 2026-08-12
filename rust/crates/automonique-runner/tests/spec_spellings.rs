// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::models::{ArtifactTransfer, WorkspaceTransfer};
use automonique_runner::{
    BackendPromptSession, PortabilityPolicy, PromptDeliveryPlan, ProtectedPromptReference,
    RemoteAttestationPolicy, RunOriginSource, RunnerEventDialect,
};

#[test]
fn fieldless_runner_enum_spellings_are_exhaustive_and_exact() {
    assert_eq!(RunOriginSource::ALL.len(), 12);
    for source in RunOriginSource::ALL {
        assert_eq!(
            RunOriginSource::from_spelling(source.as_str()),
            Some(source)
        );
        assert_eq!(
            RunOriginSource::from_spelling(&source.as_str().to_ascii_uppercase()),
            None
        );
    }
    assert_eq!(RunOriginSource::from_spelling("unknown"), None);

    assert_eq!(RemoteAttestationPolicy::ALL.len(), 3);
    for policy in RemoteAttestationPolicy::ALL {
        assert_eq!(
            RemoteAttestationPolicy::from_spelling(policy.as_str()),
            Some(policy)
        );
        assert_eq!(
            RemoteAttestationPolicy::from_spelling(&policy.as_str().to_ascii_uppercase()),
            None
        );
    }
    assert_eq!(RemoteAttestationPolicy::from_spelling("unknown"), None);

    assert_eq!(RunnerEventDialect::ALL.len(), 1);
    for dialect in RunnerEventDialect::ALL {
        assert_eq!(
            RunnerEventDialect::from_spelling(dialect.as_str()),
            Some(dialect)
        );
        assert_eq!(
            RunnerEventDialect::from_spelling(&dialect.as_str().to_ascii_uppercase()),
            None
        );
    }
    assert_eq!(RunnerEventDialect::from_spelling("unknown"), None);
}

#[test]
fn prompt_spelling_reconstruction_requires_the_exact_payload_shape() {
    let protected = || ProtectedPromptReference::new("prompt-slot-1").expect("valid reference");
    let backend = || BackendPromptSession::new("session-1").expect("valid session");

    let stdin = PromptDeliveryPlan::from_spelling("stdin", None, None).expect("stdin");
    assert_eq!(stdin.as_str(), "stdin");

    let protected_plan =
        PromptDeliveryPlan::from_spelling("protected_reference", Some(protected()), None)
            .expect("protected reference");
    assert_eq!(protected_plan.as_str(), "protected_reference");
    match protected_plan {
        PromptDeliveryPlan::ProtectedReference(reference) => {
            assert_eq!(reference.as_str(), "prompt-slot-1");
        }
        _ => panic!("protected-reference spelling reconstructed the wrong variant"),
    }

    let backend_plan = PromptDeliveryPlan::from_spelling("backend_session", None, Some(backend()))
        .expect("backend session");
    assert_eq!(backend_plan.as_str(), "backend_session");
    match backend_plan {
        PromptDeliveryPlan::BackendSession(session) => {
            assert_eq!(session.as_str(), "session-1");
        }
        _ => panic!("backend-session spelling reconstructed the wrong variant"),
    }

    assert_eq!(
        PromptDeliveryPlan::from_spelling("unknown", None, None),
        None
    );
    assert_eq!(PromptDeliveryPlan::from_spelling("STDIN", None, None), None);
    assert_eq!(
        PromptDeliveryPlan::from_spelling("PROTECTED_REFERENCE", Some(protected()), None),
        None
    );
    assert_eq!(
        PromptDeliveryPlan::from_spelling("BACKEND_SESSION", None, Some(backend())),
        None
    );
    assert_eq!(
        PromptDeliveryPlan::from_spelling("unknown", Some(protected()), Some(backend())),
        None
    );
    assert_eq!(
        PromptDeliveryPlan::from_spelling("stdin", Some(protected()), None),
        None
    );
    assert_eq!(
        PromptDeliveryPlan::from_spelling("stdin", None, Some(backend())),
        None
    );
    assert_eq!(
        PromptDeliveryPlan::from_spelling("protected_reference", None, None),
        None
    );
    assert_eq!(
        PromptDeliveryPlan::from_spelling(
            "protected_reference",
            Some(protected()),
            Some(backend())
        ),
        None
    );
    assert_eq!(
        PromptDeliveryPlan::from_spelling("protected_reference", None, Some(backend())),
        None
    );
    assert_eq!(
        PromptDeliveryPlan::from_spelling("backend_session", None, None),
        None
    );
    assert_eq!(
        PromptDeliveryPlan::from_spelling("backend_session", Some(protected()), Some(backend())),
        None
    );
    assert_eq!(
        PromptDeliveryPlan::from_spelling("backend_session", Some(protected()), None),
        None
    );
}

#[test]
fn portability_spelling_reconstruction_requires_the_exact_payload_shape() {
    let workspace = WorkspaceTransfer::ContentAddressedBundle;
    let artifact = ArtifactTransfer::DigestVerifiedPull;

    let pinned = PortabilityPolicy::from_spelling("pinned", None, None).expect("pinned");
    assert_eq!(pinned.as_str(), "pinned");
    assert_eq!(pinned.workspace_transfer(), None);
    assert_eq!(pinned.artifact_transfer(), None);

    for workspace_mode in WorkspaceTransfer::ALL {
        for artifact_mode in ArtifactTransfer::ALL {
            let portable = PortabilityPolicy::from_spelling(
                "portable",
                Some(workspace_mode),
                Some(artifact_mode),
            )
            .expect("portable");
            assert_eq!(portable.as_str(), "portable");
            assert_eq!(portable.workspace_transfer(), Some(workspace_mode));
            assert_eq!(portable.artifact_transfer(), Some(artifact_mode));
        }
    }

    assert_eq!(
        PortabilityPolicy::from_spelling("unknown", None, None),
        None
    );
    assert_eq!(PortabilityPolicy::from_spelling("PINNED", None, None), None);
    assert_eq!(
        PortabilityPolicy::from_spelling("PORTABLE", Some(workspace), Some(artifact)),
        None
    );
    assert_eq!(
        PortabilityPolicy::from_spelling("unknown", Some(workspace), Some(artifact)),
        None
    );
    assert_eq!(
        PortabilityPolicy::from_spelling("pinned", Some(workspace), None),
        None
    );
    assert_eq!(
        PortabilityPolicy::from_spelling("pinned", None, Some(artifact)),
        None
    );
    assert_eq!(
        PortabilityPolicy::from_spelling("pinned", Some(workspace), Some(artifact)),
        None
    );
    assert_eq!(
        PortabilityPolicy::from_spelling("portable", None, None),
        None
    );
    assert_eq!(
        PortabilityPolicy::from_spelling("portable", Some(workspace), None),
        None
    );
    assert_eq!(
        PortabilityPolicy::from_spelling("portable", None, Some(artifact)),
        None
    );
}
