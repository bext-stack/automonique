// SPDX-License-Identifier: Elastic-2.0

//! Where this daemon's brokered destinations come from, and how they become a
//! broker's allowlist.
//!
//! # Why a file, and why this daemon owns the answer at all
//!
//! `NetworkAccess::BrokeredNamed` is the sandbox spec's word for "named
//! destinations through the egress broker", and the spec carries **no names**:
//! there is no destination list anywhere in the protocol's sandbox module, only
//! the two access enums and an `EgressPolicyDigest` recorded in an attestation,
//! which is a digest of a policy no protocol type holds. A document can
//! therefore say that its egress is brokered and cannot say where to.
//!
//! Somebody has to answer, and the only party that can is the deployment
//! running the broker. So this daemon reads its answer from one file in its own
//! private state directory, which is owner-controlled, readable by a reviewer,
//! and separate from every document. What that buys, and what it does not, is
//! stated in [`automonique_runner::admission::AdmissionContext`]: this file
//! cannot widen a document, because a document that denies egress is admitted
//! with no broker whatever this file holds — but neither can a reviewer of the
//! document see which destinations a run was permitted, because they are not in
//! it. Closing that needs a destination list on the wire.
//!
//! # Fail closed, twice
//!
//! - A file this module cannot read **exactly** yields an error, never a
//!   partial list. There is no line this parser skips and no spelling it
//!   repairs.
//! - No file, an error, or an empty list all lead to the same place: every
//!   document asking for brokered egress is refused, because admission refuses a
//!   brokered spec whose destinations were not resolved.
//!
//! # The format
//!
//! One destination per line, three fields separated by whitespace:
//!
//! ```text
//! # host                port  scope
//! chatgpt.com           443   public
//! 127.0.0.1             8443  loopback
//! ```
//!
//! Blank lines and `#` comments are ignored. Every other line must parse
//! completely. The host, the port and the scope are all handed to the broker's
//! own [`Destination`] constructor, which is the authority on what a
//! destination is — this module contributes bounds and a field split, never a
//! second grammar.

use std::fs;
use std::path::Path;

use automonique_egress_broker::{
    AddressScope, Destination, DestinationAllowlist, DestinationError,
};
use automonique_runner::admission::{BrokeredDestination, BrokeredScope};

/// Largest destination policy file this daemon will read.
///
/// Sixteen destinations cannot need more than this, so a larger file is not a
/// policy that grew — it is a file that is not this policy.
pub const MAX_POLICY_BYTES: u64 = 8 * 1024;

/// Why a destination policy was refused.
///
/// Every variant is a refusal of the whole file. None of them means "the rest
/// of the policy was loaded".
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressPolicyError {
    /// The file exists but could not be read as a bounded regular file.
    Unreadable,
    /// The file is not UTF-8.
    NotText,
    /// A line did not carry exactly a host, a port and a scope.
    LineMalformed,
    /// A scope was not `public` or `loopback`.
    ScopeUnknown,
    /// The broker refused the destination. This carries the broker's own error,
    /// including a duplicate and an over-long list, because the broker's
    /// allowlist is the authority on both.
    DestinationRejected(DestinationError),
}

impl core::fmt::Display for EgressPolicyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unreadable => formatter.write_str("the destination policy could not be read"),
            Self::NotText => formatter.write_str("the destination policy is not UTF-8"),
            Self::LineMalformed => formatter.write_str("a policy line is not `host port scope`"),
            Self::ScopeUnknown => formatter.write_str("a policy scope is not public or loopback"),
            Self::DestinationRejected(error) => {
                write!(formatter, "the broker refused a destination: {error}")
            }
        }
    }
}

impl std::error::Error for EgressPolicyError {}

/// Read the destination policy at `path`, or answer that there is none.
///
/// An absent file is an empty policy, which is a real and useful answer: this
/// daemon permits no brokered egress at all until an operator writes one.
///
/// # Errors
///
/// Returns [`EgressPolicyError`] for a file that exists and cannot be read
/// exactly as this module's format. The caller gets no destinations either way;
/// the distinction exists so a misconfiguration can be reported rather than
/// looking like a deliberate empty policy.
pub fn load_destinations(path: &Path) -> Result<Vec<BrokeredDestination>, EgressPolicyError> {
    let Some(text) = read_bounded_text(path)? else {
        return Ok(Vec::new());
    };
    let mut destinations = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let (Some(host), Some(port), Some(scope), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err(EgressPolicyError::LineMalformed);
        };
        let scope = match scope {
            "public" => BrokeredScope::Public,
            "loopback" => BrokeredScope::Loopback,
            _ => return Err(EgressPolicyError::ScopeUnknown),
        };
        // The broker's own parser decides what this host and port are, before
        // anything is written down: a spelling it refuses never becomes a
        // destination admission could carry, and the refusal a reader sees is
        // the broker's own rather than a second opinion from this module.
        let port = automonique_egress_broker::allowlist::parse_port(port)
            .map_err(EgressPolicyError::DestinationRejected)?;
        Destination::new(host, port, address_scope(scope))
            .map_err(EgressPolicyError::DestinationRejected)?;
        // Unreachable: every host the broker accepts is inside admission's
        // bounds, which are strictly wider. Refused rather than assumed.
        destinations.push(
            BrokeredDestination::new(host, port, scope)
                .map_err(|_| EgressPolicyError::LineMalformed)?,
        );
    }
    // Built once here and thrown away, so a policy this daemon holds is always
    // a policy a broker can be started with: the host grammar, the duplicate
    // rule and the entry ceiling are all the broker's, checked at load time
    // rather than discovered when a run is already being prepared.
    allowlist_for(&destinations)?;
    Ok(destinations)
}

/// Rebuild a broker allowlist from the destinations one launch was admitted for.
///
/// The admitted requirement is the input rather than this daemon's own copy of
/// the policy, so the broker a run gets permits exactly what that run was
/// admitted against — a policy file rewritten between admission and start
/// cannot widen a launch that is already on its way.
///
/// # Errors
///
/// Returns [`EgressPolicyError`] when the broker refuses a destination that was
/// admitted. Both parses are the broker's own, so this is unreachable in
/// practice and is a refusal rather than an assumption.
pub fn allowlist_for(
    destinations: &[BrokeredDestination],
) -> Result<DestinationAllowlist, EgressPolicyError> {
    let mut allowlist = DestinationAllowlist::deny_all();
    for destination in destinations {
        allowlist = allowlist
            .allowing(
                destination.host(),
                destination.port(),
                address_scope(destination.scope()),
            )
            .map_err(EgressPolicyError::DestinationRejected)?;
    }
    Ok(allowlist)
}

/// Translate admission's scope into the broker's, variant by variant.
///
/// Exhaustive on purpose: a scope either crate grows is a compile failure here
/// rather than a destination silently checked against the wrong policy.
const fn address_scope(scope: BrokeredScope) -> AddressScope {
    match scope {
        BrokeredScope::Public => AddressScope::Public,
        BrokeredScope::Loopback => AddressScope::Loopback,
    }
}

/// Read a bounded regular file as text, or `None` when there is no such file.
fn read_bounded_text(path: &Path) -> Result<Option<String>, EgressPolicyError> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(EgressPolicyError::Unreadable),
    };
    let metadata = file.metadata().map_err(|_| EgressPolicyError::Unreadable)?;
    if !metadata.is_file() || metadata.len() > MAX_POLICY_BYTES {
        return Err(EgressPolicyError::Unreadable);
    }
    let bytes = fs::read(path).map_err(|_| EgressPolicyError::Unreadable)?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err(EgressPolicyError::Unreadable);
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| EgressPolicyError::NotText)
}

#[cfg(test)]
mod tests {
    use super::{EgressPolicyError, allowlist_for, load_destinations};
    use automonique_egress_broker::{AddressScope, DestinationHost};
    use automonique_runner::admission::BrokeredScope;
    use std::io::Write as _;

    /// Write `body` into a private temporary directory and return its path.
    fn policy(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("egress-destinations");
        let mut file = std::fs::File::create(&path).expect("policy file");
        file.write_all(body.as_bytes()).expect("policy body");
        (directory, path)
    }

    #[test]
    fn an_absent_policy_is_an_empty_policy_rather_than_a_failure() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let destinations = load_destinations(&directory.path().join("nothing-here"))
            .expect("an absent policy is not an error");
        assert!(
            destinations.is_empty(),
            "no file must permit no destination"
        );
    }

    #[test]
    fn a_policy_is_read_exactly_and_becomes_the_broker_allowlist() {
        let (_directory, path) =
            policy("# a comment\n\nchatgpt.com 443 public\n  127.0.0.1   8443   loopback  \n");
        let destinations = load_destinations(&path).expect("the policy loads");
        assert_eq!(destinations.len(), 2);
        assert_eq!(destinations[0].host(), "chatgpt.com");
        assert_eq!(destinations[0].port(), 443);
        assert_eq!(destinations[0].scope(), BrokeredScope::Public);
        assert_eq!(destinations[1].scope(), BrokeredScope::Loopback);

        // The allowlist a broker would be started with permits exactly those
        // two destinations, matched through the broker's own parser.
        let allowlist = allowlist_for(&destinations).expect("the allowlist builds");
        assert_eq!(allowlist.entries().len(), 2);
        let named = DestinationHost::Name("chatgpt.com".to_owned());
        let permitted = allowlist
            .permits(&named, 443)
            .expect("the entry is present");
        assert_eq!(permitted.scope(), AddressScope::Public);
        assert!(
            allowlist.permits(&named, 80).is_none(),
            "a neighbouring port must not be permitted"
        );
    }

    #[test]
    fn a_policy_this_module_cannot_read_exactly_is_refused_whole() {
        let cases: [(&str, EgressPolicyError); 5] = [
            ("chatgpt.com 443\n", EgressPolicyError::LineMalformed),
            (
                "chatgpt.com 443 public extra\n",
                EgressPolicyError::LineMalformed,
            ),
            (
                "chatgpt.com 443 anywhere\n",
                EgressPolicyError::ScopeUnknown,
            ),
            (
                "chatgpt.com 0 public\n",
                EgressPolicyError::DestinationRejected(
                    automonique_egress_broker::DestinationError::PortRejected,
                ),
            ),
            (
                "chat_gpt.com 443 public\n",
                EgressPolicyError::DestinationRejected(
                    automonique_egress_broker::DestinationError::HostNotLdh,
                ),
            ),
        ];
        for (body, expected) in cases {
            let (_directory, path) = policy(body);
            assert_eq!(
                load_destinations(&path).unwrap_err(),
                expected,
                "policy {body:?} must be refused"
            );
        }
    }

    /// A valid line after an invalid one must not survive: the refusal is of the
    /// file, not of the line.
    #[test]
    fn one_bad_line_refuses_the_whole_policy() {
        let (_directory, path) = policy("chatgpt.com 443 public\nnonsense\n");
        assert_eq!(
            load_destinations(&path).unwrap_err(),
            EgressPolicyError::LineMalformed
        );
    }

    /// Two spellings of one host are one destination, and the broker's own
    /// allowlist is what says so — this module never compares hosts itself.
    #[test]
    fn a_duplicate_destination_refuses_the_policy_at_load() {
        let (_directory, path) = policy("chatgpt.com 443 public\nChatGPT.com 443 public\n");
        assert_eq!(
            load_destinations(&path).unwrap_err(),
            EgressPolicyError::DestinationRejected(
                automonique_egress_broker::DestinationError::DuplicateDestination
            ),
        );
    }

    #[test]
    fn a_policy_longer_than_one_allowlist_is_refused() {
        let mut body = String::new();
        for port in 1000..1017 {
            body.push_str(&format!("chatgpt.com {port} public\n"));
        }
        let (_directory, path) = policy(&body);
        assert_eq!(
            load_destinations(&path).unwrap_err(),
            EgressPolicyError::DestinationRejected(
                automonique_egress_broker::DestinationError::TooManyDestinations
            ),
        );
    }
}
