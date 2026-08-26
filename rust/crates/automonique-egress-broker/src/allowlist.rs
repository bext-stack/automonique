// SPDX-License-Identifier: Elastic-2.0

//! The closed set of destinations a contained workload may reach.
//!
//! An allowlist entry names an **exact host and an exact port**. There is no
//! wildcard, no suffix match, no port range, and no "any port on this host":
//! every widening of a destination policy that has ever gone wrong in practice
//! is a pattern that looked narrow and matched something else. A caller that
//! needs a second endpoint adds a second entry, and the entry count is bounded
//! by [`MAX_ALLOWLIST_ENTRIES`] so an allowlist stays reviewable by reading it.
//!
//! # Two things are checked, at two different times
//!
//! 1. **The name the workload asked for** ([`DestinationAllowlist::permits`]),
//!    against the entries, before anything is resolved or dialled.
//! 2. **The address that name resolved to** ([`AddressScope::permits`]), after
//!    resolution and before the connection is made.
//!
//! The second check exists because the first one is a check on a *name*, and a
//! name is resolved by a resolver this crate does not control. Without it, an
//! allowlist entry for a public endpoint would also authorize reaching whatever
//! that name resolves to — including `127.0.0.1`, i.e. every other service on
//! the host the sandbox exists to keep the workload away from. That is DNS
//! rebinding, and it is not hypothetical: the resolver answer is attacker-
//! influenceable in exactly the deployment where this crate matters.
//!
//! # What the scope check is not
//!
//! It is not authentication of the destination. The broker does not terminate
//! TLS (see the crate docs), so the workload's own certificate validation still
//! runs end to end against the real host name. A resolver that lies about a
//! public endpoint therefore produces a TLS failure in the workload, not a
//! silent redirection — the scope check narrows *which addresses are dialled at
//! all*, and the workload's TLS is what proves *who answered*.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Upper bound on entries in one allowlist.
///
/// A destination policy longer than this is not an exception list, and the
/// caller should be reaching for a different mechanism.
pub const MAX_ALLOWLIST_ENTRIES: usize = 16;

/// Upper bound on a host name, in bytes — the DNS name limit.
pub const MAX_HOST_BYTES: usize = 253;

/// Upper bound on one dot-separated label of a host name, in bytes.
pub const MAX_LABEL_BYTES: usize = 63;

/// Where an allowlisted destination is expected to live, checked against the
/// address its name actually resolves to.
///
/// This is a required part of every entry rather than a default, because the
/// two answers are genuinely different policies and guessing wrong is the whole
/// failure mode: a destination declared [`Self::Public`] that resolves onto the
/// host is a rebinding attempt, and a destination declared [`Self::Loopback`]
/// that resolves off the host is a misconfiguration pointed at the internet.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum AddressScope {
    /// A public internet endpoint. Refuses every address that is loopback,
    /// unspecified, private, shared/CGNAT, link-local, unique-local,
    /// multicast, broadcast, or reserved.
    Public,
    /// An endpoint on this host. Requires a loopback address and nothing else.
    /// This is what a hermetic test's fake destination uses, and it is spelled
    /// out rather than inferred so a test can never accidentally prove that a
    /// public name may point at localhost.
    Loopback,
}

impl AddressScope {
    /// Whether `address` is in this scope.
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`) are canonicalized to
    /// their IPv4 form first. Without that step `Ipv6Addr::is_loopback` answers
    /// `false` for a mapped loopback address, and the mapped spelling is the
    /// ordinary way past a naive scope check.
    #[must_use]
    pub fn permits(self, address: IpAddr) -> bool {
        let address = canonical(address);
        match self {
            Self::Public => is_globally_routable(address),
            Self::Loopback => address.is_loopback(),
        }
    }

    /// Whether a session to a destination in this scope must be wrapped in TLS.
    ///
    /// A public destination always must: the identity-bound path substitutes a
    /// real credential into the request, and sending one in the clear across
    /// the internet would be worse than the exfiltration the substitution
    /// exists to prevent. A loopback destination never leaves the host, so
    /// requiring a certificate for one would only mean minting certificates.
    ///
    /// This says nothing about the `CONNECT` tunnel, which carries whatever
    /// transport security the workload negotiated end to end and is never
    /// terminated here.
    #[must_use]
    pub const fn requires_transport_security(self) -> bool {
        match self {
            Self::Public => true,
            Self::Loopback => false,
        }
    }
}

impl fmt::Display for AddressScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Public => "public",
            Self::Loopback => "loopback",
        })
    }
}

/// Collapse an IPv4-mapped IPv6 address to its IPv4 form; every other address
/// is returned unchanged.
fn canonical(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    }
}

/// Whether an address is one a public endpoint could legitimately have.
///
/// Written as explicit range tests rather than the standard library's
/// `is_global`, which is unstable: a policy this crate depends on must not be
/// on a nightly feature, and the ranges are worth reading in one place.
fn is_globally_routable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_global_v4(v4),
        IpAddr::V6(v6) => is_global_v6(v6),
    }
}

fn is_global_v4(address: Ipv4Addr) -> bool {
    let [a, b, _, _] = address.octets();
    let shared_cgnat = a == 100 && (64..128).contains(&b);
    let private = a == 10 || (a == 172 && (16..32).contains(&b)) || (a == 192 && b == 168);
    let reserved = a >= 240;
    !(address.is_loopback()
        || address.is_unspecified()
        || address.is_broadcast()
        || address.is_multicast()
        || address.is_link_local()
        || address.is_documentation()
        || a == 0
        || private
        || shared_cgnat
        || reserved)
}

fn is_global_v6(address: Ipv6Addr) -> bool {
    let first = address.segments()[0];
    let unique_local = first & 0xfe00 == 0xfc00;
    let link_local = first & 0xffc0 == 0xfe80;
    !(address.is_loopback()
        || address.is_unspecified()
        || address.is_multicast()
        || unique_local
        || link_local)
}

/// A destination host: either a DNS name or an IP literal, never both.
///
/// Keeping the two apart in the type is what lets the broker skip the resolver
/// entirely for a literal — an IP destination is dialled as written, so it can
/// neither be rebound nor block on a resolver.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DestinationHost {
    /// A DNS name, normalized to lowercase ASCII.
    Name(String),
    /// An IP literal, parsed. IPv6 may be written bracketed or bare.
    Address(IpAddr),
}

impl fmt::Display for DestinationHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => formatter.write_str(name),
            Self::Address(IpAddr::V6(address)) => write!(formatter, "[{address}]"),
            Self::Address(address) => write!(formatter, "{address}"),
        }
    }
}

/// Why a host, port, or allowlist was refused.
///
/// Every variant is a refusal. Nothing here means "accepted after repair": a
/// host this module cannot read exactly as written is rejected rather than
/// normalized into something that might match a different entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationError {
    /// The host was empty.
    HostEmpty,
    /// The host exceeded [`MAX_HOST_BYTES`].
    HostTooLong,
    /// The host carried a byte outside the letter/digit/hyphen/dot set. This
    /// includes every non-ASCII byte: an internationalized name must be
    /// presented already punycoded, because two spellings of one name are two
    /// chances to match the wrong entry.
    HostNotLdh,
    /// A dot-separated label was empty, oversized, or hyphen-edged. A trailing
    /// dot lands here too: `example.com.` and `example.com` resolve alike, and
    /// silently stripping it would make one entry match two spellings.
    LabelRejected,
    /// A bracketed host was not a well-formed IPv6 literal.
    BracketedHostNotIpv6,
    /// The port was absent, non-numeric, zero-padded, out of range, or zero.
    /// Port 0 is refused for the same reason the launch surface refuses it: it
    /// is not a port, it is "pick one".
    PortRejected,
    /// The same host and port were offered twice.
    DuplicateDestination,
    /// More than [`MAX_ALLOWLIST_ENTRIES`] destinations were offered.
    TooManyDestinations,
}

impl fmt::Display for DestinationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostEmpty => formatter.write_str("destination host is empty"),
            Self::HostTooLong => {
                write!(formatter, "destination host exceeds {MAX_HOST_BYTES} bytes")
            }
            Self::HostNotLdh => formatter
                .write_str("destination host has a byte outside letters, digits, hyphen, and dot"),
            Self::LabelRejected => write!(
                formatter,
                "a host label is empty, hyphen-edged, or exceeds {MAX_LABEL_BYTES} bytes"
            ),
            Self::BracketedHostNotIpv6 => {
                formatter.write_str("a bracketed host is not a well-formed IPv6 literal")
            }
            Self::PortRejected => {
                formatter.write_str("destination port is absent, malformed, out of range, or zero")
            }
            Self::DuplicateDestination => {
                formatter.write_str("the same host and port were allowlisted twice")
            }
            Self::TooManyDestinations => write!(
                formatter,
                "more than {MAX_ALLOWLIST_ENTRIES} destinations were allowlisted"
            ),
        }
    }
}

impl std::error::Error for DestinationError {}

/// Parse a host as written, refusing anything it cannot read exactly.
///
/// Accepted spellings, and only these: a bracketed IPv6 literal (`[::1]`), a
/// bare IP literal (`127.0.0.1`, `::1`), or a DNS name of lowercase-normalized
/// letter/digit/hyphen labels.
pub fn parse_host(host: &str) -> Result<DestinationHost, DestinationError> {
    if host.is_empty() {
        return Err(DestinationError::HostEmpty);
    }
    if host.len() > MAX_HOST_BYTES {
        return Err(DestinationError::HostTooLong);
    }
    if let Some(inner) = host.strip_prefix('[') {
        let inner = inner
            .strip_suffix(']')
            .ok_or(DestinationError::BracketedHostNotIpv6)?;
        let address: Ipv6Addr = inner
            .parse()
            .map_err(|_| DestinationError::BracketedHostNotIpv6)?;
        return Ok(DestinationHost::Address(IpAddr::V6(address)));
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(DestinationHost::Address(address));
    }
    // Not a literal: it must be a well-formed name. Checked before lowercasing
    // so the byte set is judged on what the caller actually wrote.
    if !host
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
    {
        return Err(DestinationError::HostNotLdh);
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_BYTES {
            return Err(DestinationError::LabelRejected);
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(DestinationError::LabelRejected);
        }
    }
    Ok(DestinationHost::Name(host.to_ascii_lowercase()))
}

/// Parse a port as written: decimal digits only, no sign, no padding, non-zero.
pub fn parse_port(port: &str) -> Result<u16, DestinationError> {
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(DestinationError::PortRejected);
    }
    if port.len() > 1 && port.starts_with('0') {
        return Err(DestinationError::PortRejected);
    }
    match port.parse::<u16>() {
        Ok(0) | Err(_) => Err(DestinationError::PortRejected),
        Ok(port) => Ok(port),
    }
}

/// One host and port a workload is permitted to reach, and the scope its name
/// must resolve into.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Destination {
    host: DestinationHost,
    port: u16,
    scope: AddressScope,
}

impl Destination {
    /// Build a destination from a host and port as written.
    pub fn new(host: &str, port: u16, scope: AddressScope) -> Result<Self, DestinationError> {
        if port == 0 {
            return Err(DestinationError::PortRejected);
        }
        Ok(Self {
            host: parse_host(host)?,
            port,
            scope,
        })
    }

    /// The parsed host.
    #[must_use]
    pub fn host(&self) -> &DestinationHost {
        &self.host
    }

    /// The port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The scope this destination's resolved address must fall in.
    #[must_use]
    pub const fn scope(&self) -> AddressScope {
        self.scope
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.host, self.port)
    }
}

/// The destinations a broker will connect to, and by omission every one it will
/// not.
///
/// An empty allowlist is a valid, useful policy: it refuses everything. That is
/// deliberately the [`Default`], so a partially-built configuration denies
/// rather than permits.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DestinationAllowlist {
    entries: Vec<Destination>,
}

impl DestinationAllowlist {
    /// An allowlist that permits nothing. This is also [`Default`].
    #[must_use]
    pub const fn deny_all() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add one exact destination.
    pub fn allowing(
        mut self,
        host: &str,
        port: u16,
        scope: AddressScope,
    ) -> Result<Self, DestinationError> {
        let destination = Destination::new(host, port, scope)?;
        if self
            .entries
            .iter()
            .any(|entry| entry.host == destination.host && entry.port == destination.port)
        {
            return Err(DestinationError::DuplicateDestination);
        }
        if self.entries.len() >= MAX_ALLOWLIST_ENTRIES {
            return Err(DestinationError::TooManyDestinations);
        }
        self.entries.push(destination);
        Ok(self)
    }

    /// The entries, in the order they were added.
    #[must_use]
    pub fn entries(&self) -> &[Destination] {
        &self.entries
    }

    /// Whether this allowlist permits nothing at all.
    #[must_use]
    pub fn denies_everything(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entry matching `host` and `port` exactly, or `None`.
    ///
    /// Host comparison is on the parsed, normalized form: a name matches
    /// case-insensitively because both sides were lowercased at parse time, and
    /// an IP literal matches numerically. Nothing else matches — in particular
    /// an IPv4-mapped IPv6 literal does not match the IPv4 entry it wraps,
    /// because the two are different ways to name a destination and only the
    /// one that was allowlisted is permitted.
    #[must_use]
    pub fn permits(&self, host: &DestinationHost, port: u16) -> Option<&Destination> {
        self.entries
            .iter()
            .find(|entry| entry.port == port && &entry.host == host)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AddressScope, Destination, DestinationAllowlist, DestinationError, DestinationHost,
        MAX_ALLOWLIST_ENTRIES, MAX_HOST_BYTES, parse_host, parse_port,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn name(host: &str) -> DestinationHost {
        DestinationHost::Name(host.to_owned())
    }

    #[test]
    fn a_name_is_normalized_to_lowercase_so_one_entry_matches_one_destination() {
        assert_eq!(parse_host("ChatGPT.com").unwrap(), name("chatgpt.com"));
        assert_eq!(parse_host("CHATGPT.COM").unwrap(), name("chatgpt.com"));
    }

    #[test]
    fn ip_literals_parse_as_addresses_rather_than_names() {
        assert_eq!(
            parse_host("127.0.0.1").unwrap(),
            DestinationHost::Address(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            parse_host("[::1]").unwrap(),
            DestinationHost::Address(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert_eq!(
            parse_host("::1").unwrap(),
            DestinationHost::Address(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }

    #[test]
    fn every_malformed_host_spelling_is_refused_rather_than_repaired() {
        let cases: [(&str, DestinationError); 10] = [
            ("", DestinationError::HostEmpty),
            (
                "chatgpt.com.",
                // A trailing dot leaves an empty final label.
                DestinationError::LabelRejected,
            ),
            (".chatgpt.com", DestinationError::LabelRejected),
            ("chatgpt..com", DestinationError::LabelRejected),
            ("-chatgpt.com", DestinationError::LabelRejected),
            ("chatgpt-.com", DestinationError::LabelRejected),
            ("chat_gpt.com", DestinationError::HostNotLdh),
            ("chätgpt.com", DestinationError::HostNotLdh),
            ("chatgpt.com/evil", DestinationError::HostNotLdh),
            ("[not-an-address]", DestinationError::BracketedHostNotIpv6),
        ];
        for (host, expected) in cases {
            assert_eq!(parse_host(host), Err(expected), "host {host:?}");
        }
        assert_eq!(
            parse_host(&"a".repeat(MAX_HOST_BYTES + 1)),
            Err(DestinationError::HostTooLong)
        );
        assert_eq!(
            parse_host(&format!("{}.com", "a".repeat(64))),
            Err(DestinationError::LabelRejected)
        );
    }

    #[test]
    fn a_port_must_be_plain_decimal_and_non_zero() {
        assert_eq!(parse_port("443"), Ok(443));
        assert_eq!(parse_port("65535"), Ok(65535));
        assert_eq!(parse_port("1"), Ok(1));
        for rejected in [
            "", "0", "00", "0443", "65536", "99999", "443 ", "+443", "4a3",
        ] {
            assert_eq!(
                parse_port(rejected),
                Err(DestinationError::PortRejected),
                "port {rejected:?}"
            );
        }
    }

    #[test]
    fn an_allowlist_matches_exactly_and_denies_everything_else() {
        let allowlist = DestinationAllowlist::deny_all()
            .allowing("chatgpt.com", 443, AddressScope::Public)
            .unwrap();
        assert!(allowlist.permits(&name("chatgpt.com"), 443).is_some());
        // Different port, neighbouring name, and suffix/prefix games all miss.
        assert!(allowlist.permits(&name("chatgpt.com"), 80).is_none());
        assert!(allowlist.permits(&name("evil-chatgpt.com"), 443).is_none());
        assert!(
            allowlist
                .permits(&name("chatgpt.com.evil.test"), 443)
                .is_none()
        );
        assert!(allowlist.permits(&name("com"), 443).is_none());
    }

    #[test]
    fn an_empty_allowlist_denies_everything() {
        let allowlist = DestinationAllowlist::deny_all();
        assert!(allowlist.denies_everything());
        assert!(allowlist.permits(&name("chatgpt.com"), 443).is_none());
    }

    #[test]
    fn duplicates_and_overflow_are_refused() {
        let allowlist = DestinationAllowlist::deny_all()
            .allowing("chatgpt.com", 443, AddressScope::Public)
            .unwrap();
        assert_eq!(
            allowlist
                .clone()
                .allowing("ChatGPT.com", 443, AddressScope::Loopback)
                .unwrap_err(),
            DestinationError::DuplicateDestination,
            "a duplicate under a different spelling or scope is still a duplicate"
        );
        let mut full = DestinationAllowlist::deny_all();
        for index in 0..MAX_ALLOWLIST_ENTRIES {
            full = full
                .allowing(
                    "chatgpt.com",
                    1000 + u16::try_from(index).unwrap(),
                    AddressScope::Public,
                )
                .unwrap();
        }
        assert_eq!(
            full.allowing("chatgpt.com", 2000, AddressScope::Public)
                .unwrap_err(),
            DestinationError::TooManyDestinations
        );
    }

    #[test]
    fn port_zero_is_refused_at_construction() {
        assert_eq!(
            Destination::new("chatgpt.com", 0, AddressScope::Public).unwrap_err(),
            DestinationError::PortRejected
        );
    }

    #[test]
    fn a_public_scope_refuses_every_address_a_public_endpoint_cannot_have() {
        let refused = [
            "127.0.0.1",
            "127.1.2.3",
            "0.0.0.0",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "240.0.0.1",
            "::",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
        ];
        for address in refused {
            let address: IpAddr = address.parse().unwrap();
            assert!(
                !AddressScope::Public.permits(address),
                "public scope must refuse {address}"
            );
        }
        for address in ["1.1.1.1", "104.18.32.7", "172.32.0.1", "2606:4700::1111"] {
            let address: IpAddr = address.parse().unwrap();
            assert!(
                AddressScope::Public.permits(address),
                "public scope must permit {address}"
            );
        }
    }

    /// `Ipv6Addr::is_loopback` is `false` for `::ffff:127.0.0.1`, so a scope
    /// check that forgot to canonicalize would let a rebound public name reach
    /// the host's own services through the mapped spelling.
    #[test]
    fn an_ipv4_mapped_loopback_address_does_not_pass_the_public_scope() {
        let mapped: IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        assert!(!AddressScope::Public.permits(mapped));
        assert!(AddressScope::Loopback.permits(mapped));
    }

    #[test]
    fn a_loopback_scope_refuses_an_address_off_this_host() {
        assert!(AddressScope::Loopback.permits(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(AddressScope::Loopback.permits(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!AddressScope::Loopback.permits("1.1.1.1".parse::<IpAddr>().unwrap()));
        assert!(!AddressScope::Loopback.permits("10.0.0.1".parse::<IpAddr>().unwrap()));
    }
}
