// SPDX-License-Identifier: Elastic-2.0

//! The origin lock and every value that may become part of a request path.
//!
//! [`GitHubBase`] is the whole of what a caller may say about *where* this
//! connector points, and it admits one production origin. Everything that
//! follows the origin is rendered from the validated values here — an
//! [`Owner`], a [`Repo`], an [`IssueNumber`] — whose grammars contain no `/`,
//! `?`, `#` or `.` pair. A caller therefore cannot add a path segment, escape a
//! repository, or append a query by naming one.

use std::fmt;

use crate::{GitHubRefusal, MAX_URL_BYTES};
use automonique_connector_substrate::url::{Scheme, split_port, split_scheme};

/// The one production origin this connector may address.
pub const GITHUB_API_ORIGIN: &str = "https://api.github.com";

/// Longest repository owner accepted, per GitHub's own limit.
pub const MAX_OWNER_BYTES: usize = 39;
/// Longest repository name accepted, per GitHub's own limit.
pub const MAX_REPO_BYTES: usize = 100;
/// Longest label accepted, per GitHub's own limit.
pub const MAX_LABEL_BYTES: usize = 50;
/// Highest issue number accepted.
///
/// No repository has come close; the bound exists so a number is always a
/// short, bounded path segment.
pub const MAX_ISSUE_NUMBER: u32 = 9_999_999;

/// A validated GitHub API origin.
///
/// # What is admitted
///
/// * `https://api.github.com`, which is the production shape and the only host
///   this connector will ever send a credential to, and
/// * `http://127.0.0.1[:<port>]` or `http://[::1][:<port>]`, which is the only
///   plaintext shape and cannot address anything off this host.
///
/// The loopback exception exists so the connector's wire behaviour — its
/// headers, its paths, its decoders — is provable against an in-process fake
/// without a certificate. It is safe by construction rather than by policy: the
/// two literals it admits are not routable off-box, and no name that could
/// resolve elsewhere is accepted with `http`. A plaintext base marks itself as
/// such so the HTTP agent built from it is the only one that ever relaxes
/// `https_only`.
///
/// Note what is *not* admitted: a GitHub Enterprise host. Enterprise deploys a
/// different path prefix (`/api/v3`) and a different rate-limit contract, so
/// admitting the host without the rest would be a connector that looks
/// configured and is not.
#[derive(Clone, Eq, PartialEq)]
pub struct GitHubBase {
    origin: String,
    plaintext_loopback: bool,
}

impl GitHubBase {
    /// The production origin.
    #[must_use]
    pub fn production() -> Self {
        Self {
            origin: GITHUB_API_ORIGIN.to_owned(),
            plaintext_loopback: false,
        }
    }

    /// Validate one origin.
    ///
    /// A single trailing `/` is accepted and dropped. Anything further — a path
    /// segment, a `?`, a `#`, or `user@host` — is refused rather than trimmed,
    /// because silently discarding part of a configured URL is how a connector
    /// ends up addressing a host nobody configured.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Base`] for any origin outside the two admitted
    /// shapes.
    pub fn new(base: &str) -> Result<Self, GitHubRefusal> {
        if base.is_empty() || base.len() > 128 || !base.is_ascii() {
            return Err(GitHubRefusal::Base);
        }
        let (scheme, remainder) = split_scheme(base).ok_or(GitHubRefusal::Base)?;
        let authority = remainder.strip_suffix('/').unwrap_or(remainder);
        if authority.is_empty()
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
            || authority.contains('@')
            || authority.contains('\\')
        {
            return Err(GitHubRefusal::Base);
        }
        let (host, port) = split_port(authority).ok_or(GitHubRefusal::Base)?;

        match scheme {
            // One host, and no port: a credential-bearing call to
            // `api.github.com:8443` is a call to something that is not GitHub.
            Scheme::Https => {
                if !host.eq_ignore_ascii_case("api.github.com") || port.is_some() {
                    return Err(GitHubRefusal::Base);
                }
                Ok(Self::production())
            }
            // Only the two loopback literals, never a name that a resolver
            // could point somewhere else.
            Scheme::Http => {
                if !matches!(host, "127.0.0.1" | "[::1]") {
                    return Err(GitHubRefusal::Base);
                }
                let mut origin = String::with_capacity(authority.len() + 8);
                origin.push_str("http://");
                origin.push_str(host);
                if let Some(port) = port {
                    origin.push(':');
                    origin.push_str(&port.to_string());
                }
                Ok(Self {
                    origin,
                    plaintext_loopback: true,
                })
            }
        }
    }

    /// The normalized origin, with no trailing slash.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Whether this base is the plaintext loopback shape.
    ///
    /// The HTTP agent consults this and nothing else when deciding whether to
    /// relax `https_only`.
    #[must_use]
    pub const fn is_plaintext_loopback(&self) -> bool {
        self.plaintext_loopback
    }
}

/// The origin carries no credential, so `Debug` shows it: an operator
/// diagnosing a misconfigured deployment needs to see which host was addressed.
impl fmt::Debug for GitHubBase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubBase")
            .field("origin", &self.origin)
            .field("plaintext_loopback", &self.plaintext_loopback)
            .finish()
    }
}

/// A validated repository owner — a user or an organization login.
///
/// GitHub's own grammar: ASCII alphanumerics and interior hyphens, at most
/// [`MAX_OWNER_BYTES`]. It contains no `/`, `.`, `?` or `#`, which is what
/// makes it safe as a path segment: `..` and `owner/../other` cannot be
/// spelled.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Owner(String);

impl Owner {
    /// Validate one owner.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Owner`] for anything outside the grammar.
    pub fn new(value: &str) -> Result<Self, GitHubRefusal> {
        if value.is_empty()
            || value.len() > MAX_OWNER_BYTES
            || value.starts_with('-')
            || value.ends_with('-')
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(GitHubRefusal::Owner);
        }
        Ok(Self(value.to_owned()))
    }

    /// The exact path segment.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated repository name.
///
/// GitHub's own grammar: ASCII alphanumerics, `-`, `_` and `.`, at most
/// [`MAX_REPO_BYTES`]. `.` and `..` are refused outright, so no name is a
/// relative path even though the dot is admitted (a repository may legitimately
/// be called `.github`).
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Repo(String);

impl Repo {
    /// Validate one repository name.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Repo`] for anything outside the grammar.
    pub fn new(value: &str) -> Result<Self, GitHubRefusal> {
        if value.is_empty()
            || value.len() > MAX_REPO_BYTES
            || matches!(value, "." | "..")
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(GitHubRefusal::Repo);
        }
        Ok(Self(value.to_owned()))
    }

    /// The exact path segment.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One repository this connector may address.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RepoTarget {
    owner: Owner,
    repo: Repo,
}

impl RepoTarget {
    /// Bind one owner to one repository.
    #[must_use]
    pub const fn new(owner: Owner, repo: Repo) -> Self {
        Self { owner, repo }
    }

    /// Validate an `owner`/`repo` pair from configuration.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Owner`] or [`GitHubRefusal::Repo`] naming the
    /// half that was outside its grammar.
    pub fn parse(owner: &str, repo: &str) -> Result<Self, GitHubRefusal> {
        Ok(Self::new(Owner::new(owner)?, Repo::new(repo)?))
    }

    /// The owner.
    #[must_use]
    pub const fn owner(&self) -> &Owner {
        &self.owner
    }

    /// The repository.
    #[must_use]
    pub const fn repo(&self) -> &Repo {
        &self.repo
    }
}

impl fmt::Display for RepoTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}/{}", self.owner.as_str(), self.repo.as_str())
    }
}

/// A validated issue number.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct IssueNumber(u32);

impl IssueNumber {
    /// Validate one issue number.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::IssueNumber`] for zero or a value over
    /// [`MAX_ISSUE_NUMBER`]. Zero is refused because the legacy mapper
    /// *substitutes* it for an unreadable number, so a zero reaching this
    /// connector is a value that was already lost.
    pub const fn new(number: u32) -> Result<Self, GitHubRefusal> {
        if number == 0 || number > MAX_ISSUE_NUMBER {
            return Err(GitHubRefusal::IssueNumber);
        }
        Ok(Self(number))
    }

    /// The exact path segment value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// One positive GitHub issue-comment identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommentId(u64);

impl CommentId {
    /// Validate one issue-comment id.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::CommentId`] for zero.
    pub const fn new(value: u64) -> Result<Self, GitHubRefusal> {
        if value == 0 {
            return Err(GitHubRefusal::CommentId);
        }
        Ok(Self(value))
    }

    /// The numeric id.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for CommentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl fmt::Display for IssueNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// The two states an issue may be in.
///
/// A closed vocabulary in both directions: an unknown state on the wire is a
/// refusal rather than a string carried forward, because every consumer of this
/// field branches on it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IssueState {
    /// The issue is open.
    Open,
    /// The issue is closed.
    Closed,
}

impl IssueState {
    /// The exact wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }

    /// Read one wire spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "open" => Some(Self::Open),
            "closed" => Some(Self::Closed),
            _ => None,
        }
    }
}

/// A validated issue label.
///
/// Bounded at [`MAX_LABEL_BYTES`] and free of control characters. The comma is
/// refused as well: GitHub's own `labels` filter is a comma-separated list, so
/// a label containing one could not be filtered for, and admitting it here
/// would mean a label this connector can set and never search.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Label(String);

impl Label {
    /// Validate one label.
    ///
    /// Surrounding whitespace is trimmed, matching the legacy client's own
    /// cleaning pass.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Label`] for a label that is empty after
    /// trimming, over [`MAX_LABEL_BYTES`], control-bearing, or comma-bearing.
    pub fn new(value: &str) -> Result<Self, GitHubRefusal> {
        let value = value.trim();
        if value.is_empty()
            || value.len() > MAX_LABEL_BYTES
            || value.contains(',')
            || value.chars().any(char::is_control)
        {
            return Err(GitHubRefusal::Label);
        }
        Ok(Self(value.to_owned()))
    }

    /// The exact label text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One issue named by a URL or by the `owner/repo#123` shorthand.
///
/// The legacy console accepts both spellings when an operator links a ticket by
/// hand. Parsing is total and answers `None` rather than an error, because the
/// caller is asking "is this an issue reference?" — not asserting that it is.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssueLocator {
    target: RepoTarget,
    number: IssueNumber,
}

impl IssueLocator {
    /// Bind a target to a number.
    #[must_use]
    pub const fn new(target: RepoTarget, number: IssueNumber) -> Self {
        Self { target, number }
    }

    /// Read `https://github.com/owner/repo/issues/123` or `owner/repo#123`.
    ///
    /// A `/pull/` URL parses too: the `/issues/{n}` endpoint answers for pull
    /// requests as well, and the decoder — not the parser — is where a pull
    /// request is told apart, so that a caller who pasted one is told exactly
    /// that rather than "unparseable".
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let raw = raw.trim();
        if raw.is_empty() || raw.len() > MAX_URL_BYTES || !raw.is_ascii() {
            return None;
        }
        parse_web_url(raw).or_else(|| parse_shorthand(raw))
    }

    /// The repository.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    /// The issue number.
    #[must_use]
    pub const fn number(&self) -> IssueNumber {
        self.number
    }
}

/// `…github.com[/:]owner/repo[.git]/(issues|pull)/123[…]`.
fn parse_web_url(raw: &str) -> Option<IssueLocator> {
    let lowered = raw.to_ascii_lowercase();
    let host = lowered.find("github.com")?;
    let after_host = &raw[host + "github.com".len()..];
    let separator = after_host.chars().next()?;
    if !matches!(separator, '/' | ':') {
        return None;
    }
    let mut segments = after_host[1..].split('/');
    let owner = Owner::new(segments.next()?).ok()?;
    let repo = segments.next()?;
    let repo = Repo::new(repo.strip_suffix(".git").unwrap_or(repo)).ok()?;
    if !matches!(segments.next()?, "issues" | "pull") {
        return None;
    }
    // A trailing `#issuecomment-…` or `?since=…` may follow the number; the
    // number is the leading digit run and the rest is not addressed here.
    let tail = segments.next()?;
    let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
    let number = IssueNumber::new(digits.parse().ok()?).ok()?;
    Some(IssueLocator::new(RepoTarget::new(owner, repo), number))
}

/// `owner/repo#123`.
fn parse_shorthand(raw: &str) -> Option<IssueLocator> {
    let (repository, number) = raw.split_once('#')?;
    let (owner, repo) = repository.split_once('/')?;
    let number = IssueNumber::new(number.parse().ok()?).ok()?;
    Some(IssueLocator::new(
        RepoTarget::parse(owner, repo).ok()?,
        number,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_one_tls_origin_is_addressable() {
        let base = GitHubBase::new("https://api.github.com/").expect("base");
        assert_eq!(base.origin(), GITHUB_API_ORIGIN);
        assert!(!base.is_plaintext_loopback());
        assert_eq!(GitHubBase::production().origin(), GITHUB_API_ORIGIN);
        // The scheme and host are case-insensitive; the rendering is not.
        assert_eq!(
            GitHubBase::new("HTTPS://API.GitHub.Com")
                .expect("base")
                .origin(),
            GITHUB_API_ORIGIN
        );

        for refused in [
            "https://api.github.com:8443",
            "https://github.com",
            "https://api.github.com.evil.invalid",
            "https://ghe.example.com",
            "https://api.github.com/repos",
            "https://api.github.com?a=1",
            "https://api.github.com#frag",
            "https://user:pass@api.github.com",
            "https://api.github.com\\@evil.invalid",
            "http://api.github.com",
            "//api.github.com",
            "api.github.com",
            "ftp://api.github.com",
            "",
        ] {
            assert_eq!(
                GitHubBase::new(refused).err(),
                Some(GitHubRefusal::Base),
                "must refuse {refused:?}"
            );
        }
    }

    #[test]
    fn only_the_two_loopback_literals_may_be_plaintext() {
        for admitted in [
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
            "http://127.0.0.1",
        ] {
            let base = GitHubBase::new(admitted).expect(admitted);
            assert!(base.is_plaintext_loopback(), "{admitted}");
        }
        for refused in [
            "http://localhost:8080",
            "http://10.0.0.7:8080",
            "http://127.0.0.2:8080",
            "http://0.0.0.0:8080",
            "http://127.0.0.1:0",
            "http://127.0.0.1:080",
        ] {
            assert_eq!(
                GitHubBase::new(refused).err(),
                Some(GitHubRefusal::Base),
                "must refuse {refused}"
            );
        }
    }

    #[test]
    fn an_owner_and_a_repo_can_never_add_a_path_segment() {
        assert_eq!(
            RepoTarget::parse("example-org", "example-repo")
                .expect("target")
                .to_string(),
            "example-org/example-repo"
        );
        assert!(Repo::new(".github").is_ok());
        assert!(Repo::new("repo.with_every-class.9").is_ok());

        for refused in [
            "",
            "-lead",
            "trail-",
            "with/slash",
            "with.dot",
            "with_underscore",
            "..",
            "with space",
            "accentue\u{301}",
            "with?query",
            "with#frag",
        ] {
            assert_eq!(
                Owner::new(refused).err(),
                Some(GitHubRefusal::Owner),
                "must refuse owner {refused:?}"
            );
        }
        for refused in ["", ".", "..", "with/slash", "with space", "with?query"] {
            assert_eq!(
                Repo::new(refused).err(),
                Some(GitHubRefusal::Repo),
                "must refuse repo {refused:?}"
            );
        }
        assert!(Owner::new(&"o".repeat(MAX_OWNER_BYTES)).is_ok());
        assert_eq!(
            Owner::new(&"o".repeat(MAX_OWNER_BYTES + 1)).err(),
            Some(GitHubRefusal::Owner)
        );
        assert!(Repo::new(&"r".repeat(MAX_REPO_BYTES)).is_ok());
        assert_eq!(
            Repo::new(&"r".repeat(MAX_REPO_BYTES + 1)).err(),
            Some(GitHubRefusal::Repo)
        );
    }

    #[test]
    fn an_issue_number_is_bounded_and_never_zero() {
        assert_eq!(IssueNumber::new(1).expect("number").get(), 1);
        assert_eq!(IssueNumber::new(0).err(), Some(GitHubRefusal::IssueNumber));
        assert!(IssueNumber::new(MAX_ISSUE_NUMBER).is_ok());
        assert_eq!(
            IssueNumber::new(MAX_ISSUE_NUMBER + 1).err(),
            Some(GitHubRefusal::IssueNumber)
        );
    }

    #[test]
    fn a_comment_id_is_positive_and_kept_exactly() {
        assert_eq!(CommentId::new(0).err(), Some(GitHubRefusal::CommentId));
        let id = CommentId::new(u64::MAX).expect("comment id");
        assert_eq!(id.get(), u64::MAX);
        assert_eq!(id.to_string(), u64::MAX.to_string());
    }

    #[test]
    fn a_label_is_bounded_trimmed_and_filterable() {
        assert_eq!(
            Label::new("  tenant:Milo  ").expect("label").as_str(),
            "tenant:Milo"
        );
        for refused in ["", "   ", "a,b", "with\u{1b}[2J"] {
            assert_eq!(
                Label::new(refused).err(),
                Some(GitHubRefusal::Label),
                "must refuse label {refused:?}"
            );
        }
        assert!(Label::new(&"l".repeat(MAX_LABEL_BYTES)).is_ok());
        assert_eq!(
            Label::new(&"l".repeat(MAX_LABEL_BYTES + 1)).err(),
            Some(GitHubRefusal::Label)
        );
    }

    #[test]
    fn an_issue_state_is_a_closed_vocabulary() {
        assert_eq!(IssueState::parse("open"), Some(IssueState::Open));
        assert_eq!(IssueState::parse("closed"), Some(IssueState::Closed));
        assert_eq!(IssueState::parse("OPEN"), None);
        assert_eq!(IssueState::parse("merged"), None);
        assert_eq!(IssueState::Open.as_str(), "open");
        assert_eq!(IssueState::Closed.as_str(), "closed");
    }

    #[test]
    fn an_issue_reference_parses_from_a_url_or_the_shorthand() {
        let expected = IssueLocator::new(
            RepoTarget::parse("example-org", "example-repo").expect("target"),
            IssueNumber::new(42).expect("number"),
        );
        for spelling in [
            "https://github.com/example-org/example-repo/issues/42",
            "http://github.com/example-org/example-repo/issues/42",
            "https://github.com/example-org/example-repo.git/issues/42",
            "https://github.com/example-org/example-repo/pull/42",
            "https://github.com/example-org/example-repo/issues/42#issuecomment-9",
            "git@github.com:example-org/example-repo/issues/42",
            "  example-org/example-repo#42  ",
        ] {
            assert_eq!(
                IssueLocator::parse(spelling).as_ref(),
                Some(&expected),
                "must parse {spelling:?}"
            );
        }
        for refused in [
            "",
            "not a url",
            "https://gitlab.example/example-org/example-repo/issues/42",
            "https://github.com/example-org/example-repo/issues/0",
            "https://github.com/example-org/example-repo/issues/abc",
            "https://github.com/example-org/example-repo/releases/42",
            "https://github.com/example-org/example-repo",
            "example-org/example-repo",
            "example-org#42",
            &format!("https://github.com/a/b/issues/{}", MAX_ISSUE_NUMBER + 1),
        ] {
            assert_eq!(
                IssueLocator::parse(refused),
                None,
                "must refuse {refused:?}"
            );
        }
    }
}
