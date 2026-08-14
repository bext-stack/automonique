// SPDX-License-Identifier: Elastic-2.0

//! Which repository a tenant's ticket belongs in.
//!
//! The legacy console stores this as one KV document under `issues:repo-map`:
//! a `default` repository and a list of rules, each naming a tenant and
//! optionally one of that tenant's sites. Resolution is *site rule, then tenant
//! rule, then default* — the specific beats the general, and a tenant with no
//! rule at all still lands somewhere.
//!
//! The order is the whole contract, so it is stated once, here, and proved by
//! tests that would fail if any two of the three steps were exchanged. Getting
//! it backwards does not error: it files a client's ticket in another client's
//! repository, which is the kind of mistake that is only visible after it has
//! already been read by the wrong people.

use crate::target::RepoTarget;
use crate::{GitHubRefusal, is_opaque_identifier};

/// Longest tenant or site identifier accepted.
pub const MAX_SCOPE_IDENTIFIER_BYTES: usize = 160;

/// Most rules one map may carry.
///
/// The legacy map is edited by hand in a console; a map past this size is a
/// corrupted document rather than a configuration.
pub const MAX_REPO_RULES: usize = 512;

/// A tenant identifier.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TenantId(String);

impl TenantId {
    /// Validate one tenant identifier.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::TenantId`] when the value is empty, longer than
    /// [`MAX_SCOPE_IDENTIFIER_BYTES`], or outside the identifier grammar.
    pub fn new(value: &str) -> Result<Self, GitHubRefusal> {
        if is_opaque_identifier(value, MAX_SCOPE_IDENTIFIER_BYTES) {
            Ok(Self(value.to_owned()))
        } else {
            Err(GitHubRefusal::TenantId)
        }
    }

    /// The exact identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A site identifier, scoped to a tenant.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SiteId(String);

impl SiteId {
    /// Validate one site identifier.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::SiteId`] when the value is empty, longer than
    /// [`MAX_SCOPE_IDENTIFIER_BYTES`], or outside the identifier grammar.
    pub fn new(value: &str) -> Result<Self, GitHubRefusal> {
        if is_opaque_identifier(value, MAX_SCOPE_IDENTIFIER_BYTES) {
            Ok(Self(value.to_owned()))
        } else {
            Err(GitHubRefusal::SiteId)
        }
    }

    /// The exact identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One mapping rule.
///
/// A rule with a site matches only that site. A rule without one matches every
/// site of its tenant — and, per the resolution order, only after every site
/// rule has been considered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepoRule {
    tenant_id: TenantId,
    site_id: Option<SiteId>,
    target: RepoTarget,
    label: Option<String>,
}

impl RepoRule {
    /// Bind one tenant, optionally one site, to one repository.
    ///
    /// `label` is display text carried through from the console and is never
    /// part of matching.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for a display label past its ceiling.
    pub fn new(
        tenant_id: TenantId,
        site_id: Option<SiteId>,
        target: RepoTarget,
        label: Option<&str>,
    ) -> Result<Self, GitHubRefusal> {
        let label = match label.map(str::trim) {
            None | Some("") => None,
            Some(text) if crate::is_line_text(text, MAX_SCOPE_IDENTIFIER_BYTES) => {
                Some(text.to_owned())
            }
            Some(_) => return Err(GitHubRefusal::Text),
        };
        Ok(Self {
            tenant_id,
            site_id,
            target,
            label,
        })
    }

    /// The tenant this rule matches.
    #[must_use]
    pub const fn tenant_id(&self) -> &TenantId {
        &self.tenant_id
    }

    /// The site this rule matches, when it is site-specific.
    #[must_use]
    pub const fn site_id(&self) -> Option<&SiteId> {
        self.site_id.as_ref()
    }

    /// The repository this rule resolves to.
    #[must_use]
    pub const fn target(&self) -> &RepoTarget {
        &self.target
    }

    /// The console's display text for this rule.
    #[must_use]
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }
}

/// The whole `issues:repo-map` document.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RepoMap {
    default: Option<RepoTarget>,
    rules: Vec<RepoRule>,
}

impl RepoMap {
    /// Build one map.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Rules`] for more than [`MAX_REPO_RULES`] rules.
    pub fn new(default: Option<RepoTarget>, rules: Vec<RepoRule>) -> Result<Self, GitHubRefusal> {
        if rules.len() > MAX_REPO_RULES {
            return Err(GitHubRefusal::Rules);
        }
        Ok(Self { default, rules })
    }

    /// The fallback repository, when the document names one.
    #[must_use]
    pub const fn default_target(&self) -> Option<&RepoTarget> {
        self.default.as_ref()
    }

    /// The rules, in document order.
    #[must_use]
    pub fn rules(&self) -> &[RepoRule] {
        &self.rules
    }

    /// Resolve the repository for one tenant and, optionally, one of its sites.
    ///
    /// Exactly three steps, in this order:
    ///
    /// 1. a rule naming both this tenant and this site;
    /// 2. a rule naming this tenant and no site;
    /// 3. the document's default.
    ///
    /// Answers `None` when none of the three applies, which is the legacy
    /// meaning "this ticket stays unlinked" rather than "file it anywhere". The
    /// first matching rule in document order wins at each step, matching the
    /// legacy `Array.find`.
    #[must_use]
    pub fn resolve(&self, tenant_id: &TenantId, site_id: Option<&SiteId>) -> Option<&RepoTarget> {
        if let Some(site_id) = site_id
            && let Some(rule) = self
                .rules
                .iter()
                .find(|rule| &rule.tenant_id == tenant_id && rule.site_id.as_ref() == Some(site_id))
        {
            return Some(&rule.target);
        }
        if let Some(rule) = self
            .rules
            .iter()
            .find(|rule| &rule.tenant_id == tenant_id && rule.site_id.is_none())
        {
            return Some(&rule.target);
        }
        self.default.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(repo: &str) -> RepoTarget {
        RepoTarget::parse("example-org", repo).expect("target")
    }

    fn tenant(value: &str) -> TenantId {
        TenantId::new(value).expect("tenant")
    }

    fn site(value: &str) -> SiteId {
        SiteId::new(value).expect("site")
    }

    fn rule(tenant_id: &str, site_id: Option<&str>, repo: &str) -> RepoRule {
        RepoRule::new(tenant(tenant_id), site_id.map(site), target(repo), None).expect("rule")
    }

    fn map() -> RepoMap {
        RepoMap::new(
            Some(target("fallback-repo")),
            vec![
                rule("tenant-a", None, "tenant-a-repo"),
                rule("tenant-a", Some("site-1"), "site-1-repo"),
                rule("tenant-b", Some("site-9"), "site-9-repo"),
            ],
        )
        .expect("map")
    }

    #[test]
    fn a_site_rule_wins_over_a_tenant_rule_which_wins_over_the_default() {
        let map = map();
        // Site rule, even though the tenant rule appears FIRST in the document:
        // specificity decides, not document order.
        assert_eq!(
            map.resolve(&tenant("tenant-a"), Some(&site("site-1"))),
            Some(&target("site-1-repo"))
        );
        // Tenant rule: this tenant has no rule for this site.
        assert_eq!(
            map.resolve(&tenant("tenant-a"), Some(&site("site-2"))),
            Some(&target("tenant-a-repo"))
        );
        assert_eq!(
            map.resolve(&tenant("tenant-a"), None),
            Some(&target("tenant-a-repo"))
        );
        // Default: this tenant has only a site rule, and it is not this site.
        assert_eq!(
            map.resolve(&tenant("tenant-b"), Some(&site("site-8"))),
            Some(&target("fallback-repo"))
        );
        assert_eq!(
            map.resolve(&tenant("tenant-b"), None),
            Some(&target("fallback-repo"))
        );
        // Site rule for the second tenant.
        assert_eq!(
            map.resolve(&tenant("tenant-b"), Some(&site("site-9"))),
            Some(&target("site-9-repo"))
        );
        // Unknown tenant falls all the way through.
        assert_eq!(
            map.resolve(&tenant("tenant-z"), Some(&site("site-1"))),
            Some(&target("fallback-repo"))
        );
    }

    #[test]
    fn a_site_rule_never_matches_a_bare_tenant_lookup() {
        // The inverse of the order above: asking without a site must NOT pick
        // up a site rule, or one site's repository becomes the tenant's.
        let map =
            RepoMap::new(None, vec![rule("tenant-b", Some("site-9"), "site-9-repo")]).expect("map");
        assert_eq!(map.resolve(&tenant("tenant-b"), None), None);
        assert_eq!(
            map.resolve(&tenant("tenant-b"), Some(&site("site-9"))),
            Some(&target("site-9-repo"))
        );
    }

    #[test]
    fn an_unmapped_tenant_with_no_default_stays_unlinked() {
        let map = RepoMap::new(None, vec![rule("tenant-a", None, "tenant-a-repo")]).expect("map");
        assert_eq!(map.resolve(&tenant("tenant-z"), None), None);
        assert!(map.default_target().is_none());
        assert_eq!(map.rules().len(), 1);
        assert!(
            RepoMap::default()
                .resolve(&tenant("tenant-a"), None)
                .is_none()
        );
    }

    #[test]
    fn the_first_matching_rule_of_a_step_wins() {
        let map = RepoMap::new(
            None,
            vec![
                rule("tenant-a", None, "first-repo"),
                rule("tenant-a", None, "second-repo"),
            ],
        )
        .expect("map");
        assert_eq!(
            map.resolve(&tenant("tenant-a"), None),
            Some(&target("first-repo"))
        );
    }

    #[test]
    fn identifiers_and_rule_counts_are_bounded() {
        assert_eq!(TenantId::new("").err(), Some(GitHubRefusal::TenantId));
        assert_eq!(
            TenantId::new("with space").err(),
            Some(GitHubRefusal::TenantId)
        );
        assert_eq!(
            TenantId::new("quote\"inside").err(),
            Some(GitHubRefusal::TenantId)
        );
        assert_eq!(SiteId::new("").err(), Some(GitHubRefusal::SiteId));
        assert!(TenantId::new(&"t".repeat(MAX_SCOPE_IDENTIFIER_BYTES)).is_ok());
        assert_eq!(
            SiteId::new(&"s".repeat(MAX_SCOPE_IDENTIFIER_BYTES + 1)).err(),
            Some(GitHubRefusal::SiteId)
        );

        let rules: Vec<RepoRule> = (0..=MAX_REPO_RULES)
            .map(|index| rule(&format!("tenant-{index}"), None, "repo"))
            .collect();
        assert_eq!(
            RepoMap::new(None, rules).err(),
            Some(GitHubRefusal::Rules),
            "an over-long map is refused rather than truncated"
        );
    }

    #[test]
    fn a_display_label_is_carried_but_never_matched_on() {
        let rule = RepoRule::new(
            tenant("tenant-a"),
            None,
            target("tenant-a-repo"),
            Some("  Boulangerie Milo  "),
        )
        .expect("rule");
        assert_eq!(rule.label(), Some("Boulangerie Milo"));
        assert_eq!(rule.tenant_id().as_str(), "tenant-a");
        assert!(rule.site_id().is_none());
        assert_eq!(rule.target().to_string(), "example-org/tenant-a-repo");

        assert_eq!(
            RepoRule::new(tenant("t"), None, target("r"), Some("deux\nlignes")).err(),
            Some(GitHubRefusal::Text)
        );
        assert_eq!(
            RepoRule::new(tenant("t"), None, target("r"), Some(""))
                .expect("rule")
                .label(),
            None
        );
    }
}
