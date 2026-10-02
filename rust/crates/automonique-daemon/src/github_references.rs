// SPDX-License-Identifier: Elastic-2.0

//! Read the GitHub issues a chat turn refers to.
//!
//! People name issues in many shapes: a canonical URL pasted from Slack,
//! `owner/repo#123`, a local alias such as `alias#123`, or a bare `#123` in a
//! follow-up to an answer that listed issues. This module recognizes those
//! shapes against the private repository allowlist only, resolves a bare
//! number solely when the surrounding text makes the repository unambiguous,
//! and renders one bounded, untrusted block of current state plus the latest
//! comments (author, time, excerpt).
//!
//! Every read here is a fixed-origin typed GET through [`GitHubSurface`]. No
//! text can widen the allowlist, and nothing is ever written.

use std::collections::BTreeSet;

use automonique_github_connector::{IssueLocator, IssueNumber, RepoTarget};

use crate::github::{GitHubIssueBrief, GitHubSurface, ISSUE_BRIEF_UNSUPPORTED, IssueFactDetail};

/// Most issues one turn reads.
pub const MAX_REFERENCED_ISSUES: usize = 10;
/// Characters the rendered block may occupy in a prompt.
pub const REFERENCED_ISSUES_BUDGET: usize = 8_000;
/// Latest comments read per issue.
pub const REFERENCED_ISSUE_COMMENTS: usize = 3;
/// Capability name the block is labelled with.
pub const REFERENCED_ISSUES_CAPABILITY: &str = "github_issues";

const MAX_SCANNED_TEXT_CHARS: usize = 64 * 1024;
const MAX_MENTIONS_PER_TEXT: usize = 64;
const MAX_TRACKED_REFERENCES: usize = 32;

/// Words that, written before `#123`, still mean "an issue number".
const GENERIC_ISSUE_PREFIXES: &[&str] = &["issue", "issues", "ticket", "tickets", "pr", "bug"];

/// The allowlisted repositories as chat text can name them.
#[derive(Clone, Debug, Default)]
pub struct RepositoryCatalog {
    repositories: Vec<RepoTarget>,
    /// Lowercase alias to configured repository.
    aliases: Vec<(String, RepoTarget)>,
}

impl RepositoryCatalog {
    /// Read the allowlist and its aliases from a configured surface.
    #[must_use]
    pub fn from_surface(surface: &dyn GitHubSurface) -> Self {
        Self::new(
            &surface.configured_repositories(),
            &surface.configured_repository_aliases(),
        )
    }

    /// Build from `owner/repo` strings and `(alias, owner/repo)` pairs.
    /// Aliases naming an unconfigured repository are dropped.
    #[must_use]
    pub fn new(repositories: &[String], aliases: &[(String, String)]) -> Self {
        let repositories: Vec<RepoTarget> = repositories
            .iter()
            .filter_map(|value| parse_repository(value))
            .collect();
        let aliases = aliases
            .iter()
            .filter_map(|(alias, repository)| {
                let target = parse_repository(repository)?;
                let configured = repositories
                    .iter()
                    .find(|candidate| same_repository(candidate, &target))?;
                Some((alias.to_lowercase(), configured.clone()))
            })
            .collect();
        Self {
            repositories,
            aliases,
        }
    }

    /// Whether nothing is allowlisted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.repositories.is_empty()
    }

    /// The configured spelling of `target`, if it is allowlisted.
    ///
    /// A surface that does not enumerate its allowlist (an injected,
    /// issue-only surface) enforces it on every read itself, so an exact
    /// reference passes through to that surface unchanged.
    fn configured<'a>(&'a self, target: &'a RepoTarget) -> Option<&'a RepoTarget> {
        if self.repositories.is_empty() {
            return Some(target);
        }
        self.repositories
            .iter()
            .find(|candidate| same_repository(candidate, target))
    }

    /// A local alias, else a configured repository name that is unique.
    fn by_name(&self, name: &str) -> Option<&RepoTarget> {
        let name = name.to_lowercase();
        if let Some((_, target)) = self.aliases.iter().find(|(alias, _)| *alias == name) {
            return Some(target);
        }
        let mut matching = self
            .repositories
            .iter()
            .filter(|target| target.repo().as_str().eq_ignore_ascii_case(&name));
        let first = matching.next()?;
        matching.next().is_none().then_some(first)
    }

    fn label(&self, target: &RepoTarget) -> String {
        self.aliases
            .iter()
            .find(|(_, configured)| same_repository(configured, target))
            .map_or_else(|| target.to_string(), |(alias, _)| alias.clone())
    }
}

/// One issue a turn refers to, after allowlist resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IssueReference {
    /// An exact issue in a configured repository: safe to read.
    Allowlisted(IssueLocator),
    /// An exact issue in a repository outside the allowlist: never read.
    NotConfigured(String),
    /// A bare `#number` whose repository the text does not settle.
    Ambiguous {
        number: u32,
        candidates: Vec<String>,
    },
}

impl IssueReference {
    fn key(&self) -> String {
        match self {
            Self::Allowlisted(locator) => canonical(locator).to_lowercase(),
            Self::NotConfigured(reference) => reference.to_lowercase(),
            Self::Ambiguous { number, .. } => format!("#{number}"),
        }
    }

    /// `owner/repo#number` for an allowlisted reference.
    #[must_use]
    pub fn canonical(&self) -> Option<String> {
        match self {
            Self::Allowlisted(locator) => Some(canonical(locator)),
            Self::NotConfigured(_) | Self::Ambiguous { .. } => None,
        }
    }
}

/// The texts a turn's references may come from, most relevant first.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReferenceSources<'a> {
    /// The operator's current message.
    pub message: &'a str,
    /// Live tool text read during this turn, such as a Slack snapshot,
    /// oldest line first.
    pub live: &'a [&'a str],
    /// Recent conversation messages (both roles), newest first.
    pub history_newest_first: &'a [&'a str],
    /// Canonical `owner/repo#number` references an earlier turn of the same
    /// conversation read. They settle bare numbers in a follow-up, and are
    /// the references of last resort when the turn names none itself.
    pub remembered: &'a [String],
}

/// What a turn refers to.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReferenceSelection {
    /// Deduplicated, most relevant first.
    pub references: Vec<IssueReference>,
    /// The current message itself names at least one issue.
    pub message_names_issues: bool,
}

impl ReferenceSelection {
    /// Whether any reference may be read.
    #[must_use]
    pub fn has_allowlisted(&self) -> bool {
        self.references
            .iter()
            .any(|reference| matches!(reference, IssueReference::Allowlisted(_)))
    }
}

#[derive(Clone, Debug)]
enum Mention {
    Exact(RepoTarget, IssueNumber),
    Bare(IssueNumber),
}

/// Recognize and resolve the issue references in a turn's sources.
#[must_use]
pub fn select_issue_references(
    sources: &ReferenceSources<'_>,
    catalog: &RepositoryCatalog,
) -> ReferenceSelection {
    let message = scan_mentions(sources.message, catalog);
    let live: Vec<Vec<Mention>> = sources
        .live
        .iter()
        .map(|text| {
            // Snapshots are chronological: the newest mention matters most.
            let mut mentions = scan_mentions(text, catalog);
            mentions.reverse();
            mentions
        })
        .collect();
    let history: Vec<Vec<Mention>> = sources
        .history_newest_first
        .iter()
        .map(|text| scan_mentions(text, catalog))
        .collect();
    let remembered: Vec<Mention> = sources
        .remembered
        .iter()
        .take(MAX_TRACKED_REFERENCES)
        .flat_map(|text| scan_mentions(text, catalog))
        .filter(|mention| matches!(mention, Mention::Exact(..)))
        .collect();

    // Everything the turn can see settles bare numbers: exact references
    // anywhere, plus repository aliases written as words.
    let mut exact_seen: Vec<(RepoTarget, IssueNumber)> = Vec::new();
    for mention in message
        .iter()
        .chain(live.iter().flatten())
        .chain(history.iter().flatten())
        .chain(remembered.iter())
    {
        if let Mention::Exact(target, number) = mention
            && let Some(configured) = catalog.configured(target)
            && !exact_seen
                .iter()
                .any(|(seen, seen_number)| seen == configured && seen_number == number)
        {
            exact_seen.push((configured.clone(), *number));
        }
    }
    let mut named_repositories: Vec<RepoTarget> = Vec::new();
    let mut note_repository = |target: &RepoTarget| {
        if !named_repositories.contains(target) {
            named_repositories.push(target.clone());
        }
    };
    for (target, _) in &exact_seen {
        note_repository(target);
    }
    for text in std::iter::once(&sources.message)
        .chain(sources.live.iter())
        .chain(sources.history_newest_first.iter())
    {
        for term in repository_terms(text) {
            if let Some(target) = catalog.by_name(&term) {
                note_repository(target);
            }
        }
    }

    let mut selection = ReferenceSelection {
        message_names_issues: !message.is_empty(),
        references: Vec::new(),
    };
    let mut keys = BTreeSet::new();
    let mut push = |selection: &mut ReferenceSelection, reference: IssueReference| {
        if selection.references.len() >= MAX_TRACKED_REFERENCES {
            return;
        }
        if keys.insert(reference.key()) {
            selection.references.push(reference);
        }
    };
    for mention in message
        .iter()
        .chain(live.iter().flatten())
        .chain(history.iter().flatten())
    {
        let reference = resolve(mention, catalog, &exact_seen, &named_repositories);
        push(&mut selection, reference);
    }
    if !selection.has_allowlisted() {
        for mention in &remembered {
            let reference = resolve(mention, catalog, &exact_seen, &named_repositories);
            push(&mut selection, reference);
        }
    }
    // A bare number settled elsewhere in the turn is not also ambiguous.
    let resolved_numbers: BTreeSet<u32> = selection
        .references
        .iter()
        .filter_map(|reference| match reference {
            IssueReference::Allowlisted(locator) => Some(locator.number().get()),
            _ => None,
        })
        .collect();
    selection.references.retain(|reference| match reference {
        IssueReference::Ambiguous { number, .. } => !resolved_numbers.contains(number),
        _ => true,
    });
    selection
}

fn resolve(
    mention: &Mention,
    catalog: &RepositoryCatalog,
    exact_seen: &[(RepoTarget, IssueNumber)],
    named_repositories: &[RepoTarget],
) -> IssueReference {
    match mention {
        Mention::Exact(target, number) => match catalog.configured(target) {
            Some(configured) => {
                IssueReference::Allowlisted(IssueLocator::new(configured.clone(), *number))
            }
            None => IssueReference::NotConfigured(format!("{target}#{number}")),
        },
        Mention::Bare(number) => {
            let same_number: Vec<&RepoTarget> = exact_seen
                .iter()
                .filter(|(_, seen)| seen == number)
                .map(|(target, _)| target)
                .collect();
            let candidates: Vec<&RepoTarget> = match same_number.as_slice() {
                [] if named_repositories.len() == 1 => named_repositories.iter().collect(),
                [] => catalog.repositories.iter().collect(),
                _ => same_number,
            };
            match candidates.as_slice() {
                [only] => IssueReference::Allowlisted(IssueLocator::new((*only).clone(), *number)),
                _ => IssueReference::Ambiguous {
                    number: number.get(),
                    candidates: candidates
                        .iter()
                        .map(|target| catalog.label(target))
                        .collect(),
                },
            }
        }
    }
}

/// Whether the message asks about issues, their status, progress, or comments.
#[must_use]
pub fn mentions_issue_work(message: &str) -> bool {
    message
        .split(|character: char| !character.is_alphanumeric() && character != '\'')
        .filter(|term| !term.is_empty())
        .map(str::to_lowercase)
        .any(|term| {
            matches!(
                term.as_str(),
                "issue"
                    | "issues"
                    | "ticket"
                    | "tickets"
                    | "done"
                    | "finished"
                    | "complete"
                    | "completed"
                    | "status"
                    | "progress"
                    | "open"
                    | "closed"
                    | "comment"
                    | "comments"
                    | "commented"
                    | "reply"
                    | "replies"
                    | "replied"
                    | "answered"
                    | "who"
                    | "latest"
                    | "update"
                    | "updates"
                    | "updated"
                    | "state"
                    | "fixed"
                    | "resolved"
                    | "assigned"
                    | "pending"
                    | "still"
                    | "delivered"
                    | "sent"
                    | "fait"
                    | "faits"
                    | "fini"
                    | "finis"
                    | "terminé"
                    | "terminés"
                    | "termine"
                    | "commentaire"
                    | "commentaires"
                    | "qui"
                    | "statut"
                    | "avancement"
                    | "ouvert"
                    | "ouverts"
                    | "fermé"
                    | "fermés"
                    | "répondu"
                    | "dernier"
                    | "dernière"
                    | "derniers"
                    | "dernières"
                    | "état"
                    | "livré"
                    | "envoyé"
            )
        })
}

/// Whether a turn should read its referenced issues.
#[must_use]
pub fn issue_lookup_requested(message: &str, selection: &ReferenceSelection) -> bool {
    !selection.references.is_empty()
        && (selection.message_names_issues || mentions_issue_work(message))
}

/// The rendered block plus what it read.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReferencedIssues {
    /// Bounded untrusted text for one `github_issues` live-tool block.
    pub content: String,
    /// Canonical references that were read successfully.
    pub read: Vec<String>,
}

enum Entry {
    Brief(GitHubIssueBrief),
    Facts(String, String),
    Failed(String, String),
    NotConfigured(String),
    Ambiguous(u32, Vec<String>),
    Omitted(String),
}

/// Read every allowlisted reference (capped) and render one bounded block.
///
/// Each reference gets its own line, including a failure line naming why it
/// could not be read, so a gap is never passed off as a vague truncation.
pub fn read_referenced_issues(
    surface: &mut dyn GitHubSurface,
    references: &[IssueReference],
    budget: usize,
) -> ReferencedIssues {
    let mut entries = Vec::new();
    let mut read = Vec::new();
    let mut attempted = 0_usize;
    for reference in references {
        match reference {
            IssueReference::Allowlisted(locator) => {
                let key = canonical(locator);
                if attempted >= MAX_REFERENCED_ISSUES {
                    entries.push(Entry::Omitted(key));
                    continue;
                }
                attempted += 1;
                match surface.issue_brief(locator, REFERENCED_ISSUE_COMMENTS) {
                    Ok(brief) => {
                        read.push(key);
                        entries.push(Entry::Brief(brief));
                    }
                    Err(error) if error == ISSUE_BRIEF_UNSUPPORTED => {
                        match surface.issue_facts(locator, IssueFactDetail::Summary) {
                            Ok(facts) => {
                                read.push(key.clone());
                                entries.push(Entry::Facts(key, facts));
                            }
                            Err(error) => entries.push(Entry::Failed(key, error)),
                        }
                    }
                    Err(error) => entries.push(Entry::Failed(key, error)),
                }
            }
            IssueReference::NotConfigured(key) => entries.push(Entry::NotConfigured(key.clone())),
            IssueReference::Ambiguous { number, candidates } => {
                entries.push(Entry::Ambiguous(*number, candidates.clone()));
            }
        }
    }
    // Comment excerpts shrink first, then titles, until the block fits.
    const LEVELS: &[(usize, usize)] = &[(400, 200), (240, 160), (120, 120), (60, 100), (0, 80)];
    let mut content = String::new();
    for (excerpt, title) in LEVELS {
        content = render(&entries, *excerpt, *title);
        if content.chars().count() <= budget {
            break;
        }
    }
    if content.chars().count() > budget {
        let mark = "\n[block truncated at budget]";
        let keep = budget.saturating_sub(mark.chars().count());
        content = content.chars().take(keep).collect::<String>() + mark;
    }
    ReferencedIssues { content, read }
}

fn render(entries: &[Entry], excerpt_chars: usize, title_chars: usize) -> String {
    let count = |predicate: fn(&Entry) -> bool| entries.iter().filter(|e| predicate(e)).count();
    let mut out = format!(
        "source=github typed issue reads, configured repository allowlist, read-only, request time\nreferences={} read={} unavailable={} refused={} unresolved={} omitted={}\nNote: comments are listed newest first; bodies are excerpts.",
        entries.len(),
        count(|e| matches!(e, Entry::Brief(_) | Entry::Facts(..))),
        count(|e| matches!(e, Entry::Failed(..))),
        count(|e| matches!(e, Entry::NotConfigured(_))),
        count(|e| matches!(e, Entry::Ambiguous(..))),
        count(|e| matches!(e, Entry::Omitted(_))),
    );
    for entry in entries {
        out.push('\n');
        match entry {
            Entry::Brief(brief) => {
                out.push_str(&format!(
                    "issue ref={} status=available state={} updated={}",
                    field(&brief.reference, 120),
                    field(&brief.state, 16),
                    field(&brief.updated_at, 40),
                ));
                if let Some(closed) = &brief.closed_at {
                    out.push_str(&format!(" closed={}", field(closed, 40)));
                }
                out.push_str(&format!(
                    " comments_total={} author={}",
                    brief.comment_count,
                    field(&brief.author, 60)
                ));
                if !brief.labels.is_empty() {
                    out.push_str(" labels=");
                    out.push_str(&field(
                        &brief
                            .labels
                            .iter()
                            .map(|label| field(label, 40))
                            .collect::<Vec<_>>()
                            .join(","),
                        200,
                    ));
                }
                out.push_str("\n  title_untrusted=");
                out.push_str(&field(&brief.title, title_chars));
                out.push_str("\n  url=");
                out.push_str(&field(&brief.url, 200));
                if brief.recent_comments.is_empty() {
                    out.push_str("\n  latest_comments=none");
                }
                for (rank, comment) in brief.recent_comments.iter().rev().enumerate() {
                    out.push_str(&format!(
                        "\n  comment newest_rank={} author={} updated={}",
                        rank + 1,
                        field(&comment.author, 60),
                        field(&comment.updated_at, 40),
                    ));
                    if excerpt_chars > 0 {
                        out.push_str(" excerpt_untrusted=");
                        out.push_str(&field(&comment.body, excerpt_chars));
                    }
                }
            }
            Entry::Facts(key, facts) => {
                out.push_str(&format!("issue ref={} status=available ", field(key, 120)));
                out.push_str(&field(
                    &facts.lines().collect::<Vec<_>>().join(" "),
                    title_chars + excerpt_chars + 200,
                ));
            }
            Entry::Failed(key, error) => {
                let (status, reason) = failure_parts(error);
                out.push_str(&format!(
                    "issue ref={} status={status} reason={reason}",
                    field(key, 120)
                ));
            }
            Entry::NotConfigured(key) => out.push_str(&format!(
                "issue ref={} status=refused reason=repository_not_configured",
                field(key, 120)
            )),
            Entry::Ambiguous(number, candidates) => out.push_str(&format!(
                "issue ref=#{number} status=unresolved reason=repository_ambiguous candidates={}",
                field(&candidates.join(","), 200)
            )),
            Entry::Omitted(key) => out.push_str(&format!(
                "issue ref={} status=omitted reason=per_turn_cap_{MAX_REFERENCED_ISSUES}",
                field(key, 120)
            )),
        }
    }
    out
}

fn failure_parts(error: &str) -> (&'static str, String) {
    let value = |name: &str| {
        error
            .split_whitespace()
            .find_map(|part| part.strip_prefix(name))
            .map(|value| {
                value
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
                    .take(80)
                    .collect::<String>()
            })
            .filter(|value| !value.is_empty())
    };
    let status = match value("status=").as_deref() {
        Some("refused") => "refused",
        _ => "unavailable",
    };
    (
        status,
        value("reason=").unwrap_or_else(|| String::from("github_read_failed")),
    )
}

fn field(value: &str, characters: usize) -> String {
    let collapsed = value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if collapsed.chars().count() <= characters {
        return collapsed;
    }
    let mut kept: String = collapsed
        .chars()
        .take(characters.saturating_sub(1))
        .collect();
    kept.push('…');
    kept
}

fn canonical(locator: &IssueLocator) -> String {
    format!("{}#{}", locator.target(), locator.number())
}

fn parse_repository(value: &str) -> Option<RepoTarget> {
    let (owner, repo) = value.trim().split_once('/')?;
    RepoTarget::parse(owner, repo).ok()
}

fn same_repository(left: &RepoTarget, right: &RepoTarget) -> bool {
    left.to_string().eq_ignore_ascii_case(&right.to_string())
}

fn repository_terms(text: &str) -> impl Iterator<Item = String> + '_ {
    bounded(text)
        .split(|c: char| !c.is_alphanumeric() && c != '-' && c != '_' && c != '.')
        .map(|term| term.trim_matches('.'))
        .filter(|term| !term.is_empty())
        .map(str::to_lowercase)
}

fn bounded(text: &str) -> &str {
    match text.char_indices().nth(MAX_SCANNED_TEXT_CHARS) {
        Some((end, _)) => &text[..end],
        None => text,
    }
}

/// Every issue mention in one text, in order of appearance.
fn scan_mentions(text: &str, catalog: &RepositoryCatalog) -> Vec<Mention> {
    let mut mentions = Vec::new();
    let pieces = bounded(text).split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '<' | '>'
                    | '|'
                    | '('
                    | ')'
                    | '['
                    | ']'
                    | '{'
                    | '}'
                    | '"'
                    | '\''
                    | '`'
                    | '*'
                    | ','
                    | ';'
                    | '!'
                    | '?'
                    | '“'
                    | '”'
                    | '’'
                    | '«'
                    | '»'
            )
    });
    // "owner/repo #12" and "alias #12" name the repository in the word just
    // before the number; remember it for exactly one following piece.
    let mut preceding: Option<RepoTarget> = None;
    for piece in pieces {
        if mentions.len() >= MAX_MENTIONS_PER_TEXT {
            break;
        }
        let piece = piece.trim_end_matches(['.', ':']);
        if piece.is_empty() {
            continue;
        }
        let named = preceding.take();
        if !piece.is_ascii() {
            continue;
        }
        if !piece.contains('#') {
            preceding = if piece.contains('/') {
                parse_repository(piece)
            } else {
                catalog.by_name(piece).cloned()
            };
        }
        if piece.to_ascii_lowercase().contains("github.com") {
            if let Some(locator) = IssueLocator::parse(piece) {
                mentions.push(Mention::Exact(locator.target().clone(), locator.number()));
            }
            continue;
        }
        let Some((prefix, rest)) = piece.split_once('#') else {
            continue;
        };
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() || digits.len() > 9 || rest.len() != digits.len() {
            continue;
        }
        let Some(number) = digits
            .parse::<u32>()
            .ok()
            .and_then(|value| IssueNumber::new(value).ok())
        else {
            continue;
        };
        if prefix.contains('/') {
            if let Some(target) = parse_repository(prefix) {
                mentions.push(Mention::Exact(target, number));
            }
        } else if let (true, Some(target)) = (prefix.is_empty(), named) {
            mentions.push(Mention::Exact(target, number));
        } else if prefix.is_empty()
            || GENERIC_ISSUE_PREFIXES
                .iter()
                .any(|generic| prefix.eq_ignore_ascii_case(generic))
        {
            mentions.push(Mention::Bare(number));
        } else if let Some(target) = catalog.by_name(prefix) {
            mentions.push(Mention::Exact(target.clone(), number));
        }
    }
    mentions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::GitHubContextComment;

    #[test]
    fn a_repository_named_just_before_a_bare_number_owns_it() {
        let catalog = catalog();
        let mentions = scan_mentions(
            "see example-org/alpha-shop #1728 and gamma #31, then #9 alone",
            &catalog,
        );
        assert_eq!(mentions.len(), 3);
        assert!(matches!(&mentions[0], Mention::Exact(target, number)
            if same_repository(target, &parse_repository("example-org/alpha-shop").unwrap()) && number.get() == 1728));
        assert!(matches!(&mentions[1], Mention::Exact(target, number)
            if same_repository(target, &parse_repository("example-user/gamma").unwrap()) && number.get() == 31));
        assert!(matches!(&mentions[2], Mention::Bare(number) if number.get() == 9));
    }

    fn catalog() -> RepositoryCatalog {
        RepositoryCatalog::new(
            &[
                String::from("example-org/alpha"),
                String::from("example-org/alpha-shop"),
                String::from("example-user/gamma"),
            ],
            &[
                (String::from("alpha"), String::from("example-org/alpha")),
                (
                    String::from("alpha-shop"),
                    String::from("example-org/alpha-shop"),
                ),
                (String::from("gamma"), String::from("example-user/gamma")),
                (String::from("stray"), String::from("other/unlisted")),
            ],
        )
    }

    fn keys(selection: &ReferenceSelection) -> Vec<String> {
        selection
            .references
            .iter()
            .map(|reference| match reference {
                IssueReference::Allowlisted(locator) => canonical(locator),
                IssueReference::NotConfigured(key) => format!("refused:{key}"),
                IssueReference::Ambiguous { number, .. } => format!("ambiguous:#{number}"),
            })
            .collect()
    }

    #[test]
    fn urls_shorthand_and_aliases_resolve_against_the_allowlist_only() {
        let selection = select_issue_references(
            &ReferenceSources {
                message: "see <https://github.com/example-org/alpha/issues/12|alpha#12>, \
                          example-user/gamma#7, alpha-shop#3 and other/unlisted#9; stray#4",
                ..ReferenceSources::default()
            },
            &catalog(),
        );
        assert_eq!(
            keys(&selection),
            [
                "example-org/alpha#12",
                "example-user/gamma#7",
                "example-org/alpha-shop#3",
                "refused:other/unlisted#9",
            ]
        );
        assert!(selection.message_names_issues);
    }

    #[test]
    fn bare_numbers_resolve_only_when_unambiguous() {
        let catalog = catalog();
        let ambiguous = select_issue_references(
            &ReferenceSources {
                message: "what about #5?",
                ..ReferenceSources::default()
            },
            &catalog,
        );
        assert_eq!(keys(&ambiguous), ["ambiguous:#5"]);

        let by_alias_word = select_issue_references(
            &ReferenceSources {
                message: "in gamma, is #5 done?",
                ..ReferenceSources::default()
            },
            &catalog,
        );
        assert_eq!(keys(&by_alias_word), ["example-user/gamma#5"]);

        let history = ["alpha#5 is still open"];
        let by_history = select_issue_references(
            &ReferenceSources {
                message: "and #5 now?",
                history_newest_first: &history,
                ..ReferenceSources::default()
            },
            &catalog,
        );
        assert_eq!(keys(&by_history), ["example-org/alpha#5"]);
    }

    #[test]
    fn remembered_references_settle_bare_numbers_and_back_a_bare_followup() {
        let remembered = [
            String::from("example-org/alpha#1119"),
            String::from("example-org/alpha#1114"),
        ];
        let history = ["#1119 and #1114 still open"];
        let selection = select_issue_references(
            &ReferenceSources {
                message: "check who sent latest comments",
                history_newest_first: &history,
                remembered: &remembered,
                ..ReferenceSources::default()
            },
            &catalog(),
        );
        assert_eq!(
            keys(&selection),
            ["example-org/alpha#1119", "example-org/alpha#1114"]
        );
        assert!(!selection.message_names_issues);
        assert!(issue_lookup_requested(
            "check who sent latest comments",
            &selection
        ));
        assert!(!issue_lookup_requested("thanks!", &selection));

        let fallback = select_issue_references(
            &ReferenceSources {
                message: "any new comments?",
                remembered: &remembered,
                ..ReferenceSources::default()
            },
            &catalog(),
        );
        assert_eq!(keys(&fallback).len(), 2);
    }

    #[derive(Default)]
    struct Fake {
        reads: Vec<String>,
    }

    impl GitHubSurface for Fake {
        fn issue_facts(
            &mut self,
            _locator: &IssueLocator,
            _detail: IssueFactDetail,
        ) -> Result<String, String> {
            Err(String::from("status=unavailable reason=unused"))
        }

        fn issue_brief(
            &mut self,
            locator: &IssueLocator,
            recent_comments: usize,
        ) -> Result<GitHubIssueBrief, String> {
            let key = canonical(locator);
            self.reads.push(key.clone());
            if locator.number().get() == 13 {
                return Err(String::from("status=unavailable reason=rate_limited"));
            }
            Ok(GitHubIssueBrief {
                reference: key.clone(),
                url: format!(
                    "https://github.com/{}/issues/{}",
                    locator.target(),
                    locator.number()
                ),
                state: String::from("open"),
                title: "T".repeat(500),
                labels: vec![String::from("bug")],
                author: String::from("reporter"),
                comment_count: 9,
                updated_at: String::from("2026-10-02T09:00:00Z"),
                closed_at: None,
                recent_comments: (0..recent_comments)
                    .map(|index| GitHubContextComment {
                        author: format!("person{index}"),
                        body: "x".repeat(3_000),
                        updated_at: format!("2026-10-0{}T08:00:00Z", index + 1),
                    })
                    .collect(),
            })
        }
    }

    #[test]
    fn reads_are_capped_bounded_and_name_every_failure() {
        let catalog = catalog();
        let message = (10..25)
            .map(|number| format!("alpha#{number}"))
            .collect::<Vec<_>>()
            .join(" ")
            + " other/unlisted#1 #77 (gamma too)";
        let selection = select_issue_references(
            &ReferenceSources {
                message: &message,
                ..ReferenceSources::default()
            },
            &catalog,
        );
        let mut fake = Fake::default();
        let block =
            read_referenced_issues(&mut fake, &selection.references, REFERENCED_ISSUES_BUDGET);
        assert_eq!(fake.reads.len(), MAX_REFERENCED_ISSUES);
        assert!(block.content.chars().count() <= REFERENCED_ISSUES_BUDGET);
        assert!(
            block
                .content
                .contains("issue ref=example-org/alpha#13 status=unavailable reason=rate_limited")
        );
        assert!(block.content.contains(
            "issue ref=other/unlisted#1 status=refused reason=repository_not_configured"
        ));
        assert!(
            block
                .content
                .contains("issue ref=#77 status=unresolved reason=repository_ambiguous")
        );
        assert!(
            block
                .content
                .contains("issue ref=example-org/alpha#24 status=omitted")
        );
        assert!(
            block
                .content
                .contains("comment newest_rank=1 author=person2 updated=2026-10-03T08:00:00Z")
        );
        assert!(!block.content.contains("truncated at budget"));
        assert_eq!(block.read.len(), MAX_REFERENCED_ISSUES - 1);
    }
}
