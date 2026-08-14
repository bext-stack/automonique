// SPDX-License-Identifier: Elastic-2.0

//! The issue body a support thread becomes.
//!
//! One shape, four sections, in this order and no other:
//!
//! ```text
//! ## Attribution
//! ## À faire
//! ## Références fournies   (only when the thread referenced something)
//! ## Derniers échanges
//! ```
//!
//! and, last, the idempotency marker: `<!-- support-thread:<id> -->`. That
//! marker is the whole reason a retry is safe. The legacy bridge finds an
//! existing ticket by searching bodies for it, so a support agent who presses
//! the button twice — or a create that succeeded remotely and failed locally —
//! reuses the ticket instead of opening a second one. It is written last and
//! read back by [`marker_thread_id`], and the round trip is proved rather than
//! assumed.
//!
//! # What is deliberately absent
//!
//! The legacy draft is produced by a heuristic that reads a support transcript
//! and *infers* a checklist — French and English action-verb matching, a
//! before/after "should be" rewriter, a thematic summarizer. None of it is
//! here. [`ChecklistItem`] normalizes items a caller already has, which is the
//! part with a stable contract; inference belongs beside the transcript model
//! and is a later refinement. A caller with nothing to list supplies the
//! legacy's own fallback line rather than getting an empty section.

use crate::ticket::{IssueBodyText, IssueTitle, MAX_TICKET_NAME_BYTES};
use crate::{
    GitHubRefusal, MAX_TIMESTAMP_BYTES, MAX_URL_BYTES, is_body_text, is_line_text,
    is_opaque_identifier,
};

/// The opening of the support-thread idempotency marker.
pub const SUPPORT_THREAD_MARKER_PREFIX: &str = "<!-- support-thread:";
/// The close of the support-thread idempotency marker.
pub const SUPPORT_THREAD_MARKER_SUFFIX: &str = " -->";

/// Longest support thread identifier accepted, matching the legacy bridge's
/// own guard.
pub const MAX_THREAD_ID_BYTES: usize = 160;

/// Most checklist items one draft may carry.
pub const MAX_CHECKLIST_ITEMS: usize = 30;
/// Longest checklist item retained, in characters.
pub const MAX_CHECKLIST_ITEM_CHARS: usize = 300;
/// Shortest checklist item accepted, in characters.
///
/// The legacy guard exists because of a real incident: a two-character value
/// typed while testing a modal replaced an entire inferred checklist.
pub const MIN_CHECKLIST_ITEM_CHARS: usize = 4;
/// Most references one draft may carry.
pub const MAX_TICKET_REFERENCES: usize = 20;
/// Most transcript entries one draft may carry.
pub const MAX_TICKET_EXCHANGES: usize = 8;
/// Longest transcript entry retained.
pub const MAX_EXCHANGE_BYTES: usize = 4_000;

/// A support thread identifier.
///
/// The grammar is the legacy bridge's: letters, digits, `.`, `_`, `:` and `-`.
/// It excludes every byte that would otherwise let a thread id close the HTML
/// comment early — `-->` cannot be spelled without a `>`, and `>` is not in the
/// set — so a marker built from one is always exactly one comment.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ThreadId(String);

impl ThreadId {
    /// Validate one thread identifier.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::ThreadId`] for an empty value, one over
    /// [`MAX_THREAD_ID_BYTES`], or one outside the grammar.
    pub fn new(value: &str) -> Result<Self, GitHubRefusal> {
        if value.is_empty()
            || value.len() > MAX_THREAD_ID_BYTES
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            })
        {
            return Err(GitHubRefusal::ThreadId);
        }
        Ok(Self(value.to_owned()))
    }

    /// The exact identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The exact marker this thread writes into an issue body.
    #[must_use]
    pub fn marker(&self) -> String {
        format!(
            "{SUPPORT_THREAD_MARKER_PREFIX}{}{SUPPORT_THREAD_MARKER_SUFFIX}",
            self.0
        )
    }
}

/// Read the support thread id an issue body was created for.
///
/// The first marker wins: a body carrying two is a body two threads have
/// claimed, and reading the first is what the legacy `includes` search does.
#[must_use]
pub fn marker_thread_id(body: &str) -> Option<ThreadId> {
    let start = body.find(SUPPORT_THREAD_MARKER_PREFIX)? + SUPPORT_THREAD_MARKER_PREFIX.len();
    let rest = &body[start..];
    let end = rest.find(SUPPORT_THREAD_MARKER_SUFFIX)?;
    ThreadId::new(&rest[..end]).ok()
}

/// Whether an issue body was created for this support thread.
///
/// The idempotency question, asked exactly the way the legacy bridge asks it.
#[must_use]
pub fn body_carries_marker(body: &str, thread_id: &ThreadId) -> bool {
    body.contains(&thread_id.marker())
}

/// One line of the `## À faire` checklist.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChecklistItem(String);

impl ChecklistItem {
    /// Normalize one item.
    ///
    /// A leading bullet or `[ ]`/`[x]` box is stripped so an item that already
    /// looks like a checklist line does not become `- [ ] - [ ] …`; interior
    /// whitespace is collapsed; the result is cut to
    /// [`MAX_CHECKLIST_ITEM_CHARS`] characters on a character boundary.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Checklist`] for an item shorter than
    /// [`MIN_CHECKLIST_ITEM_CHARS`] characters after normalizing, or one
    /// carrying a control character.
    pub fn new(value: &str) -> Result<Self, GitHubRefusal> {
        if value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        {
            return Err(GitHubRefusal::Checklist);
        }
        let mut text = String::new();
        let mut characters = 0;
        let mut pending_space = false;
        for character in strip_bullet(value).chars() {
            if characters >= MAX_CHECKLIST_ITEM_CHARS {
                break;
            }
            if character.is_whitespace() {
                pending_space = !text.is_empty();
                continue;
            }
            if pending_space {
                text.push(' ');
                characters += 1;
                pending_space = false;
                if characters >= MAX_CHECKLIST_ITEM_CHARS {
                    break;
                }
            }
            text.push(character);
            characters += 1;
        }
        if characters < MIN_CHECKLIST_ITEM_CHARS {
            return Err(GitHubRefusal::Checklist);
        }
        Ok(Self(text))
    }

    /// The normalized item.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Strip one leading bullet and one leading checkbox, in that order.
fn strip_bullet(value: &str) -> &str {
    let value = value.trim_start();
    let value = value
        .strip_prefix("- ")
        .or_else(|| value.strip_prefix("* "))
        .or_else(|| value.strip_prefix('-'))
        .or_else(|| value.strip_prefix('*'))
        .unwrap_or(value)
        .trim_start();
    for box_form in ["[ ]", "[x]", "[X]"] {
        if let Some(rest) = value.strip_prefix(box_form) {
            return rest.trim_start();
        }
    }
    value
}

/// The `## Attribution` block: who asked, for which client, through what.
///
/// Every field but the channel is optional, and an absent field renders no
/// line at all — the legacy block is built by filtering empties, and a ticket
/// with `- **Email du demandeur :**` and nothing after it tells a reader
/// something false.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attribution {
    site_label: Option<String>,
    site_host: Option<String>,
    requested_by: Option<String>,
    tenant_name: Option<String>,
    requester_email: Option<String>,
    requester_phone: Option<String>,
    channel: String,
    received_at: Option<String>,
    site_id: Option<String>,
    conversation_url: Option<String>,
}

impl Attribution {
    /// Start a block for one intake channel.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for a channel outside its bound.
    pub fn new(channel: &str) -> Result<Self, GitHubRefusal> {
        let channel = channel.trim();
        if !is_line_text(channel, MAX_TICKET_NAME_BYTES) {
            return Err(GitHubRefusal::Text);
        }
        Ok(Self {
            site_label: None,
            site_host: None,
            requested_by: None,
            tenant_name: None,
            requester_email: None,
            requester_phone: None,
            channel: channel.to_owned(),
            received_at: None,
            site_id: None,
            conversation_url: None,
        })
    }

    /// Name the client site, and optionally the host it is served from.
    ///
    /// The host is normalized the way the legacy console normalizes it: lower
    /// case, no scheme, no `www.`, no port, no path.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for a label or host outside its bound.
    pub fn with_site(mut self, label: &str, host: Option<&str>) -> Result<Self, GitHubRefusal> {
        let label = label.trim();
        if !is_line_text(label, MAX_TICKET_NAME_BYTES) {
            return Err(GitHubRefusal::Text);
        }
        self.site_label = Some(label.to_owned());
        self.site_host = match host.map(clean_host) {
            None => None,
            Some(host) if host.is_empty() => None,
            Some(host) if is_line_text(&host, MAX_TICKET_NAME_BYTES) => Some(host),
            Some(_) => return Err(GitHubRefusal::Text),
        };
        Ok(self)
    }

    /// Name the person who transmitted the request.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for a name outside its bound.
    pub fn with_requested_by(mut self, name: &str) -> Result<Self, GitHubRefusal> {
        self.requested_by = Some(bounded_line(name, MAX_TICKET_NAME_BYTES)?);
        Ok(self)
    }

    /// Name the support tenant the request came through.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for a name outside its bound.
    pub fn with_tenant(mut self, name: &str) -> Result<Self, GitHubRefusal> {
        self.tenant_name = Some(bounded_line(name, MAX_TICKET_NAME_BYTES)?);
        Ok(self)
    }

    /// Record how to reach the requester.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for a value outside its bound.
    pub fn with_contact(
        mut self,
        email: Option<&str>,
        phone: Option<&str>,
    ) -> Result<Self, GitHubRefusal> {
        self.requester_email = email
            .map(|value| bounded_line(value, MAX_TICKET_NAME_BYTES))
            .transpose()?;
        self.requester_phone = phone
            .map(|value| bounded_line(value, MAX_TICKET_NAME_BYTES))
            .transpose()?;
        Ok(self)
    }

    /// Record when the request arrived.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for a timestamp outside its bound.
    pub fn with_received_at(mut self, at: &str) -> Result<Self, GitHubRefusal> {
        self.received_at = Some(bounded_line(at, MAX_TIMESTAMP_BYTES)?);
        Ok(self)
    }

    /// Record the stable site identifier.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for an identifier outside its bound.
    pub fn with_site_id(mut self, site_id: &str) -> Result<Self, GitHubRefusal> {
        let site_id = site_id.trim();
        if !is_opaque_identifier(site_id, MAX_TICKET_NAME_BYTES) {
            return Err(GitHubRefusal::Text);
        }
        self.site_id = Some(site_id.to_owned());
        Ok(self)
    }

    /// Link back to the conversation this ticket came from.
    ///
    /// The URL is supplied by the caller rather than composed here: the
    /// conversation lives on whichever support surface the deployment runs, and
    /// a connector that hard-codes one host is a connector that lies on every
    /// other deployment.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for anything that is not a bounded
    /// `http`/`https` URL.
    pub fn with_conversation_url(mut self, url: &str) -> Result<Self, GitHubRefusal> {
        self.conversation_url = Some(reference_url(url)?);
        Ok(self)
    }

    /// Render the block, one bullet per present field.
    #[must_use]
    pub fn render(&self) -> String {
        let mut lines: Vec<String> = Vec::new();
        if let Some(label) = &self.site_label {
            let host = self
                .site_host
                .as_ref()
                .map_or_else(String::new, |host| format!(" · https://{host}/"));
            lines.push(format!("- **Client / site concerné :** {label}{host}"));
        }
        if let Some(name) = &self.requested_by {
            lines.push(format!("- **Demande transmise par :** {name}"));
        }
        if let Some(tenant) = &self.tenant_name {
            lines.push(format!("- **Agence / locataire support :** {tenant}"));
        }
        if let Some(email) = &self.requester_email {
            lines.push(format!("- **Email du demandeur :** {email}"));
        }
        if let Some(phone) = &self.requester_phone {
            lines.push(format!("- Téléphone : {phone}"));
        }
        lines.push(format!("- **Canal :** {}", self.channel));
        if let Some(at) = &self.received_at {
            lines.push(format!("- **Reçue le :** {at}"));
        }
        if let Some(site_id) = &self.site_id {
            lines.push(format!("- **Identifiant du site :** {site_id}"));
        }
        if let Some(url) = &self.conversation_url {
            lines.push(format!("- **Conversation source :** {url}"));
        }
        lines.join("\n")
    }
}

/// One entry of the `## Derniers échanges` transcript.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketExchange {
    speaker: String,
    at: String,
    text: String,
}

impl TicketExchange {
    /// Record one message of the conversation.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for a speaker or timestamp outside its
    /// bound, and for text that is empty or over [`MAX_EXCHANGE_BYTES`].
    pub fn new(speaker: &str, at: &str, text: &str) -> Result<Self, GitHubRefusal> {
        let text = text.trim();
        if !is_body_text(text, MAX_EXCHANGE_BYTES) {
            return Err(GitHubRefusal::Text);
        }
        Ok(Self {
            speaker: bounded_line(speaker, MAX_TICKET_NAME_BYTES)?,
            at: bounded_line(at, MAX_TIMESTAMP_BYTES)?,
            text: text.to_owned(),
        })
    }

    /// Render the entry: a bold speaker, the timestamp, and the message as a
    /// Markdown quote.
    ///
    /// Quoting matters beyond style — an unquoted client message containing
    /// `## Derniers échanges` would otherwise forge a section heading in the
    /// rendered ticket.
    #[must_use]
    pub fn render(&self) -> String {
        let quoted: Vec<String> = self
            .text
            .split('\n')
            .map(|line| format!("> {}", line.trim_end_matches('\r')))
            .collect();
        format!(
            "**{}** · {}\n\n{}",
            self.speaker,
            self.at,
            quoted.join("\n")
        )
    }
}

/// A complete issue body, ready to be rendered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TicketDraft {
    title: IssueTitle,
    attribution: Attribution,
    checklist: Vec<ChecklistItem>,
    references: Vec<String>,
    exchanges: Vec<TicketExchange>,
    thread_id: Option<ThreadId>,
}

impl TicketDraft {
    /// Start a draft from a title, an attribution block and a checklist.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Checklist`] for an empty checklist or one over
    /// [`MAX_CHECKLIST_ITEMS`] items. An empty checklist is refused because the
    /// section is not optional: a ticket whose `## À faire` is blank reads as
    /// "nothing to do".
    pub fn new(
        title: IssueTitle,
        attribution: Attribution,
        checklist: Vec<ChecklistItem>,
    ) -> Result<Self, GitHubRefusal> {
        if checklist.is_empty() || checklist.len() > MAX_CHECKLIST_ITEMS {
            return Err(GitHubRefusal::Checklist);
        }
        Ok(Self {
            title,
            attribution,
            checklist,
            references: Vec::new(),
            exchanges: Vec::new(),
            thread_id: None,
        })
    }

    /// Carry the URLs the conversation referenced.
    ///
    /// Duplicates are dropped, in first-seen order, matching the legacy
    /// collector.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for a URL outside its bound or over
    /// [`MAX_TICKET_REFERENCES`] of them.
    pub fn with_references(mut self, references: &[&str]) -> Result<Self, GitHubRefusal> {
        if references.len() > MAX_TICKET_REFERENCES {
            return Err(GitHubRefusal::Text);
        }
        let mut kept: Vec<String> = Vec::with_capacity(references.len());
        for reference in references {
            let url = reference_url(reference)?;
            if !kept.contains(&url) {
                kept.push(url);
            }
        }
        self.references = kept;
        Ok(self)
    }

    /// Carry the last messages of the conversation.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Text`] for more than [`MAX_TICKET_EXCHANGES`]
    /// entries.
    pub fn with_exchanges(mut self, exchanges: Vec<TicketExchange>) -> Result<Self, GitHubRefusal> {
        if exchanges.len() > MAX_TICKET_EXCHANGES {
            return Err(GitHubRefusal::Text);
        }
        self.exchanges = exchanges;
        Ok(self)
    }

    /// Stamp the body with the support thread it came from.
    #[must_use]
    pub fn with_thread(mut self, thread_id: ThreadId) -> Self {
        self.thread_id = Some(thread_id);
        self
    }

    /// The title this draft would file under.
    #[must_use]
    pub const fn title(&self) -> &IssueTitle {
        &self.title
    }

    /// The support thread this draft is stamped with, when it is stamped.
    #[must_use]
    pub const fn thread_id(&self) -> Option<&ThreadId> {
        self.thread_id.as_ref()
    }

    /// Render the exact issue body.
    ///
    /// Sections are separated by a blank line, and the marker — when there is
    /// one — is the last thing in the body, so a body that was truncated
    /// upstream is a body whose marker is visibly gone rather than one that
    /// silently no longer matches.
    ///
    /// # Errors
    ///
    /// Returns [`GitHubRefusal::Body`] when the rendered body is over
    /// [`crate::MAX_ISSUE_BODY_BYTES`].
    pub fn render_body(&self) -> Result<IssueBodyText, GitHubRefusal> {
        let mut sections: Vec<String> = Vec::with_capacity(8);
        sections.push("## Attribution".to_owned());
        sections.push(self.attribution.render());
        sections.push("## À faire".to_owned());
        sections.push(
            self.checklist
                .iter()
                .map(|item| format!("- [ ] {}", item.as_str()))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        if !self.references.is_empty() {
            sections.push("## Références fournies".to_owned());
            sections.push(
                self.references
                    .iter()
                    .map(|url| format!("- {url}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
        }
        sections.push("## Derniers échanges".to_owned());
        sections.push(if self.exchanges.is_empty() {
            "_Aucun échange disponible._".to_owned()
        } else {
            self.exchanges
                .iter()
                .map(TicketExchange::render)
                .collect::<Vec<_>>()
                .join("\n\n")
        });
        if let Some(thread_id) = &self.thread_id {
            sections.push(thread_id.marker());
        }
        IssueBodyText::new(&sections.join("\n\n"))
    }
}

/// Trim, bound and refuse a single-line field.
fn bounded_line(value: &str, max_bytes: usize) -> Result<String, GitHubRefusal> {
    let value = value.trim();
    if is_line_text(value, max_bytes) {
        Ok(value.to_owned())
    } else {
        Err(GitHubRefusal::Text)
    }
}

/// Validate one referenced URL.
fn reference_url(value: &str) -> Result<String, GitHubRefusal> {
    let value = value.trim();
    if value.len() > MAX_URL_BYTES
        || !(value.starts_with("https://") || value.starts_with("http://"))
        || value.chars().any(|character| {
            character.is_control() || character.is_whitespace() || character == ')'
        })
    {
        return Err(GitHubRefusal::Text);
    }
    Ok(value.to_owned())
}

/// Reduce a configured host to the bare name the legacy console renders.
fn clean_host(value: &str) -> String {
    let value = value.trim().to_lowercase();
    let value = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .unwrap_or(&value);
    let value = value.strip_prefix("www.").unwrap_or(value);
    let value = value.split(['/', '?', '#']).next().unwrap_or_default();
    value.split(':').next().unwrap_or_default().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const THREAD: &str = "thr_2026-08-13.01";

    fn attribution() -> Attribution {
        Attribution::new("email")
            .expect("channel")
            .with_site("Milo Paris", Some("https://WWW.Milo.invalid:443/contact"))
            .expect("site")
            .with_requested_by("Claire Martin")
            .expect("requested by")
            .with_tenant("Boulangerie Milo")
            .expect("tenant")
            .with_contact(Some("claire@exemple.invalid"), Some("+33 1 00 00 00 00"))
            .expect("contact")
            .with_received_at("2026-08-13T09:12:00.000Z")
            .expect("received at")
            .with_site_id("site-1")
            .expect("site id")
            .with_conversation_url("https://support.exemple.invalid/?thread=thr_1")
            .expect("conversation")
    }

    fn draft() -> TicketDraft {
        TicketDraft::new(
            IssueTitle::new("Milo Paris · Panne de paiement").expect("title"),
            attribution(),
            vec![
                ChecklistItem::new("- [ ] Corriger le formulaire de paiement").expect("item"),
                ChecklistItem::new("Vérifier le résultat sur Milo Paris").expect("item"),
            ],
        )
        .expect("draft")
    }

    #[test]
    fn a_body_carries_the_four_sections_in_order_and_the_marker_last() {
        let body = draft()
            .with_references(&["https://milo.invalid/panier"])
            .expect("references")
            .with_exchanges(vec![
                TicketExchange::new(
                    "Claire",
                    "2026-08-13T09:12:00.000Z",
                    "Bonjour,\nle paiement echoue.",
                )
                .expect("exchange"),
            ])
            .expect("exchanges")
            .with_thread(ThreadId::new(THREAD).expect("thread"))
            .render_body()
            .expect("body");

        assert_eq!(
            body.as_str(),
            "## Attribution\n\n\
             - **Client / site concerné :** Milo Paris · https://milo.invalid/\n\
             - **Demande transmise par :** Claire Martin\n\
             - **Agence / locataire support :** Boulangerie Milo\n\
             - **Email du demandeur :** claire@exemple.invalid\n\
             - Téléphone : +33 1 00 00 00 00\n\
             - **Canal :** email\n\
             - **Reçue le :** 2026-08-13T09:12:00.000Z\n\
             - **Identifiant du site :** site-1\n\
             - **Conversation source :** https://support.exemple.invalid/?thread=thr_1\n\n\
             ## À faire\n\n\
             - [ ] Corriger le formulaire de paiement\n\
             - [ ] Vérifier le résultat sur Milo Paris\n\n\
             ## Références fournies\n\n\
             - https://milo.invalid/panier\n\n\
             ## Derniers échanges\n\n\
             **Claire** · 2026-08-13T09:12:00.000Z\n\n\
             > Bonjour,\n\
             > le paiement echoue.\n\n\
             <!-- support-thread:thr_2026-08-13.01 -->"
        );
    }

    #[test]
    fn the_marker_round_trips_and_is_how_a_retry_finds_its_ticket() {
        let thread = ThreadId::new(THREAD).expect("thread");
        let body = draft()
            .with_thread(thread.clone())
            .render_body()
            .expect("body");

        assert_eq!(thread.marker(), "<!-- support-thread:thr_2026-08-13.01 -->");
        assert!(body.as_str().ends_with(&thread.marker()));
        assert!(body_carries_marker(body.as_str(), &thread));
        assert_eq!(marker_thread_id(body.as_str()).as_ref(), Some(&thread));

        // A different thread does not match the same body.
        let other = ThreadId::new("thr_other").expect("thread");
        assert!(!body_carries_marker(body.as_str(), &other));

        // An unstamped body carries no marker at all.
        let unstamped = draft().render_body().expect("body");
        assert_eq!(marker_thread_id(unstamped.as_str()), None);
        assert!(!body_carries_marker(unstamped.as_str(), &thread));
    }

    #[test]
    fn a_marker_is_read_back_only_from_a_well_formed_comment() {
        assert_eq!(
            marker_thread_id("texte <!-- support-thread:abc --> suite")
                .as_ref()
                .map(ThreadId::as_str),
            Some("abc")
        );
        // The first marker wins when a body carries two.
        assert_eq!(
            marker_thread_id("<!-- support-thread:un --><!-- support-thread:deux -->")
                .as_ref()
                .map(ThreadId::as_str),
            Some("un")
        );
        for absent in [
            "",
            "aucun marqueur",
            "<!-- support-thread:abc",
            "<!-- support-thread: -->",
            "<!-- support-thread:with space -->",
            "<!-- other-thread:abc -->",
        ] {
            assert_eq!(marker_thread_id(absent), None, "must not read {absent:?}");
        }
    }

    #[test]
    fn a_thread_id_can_never_close_the_comment_it_is_written_into() {
        for hostile in [
            "",
            "a b",
            "a-->b",
            "a>b",
            "a<b",
            "accentue\u{301}",
            "a\nb",
            &"t".repeat(MAX_THREAD_ID_BYTES + 1),
        ] {
            assert_eq!(
                ThreadId::new(hostile).err(),
                Some(GitHubRefusal::ThreadId),
                "must refuse {hostile:?}"
            );
        }
        assert!(ThreadId::new(&"t".repeat(MAX_THREAD_ID_BYTES)).is_ok());
        assert!(ThreadId::new("A-z.0_9:x").is_ok());
    }

    #[test]
    fn a_checklist_item_is_normalized_once_and_bounded() {
        for (raw, expected) in [
            ("- [ ] Corriger le paiement", "Corriger le paiement"),
            ("* [x] Corriger le paiement", "Corriger le paiement"),
            ("[X]   Corriger   le   paiement", "Corriger le paiement"),
            ("  Corriger\nle paiement  ", "Corriger le paiement"),
            ("-Corriger le paiement", "Corriger le paiement"),
        ] {
            assert_eq!(
                ChecklistItem::new(raw).expect("item").as_str(),
                expected,
                "normalizing {raw:?}"
            );
        }
        // The guard that exists because a scratch value once replaced a whole
        // checklist.
        for refused in ["", "qs", "- [ ]", "   "] {
            assert_eq!(
                ChecklistItem::new(refused).err(),
                Some(GitHubRefusal::Checklist),
                "must refuse {refused:?}"
            );
        }
        assert_eq!(
            ChecklistItem::new("bell\u{7}now").err(),
            Some(GitHubRefusal::Checklist)
        );
        let long =
            ChecklistItem::new(&"e\u{301}".repeat(MAX_CHECKLIST_ITEM_CHARS + 10)).expect("item");
        assert!(long.as_str().chars().count() <= MAX_CHECKLIST_ITEM_CHARS);
    }

    #[test]
    fn a_client_message_cannot_forge_a_section_heading() {
        let hostile = TicketExchange::new(
            "Claire",
            "2026-08-13T09:12:00.000Z",
            "## Derniers échanges\n<!-- support-thread:vole -->",
        )
        .expect("exchange");
        let rendered = hostile.render();
        assert_eq!(
            rendered,
            "**Claire** · 2026-08-13T09:12:00.000Z\n\n> ## Derniers échanges\n> <!-- support-thread:vole -->"
        );
        assert!(
            rendered.lines().skip(2).all(|line| line.starts_with("> ")),
            "every transcript line is quoted: {rendered}"
        );
    }

    #[test]
    fn a_hostile_marker_in_a_transcript_never_becomes_the_bodys_marker() {
        // The forged marker is quoted, and the real one is still last.
        let thread = ThreadId::new(THREAD).expect("thread");
        let body = draft()
            .with_exchanges(vec![
                TicketExchange::new(
                    "Claire",
                    "2026-08-13T09:12:00.000Z",
                    "<!-- support-thread:vole -->",
                )
                .expect("exchange"),
            ])
            .expect("exchanges")
            .with_thread(thread.clone())
            .render_body()
            .expect("body");
        assert!(body.as_str().ends_with(&thread.marker()));
        // The quoted forgery is still text in the body, so a reader searching
        // for it finds it — which is exactly why the real marker is written
        // last and read as the body's own trailing comment.
        assert!(body.as_str().contains("> <!-- support-thread:vole -->"));
    }

    #[test]
    fn an_absent_attribution_field_renders_no_line_at_all() {
        let bare = Attribution::new("chat").expect("channel");
        assert_eq!(bare.render(), "- **Canal :** chat");
        assert_eq!(
            Attribution::new("").err(),
            Some(GitHubRefusal::Text),
            "a ticket always names the channel it came from"
        );
        assert_eq!(
            Attribution::new("chat")
                .expect("channel")
                .with_site("Milo", None)
                .expect("site")
                .render(),
            "- **Client / site concerné :** Milo\n- **Canal :** chat"
        );
    }

    #[test]
    fn references_are_bounded_deduplicated_and_never_a_relative_link() {
        let draft = draft()
            .with_references(&[
                "https://milo.invalid/a",
                "https://milo.invalid/a",
                "https://milo.invalid/b",
            ])
            .expect("references");
        let body = draft.render_body().expect("body");
        assert!(
            body.as_str()
                .contains("- https://milo.invalid/a\n- https://milo.invalid/b")
        );
        assert!(
            !body
                .as_str()
                .contains("- https://milo.invalid/a\n- https://milo.invalid/a")
        );

        for refused in ["", "milo.invalid/a", "javascript:alert(1)", "https://a b"] {
            assert_eq!(
                draft.clone().with_references(&[refused]).err(),
                Some(GitHubRefusal::Text),
                "must refuse reference {refused:?}"
            );
        }
        let many: Vec<&str> = (0..=MAX_TICKET_REFERENCES)
            .map(|_| "https://milo.invalid/a")
            .collect();
        assert_eq!(
            draft.clone().with_references(&many).err(),
            Some(GitHubRefusal::Text)
        );
    }

    #[test]
    fn an_empty_or_over_long_checklist_is_refused() {
        assert_eq!(
            TicketDraft::new(
                IssueTitle::new("Titre").expect("title"),
                attribution(),
                Vec::new()
            )
            .err(),
            Some(GitHubRefusal::Checklist)
        );
        let many: Vec<ChecklistItem> = (0..=MAX_CHECKLIST_ITEMS)
            .map(|index| ChecklistItem::new(&format!("tache numero {index}")).expect("item"))
            .collect();
        assert_eq!(
            TicketDraft::new(
                IssueTitle::new("Titre").expect("title"),
                attribution(),
                many
            )
            .err(),
            Some(GitHubRefusal::Checklist)
        );
    }

    #[test]
    fn an_empty_transcript_says_so_rather_than_leaving_a_blank_section() {
        let body = draft().render_body().expect("body");
        assert!(
            body.as_str()
                .ends_with("## Derniers échanges\n\n_Aucun échange disponible._")
        );
        assert_eq!(draft().title().as_str(), "Milo Paris · Panne de paiement");
        assert!(draft().thread_id().is_none());
    }

    #[test]
    fn a_host_is_reduced_to_the_bare_name() {
        for (raw, expected) in [
            ("https://WWW.Milo.invalid:443/contact", "milo.invalid"),
            ("http://milo.invalid", "milo.invalid"),
            ("Milo.Invalid/", "milo.invalid"),
            ("milo.invalid?a=1", "milo.invalid"),
            ("", ""),
        ] {
            assert_eq!(clean_host(raw), expected, "cleaning {raw:?}");
        }
    }
}
