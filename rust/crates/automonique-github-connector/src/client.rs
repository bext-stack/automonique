// SPDX-License-Identifier: Elastic-2.0

//! The synchronous GitHub client.
//!
//! One origin, sixteen operations. The client is the composition of
//! [`GitHubOperation`]'s rendering and the `decode_*` functions around a single
//! bounded HTTP call — it adds no field to a request and repairs no field in a
//! response, so everything it can send or accept is already provable without a
//! socket.
//!
//! The ureq agent mirrors `FleetClient` and `TelegramHttpsClient`: pinned
//! WebPKI roots, no environment proxy, no redirects, a header-size ceiling, and
//! statuses surfaced as values rather than errors. `https_only` is relaxed only
//! for a [`GitHubBase`] that proved itself the plaintext-loopback shape, which
//! is how the hermetic tests reach an in-process fake without a certificate.
//!
//! # Why redirects are refused rather than followed
//!
//! The credential is bound to one origin. A redirect is an instruction to send
//! the next request somewhere else, and a client that follows one has handed
//! the decision about where its token goes to the response it just received.

use std::fmt;
use std::time::Duration;

use automonique_connector_substrate::http::{map_ureq_error, read_bounded_body};
use ureq::tls::{RootCerts, TlsConfig};

use crate::request::HttpMethod;
use crate::response::{
    CommentRef, GitHubComment, GitHubIssue, GitHubReply, GitHubRepository, GitHubWorkflowRun,
    IssueListPage, IssueSearchPage, Viewer, decode_comment, decode_comment_ref, decode_comments,
    decode_error_message, decode_issue, decode_issue_list, decode_issue_ref, decode_labels,
    decode_repository, decode_repository_labels, decode_search, decode_viewer, decode_workflow_run,
};
use crate::{
    CommentRequest, CreateIssueRequest, EntityTag, GITHUB_REQUEST_TIMEOUT_SECONDS,
    GetCommentsRequest, GetIssueCommentRequest, GetIssueRequest, GetRepositoryRequest,
    GetWorkflowRunRequest, GitHubBase, GitHubFailure, GitHubOperation, GitHubOutcome,
    GitHubRejection, GitHubToken, ListIssuesRequest, ListLabelsRequest, MAX_GITHUB_RESPONSE_BYTES,
    ManagementReceipt, ManagementRequest, RateLimit, ReplaceLabelsRequest, RerunWorkflowRequest,
    SearchIssuesRequest, SetStateRequest, UpdateIssueBodyRequest, UpdateIssueCommentRequest,
    Versioned,
};

/// The API version every request pins.
///
/// GitHub versions its REST API by date and reserves the right to change
/// behaviour for a client that does not pin one. This is the version the
/// contract was read against.
pub const GITHUB_API_VERSION: &str = "2026-03-10";

/// The media type every request asks for.
pub const GITHUB_ACCEPT: &str = "application/vnd.github+json";

/// How this connector identifies itself.
///
/// GitHub requires a `User-Agent` naming the application. The legacy client
/// sends the name of the console it is part of; this is a different program and
/// says so, because a shared user agent makes two applications' traffic
/// indistinguishable in an audit log.
pub const GITHUB_USER_AGENT: &str = "automonique-github-connector";

const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

/// The workspace caps the `log` facade at Debug because ureq redacts request
/// metadata at Debug and reveals more at Trace. Rebuilding with Trace enabled
/// is intentionally unsupported, and this assertion is what says so.
const _: () = assert!((log::STATIC_MAX_LEVEL as usize) <= (log::LevelFilter::Debug as usize));

/// A synchronous client for one GitHub origin and one credential.
pub struct GitHubClient {
    agent: ureq::Agent,
    base: GitHubBase,
    token: GitHubToken,
    timeout: Duration,
}

impl GitHubClient {
    /// Bind one origin and one credential.
    ///
    /// The request budget is [`GITHUB_REQUEST_TIMEOUT_SECONDS`].
    #[must_use]
    pub fn new(base: GitHubBase, token: GitHubToken) -> Self {
        Self::with_request_timeout(
            base,
            token,
            Duration::from_secs(GITHUB_REQUEST_TIMEOUT_SECONDS),
        )
    }

    /// Bind a client with a *tighter* request budget.
    ///
    /// The budget is clamped to [`GITHUB_REQUEST_TIMEOUT_SECONDS`], so a caller
    /// may only shorten it, never extend it: a host that is talked into asking
    /// for an hour still gets eight seconds. A zero budget is read as "the
    /// ceiling" rather than "no wait at all", because a zero-length deadline is
    /// never what a caller means.
    #[must_use]
    pub fn with_request_timeout(base: GitHubBase, token: GitHubToken, timeout: Duration) -> Self {
        let ceiling = Duration::from_secs(GITHUB_REQUEST_TIMEOUT_SECONDS);
        let timeout = if timeout.is_zero() {
            ceiling
        } else {
            timeout.min(ceiling)
        };
        let tls = TlsConfig::builder().root_certs(RootCerts::WebPki).build();
        let config = ureq::Agent::config_builder()
            .https_only(!base.is_plaintext_loopback())
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .max_response_header_size(MAX_RESPONSE_HEADER_BYTES)
            .user_agent(GITHUB_USER_AGENT)
            .tls_config(tls)
            .build();
        Self {
            agent: config.new_agent(),
            base,
            token,
            timeout,
        }
    }

    /// The origin this client is locked to.
    #[must_use]
    pub const fn base(&self) -> &GitHubBase {
        &self.base
    }

    /// The whole-call budget this client issues requests with.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.timeout
    }

    /// The exact URL an operation would address, without addressing it.
    #[must_use]
    pub fn endpoint(&self, operation: &GitHubOperation) -> String {
        format!("{}{}", self.base.origin(), operation.path())
    }

    /// Open one issue. An externally visible effect: call it only from a
    /// confirmed-action path.
    ///
    /// # Errors
    ///
    /// Returns the closed [`GitHubFailure`] vocabulary for a transport problem
    /// or a response that is not this operation's contract. GitHub's own
    /// refusal is an `Ok` reply carrying a [`GitHubRejection`].
    pub fn create_issue(
        &self,
        request: &CreateIssueRequest,
    ) -> Result<GitHubReply<GitHubIssue>, GitHubFailure> {
        self.call(&GitHubOperation::CreateIssue(request.clone()), |bytes| {
            decode_issue_ref(bytes)
        })
    }

    /// Add one comment. An externally visible effect.
    ///
    /// # Errors
    ///
    /// As [`GitHubClient::create_issue`], for this operation's contract.
    pub fn comment(
        &self,
        request: &CommentRequest,
    ) -> Result<GitHubReply<CommentRef>, GitHubFailure> {
        self.call(
            &GitHubOperation::Comment(request.clone()),
            decode_comment_ref,
        )
    }

    /// Open or close one issue. An externally visible effect.
    ///
    /// # Errors
    ///
    /// As [`GitHubClient::create_issue`], for this operation's contract.
    pub fn set_state(
        &self,
        request: &SetStateRequest,
    ) -> Result<GitHubReply<GitHubIssue>, GitHubFailure> {
        self.call(&GitHubOperation::SetState(request.clone()), |bytes| {
            decode_issue_ref(bytes)
        })
    }

    /// Replace *every* label on one issue. An externally visible effect.
    ///
    /// # Errors
    ///
    /// As [`GitHubClient::create_issue`], for this operation's contract.
    pub fn replace_labels(
        &self,
        request: &ReplaceLabelsRequest,
    ) -> Result<GitHubReply<Vec<String>>, GitHubFailure> {
        self.call(
            &GitHubOperation::ReplaceLabels(request.clone()),
            decode_labels,
        )
    }

    /// Read one issue back.
    ///
    /// # Errors
    ///
    /// As [`GitHubClient::create_issue`], for this operation's contract.
    pub fn get_issue(
        &self,
        request: &GetIssueRequest,
    ) -> Result<GitHubReply<GitHubIssue>, GitHubFailure> {
        self.call(&GitHubOperation::GetIssue(request.clone()), decode_issue)
    }

    /// Read one issue and retain its entity tag for a conditional body update.
    ///
    /// # Errors
    ///
    /// As [`GitHubClient::get_issue`], plus [`GitHubFailure::MissingField`] if
    /// an accepted response has no `ETag`, or
    /// [`GitHubFailure::FieldOutOfBounds`] if that header is malformed.
    pub fn get_issue_versioned(
        &self,
        request: &GetIssueRequest,
    ) -> Result<GitHubReply<Versioned<GitHubIssue>>, GitHubFailure> {
        self.call_versioned(&GitHubOperation::GetIssue(request.clone()), decode_issue)
    }

    /// Read one page of an issue's comments.
    ///
    /// # Errors
    ///
    /// As [`GitHubClient::create_issue`], for this operation's contract.
    pub fn get_comments(
        &self,
        request: &GetCommentsRequest,
    ) -> Result<GitHubReply<Vec<GitHubComment>>, GitHubFailure> {
        let per_page = request.page().per_page();
        self.call(&GitHubOperation::GetComments(request.clone()), |bytes| {
            decode_comments(bytes, per_page)
        })
    }

    /// Read one issue comment and retain its entity tag for a conditional edit.
    ///
    /// # Errors
    ///
    /// As [`GitHubClient::get_issue_versioned`].
    pub fn get_issue_comment(
        &self,
        request: &GetIssueCommentRequest,
    ) -> Result<GitHubReply<Versioned<GitHubComment>>, GitHubFailure> {
        self.call_versioned(
            &GitHubOperation::GetIssueComment(request.clone()),
            decode_comment,
        )
    }

    /// Replace one issue body only if its entity tag still matches.
    ///
    /// A `412 Precondition Failed` is returned as a rejected reply, allowing
    /// the caller to re-read and reconcile rather than overwriting a concurrent
    /// human edit.
    ///
    /// # Errors
    ///
    /// As [`GitHubClient::get_issue_versioned`].
    pub fn update_issue_body(
        &self,
        request: &UpdateIssueBodyRequest,
    ) -> Result<GitHubReply<Versioned<GitHubIssue>>, GitHubFailure> {
        self.call_versioned(
            &GitHubOperation::UpdateIssueBody(request.clone()),
            decode_issue,
        )
    }

    /// Replace one issue-comment body only if its entity tag still matches.
    ///
    /// # Errors
    ///
    /// As [`GitHubClient::update_issue_body`].
    pub fn update_issue_comment(
        &self,
        request: &UpdateIssueCommentRequest,
    ) -> Result<GitHubReply<Versioned<GitHubComment>>, GitHubFailure> {
        self.call_versioned(
            &GitHubOperation::UpdateIssueComment(request.clone()),
            decode_comment,
        )
    }

    /// Read one page of labels configured on a repository.
    ///
    /// # Errors
    ///
    /// As [`GitHubClient::get_comments`].
    pub fn list_labels(
        &self,
        request: &ListLabelsRequest,
    ) -> Result<GitHubReply<Vec<String>>, GitHubFailure> {
        let per_page = request.page().per_page();
        self.call(&GitHubOperation::ListLabels(request.clone()), |bytes| {
            decode_repository_labels(bytes, per_page)
        })
    }

    /// Read one page of a repository's issues.
    ///
    /// # Errors
    ///
    /// As [`GitHubClient::create_issue`], for this operation's contract.
    pub fn list_issues(
        &self,
        request: &ListIssuesRequest,
    ) -> Result<GitHubReply<IssueListPage>, GitHubFailure> {
        let per_page = request.page().per_page();
        self.call(&GitHubOperation::ListIssues(request.clone()), |bytes| {
            decode_issue_list(bytes, per_page)
        })
    }

    /// Read canonical push-activity metadata for one repository.
    ///
    /// # Errors
    ///
    /// As [`GitHubClient::create_issue`], for this operation's contract.
    pub fn get_repository(
        &self,
        request: &GetRepositoryRequest,
    ) -> Result<GitHubReply<GitHubRepository>, GitHubFailure> {
        self.call(
            &GitHubOperation::GetRepository(request.clone()),
            decode_repository,
        )
    }

    /// Read one exact GitHub Actions workflow run for revision reconciliation.
    pub fn get_workflow_run(
        &self,
        request: &GetWorkflowRunRequest,
    ) -> Result<GitHubReply<GitHubWorkflowRun>, GitHubFailure> {
        self.call(
            &GitHubOperation::GetWorkflowRun(request.clone()),
            decode_workflow_run,
        )
    }

    /// Re-run one exact GitHub Actions workflow run.
    ///
    /// GitHub documents an empty `201 Created` response for this operation.
    /// The endpoint has no idempotency key, so callers must persist their
    /// submission state before calling and must never blindly replay an
    /// ambiguous result.
    pub fn rerun_workflow(
        &self,
        request: &RerunWorkflowRequest,
    ) -> Result<GitHubReply<()>, GitHubFailure> {
        self.call_empty(&GitHubOperation::RerunWorkflow(request.clone()), 201)
    }

    /// Search issues across repositories.
    ///
    /// # Errors
    ///
    /// As [`GitHubClient::create_issue`], for this operation's contract.
    pub fn search_issues(
        &self,
        request: &SearchIssuesRequest,
    ) -> Result<GitHubReply<IssueSearchPage>, GitHubFailure> {
        let per_page = request.page().per_page();
        self.call(&GitHubOperation::SearchIssues(request.clone()), |bytes| {
            decode_search(bytes, per_page)
        })
    }

    /// Identify the account the credential belongs to.
    ///
    /// The cheap connectivity and scope probe, and the only operation that
    /// names no repository.
    ///
    /// # Errors
    ///
    /// As [`GitHubClient::create_issue`], for this operation's contract.
    pub fn whoami(&self) -> Result<GitHubReply<Viewer>, GitHubFailure> {
        self.call(&GitHubOperation::Whoami, decode_viewer)
    }

    /// Execute one closed work-management request.
    ///
    /// Accepted empty responses (notably `204`) are represented by an empty
    /// [`ManagementReceipt`]; JSON responses retain their bounded document.
    pub fn manage(
        &self,
        request: &ManagementRequest,
    ) -> Result<GitHubReply<ManagementReceipt>, GitHubFailure> {
        let answer = self.send_parts(
            request.method(),
            request.path(),
            request.body(),
            request.if_match().map(EntityTag::as_str),
        )?;
        if (300..400).contains(&answer.status) {
            return Err(GitHubFailure::Redirected);
        }
        if !(200..300).contains(&answer.status) {
            let message = decode_error_message(&answer.body, answer.status);
            return Ok(GitHubReply::new(
                answer.rate,
                GitHubOutcome::Rejected(GitHubRejection::new(
                    answer.status,
                    message,
                    &answer.rate,
                    answer.retry_after_seconds,
                )),
            ));
        }
        let receipt = if answer.body.is_empty() {
            ManagementReceipt::empty()
        } else {
            if !answer.json {
                return Err(GitHubFailure::UnexpectedContentType);
            }
            let value: serde_json::Value =
                serde_json::from_slice(&answer.body).map_err(|_| GitHubFailure::InvalidResponse)?;
            if request.path() == "/graphql"
                && value
                    .get("errors")
                    .is_some_and(|errors| errors.as_array().is_none_or(|items| !items.is_empty()))
            {
                return Err(GitHubFailure::InvalidResponse);
            }
            ManagementReceipt::document(value)
        };
        Ok(GitHubReply::new(
            answer.rate,
            GitHubOutcome::Accepted(receipt),
        ))
    }

    /// Issue one operation and decode its answer.
    fn call<T>(
        &self,
        operation: &GitHubOperation,
        decode: impl FnOnce(&[u8]) -> Result<T, GitHubFailure>,
    ) -> Result<GitHubReply<T>, GitHubFailure> {
        let answer = self.send(operation)?;
        if (300..400).contains(&answer.status) {
            // The credential is bound to one origin; a redirect is an
            // instruction to send the next one elsewhere.
            return Err(GitHubFailure::Redirected);
        }
        if !(200..300).contains(&answer.status) {
            let message = decode_error_message(&answer.body, answer.status);
            return Ok(GitHubReply::new(
                answer.rate,
                GitHubOutcome::Rejected(GitHubRejection::new(
                    answer.status,
                    message,
                    &answer.rate,
                    answer.retry_after_seconds,
                )),
            ));
        }
        if !answer.json {
            return Err(GitHubFailure::UnexpectedContentType);
        }
        Ok(GitHubReply::new(
            answer.rate,
            GitHubOutcome::Accepted(decode(&answer.body)?),
        ))
    }

    fn call_empty(
        &self,
        operation: &GitHubOperation,
        accepted_status: u16,
    ) -> Result<GitHubReply<()>, GitHubFailure> {
        let answer = self.send(operation)?;
        if (300..400).contains(&answer.status) {
            return Err(GitHubFailure::Redirected);
        }
        if !(200..300).contains(&answer.status) {
            let message = decode_error_message(&answer.body, answer.status);
            return Ok(GitHubReply::new(
                answer.rate,
                GitHubOutcome::Rejected(GitHubRejection::new(
                    answer.status,
                    message,
                    &answer.rate,
                    answer.retry_after_seconds,
                )),
            ));
        }
        if answer.status != accepted_status || !answer.body.is_empty() {
            return Err(GitHubFailure::InvalidResponse);
        }
        Ok(GitHubReply::new(answer.rate, GitHubOutcome::Accepted(())))
    }

    /// Issue one operation whose accepted response must carry an entity tag.
    fn call_versioned<T>(
        &self,
        operation: &GitHubOperation,
        decode: impl FnOnce(&[u8]) -> Result<T, GitHubFailure>,
    ) -> Result<GitHubReply<Versioned<T>>, GitHubFailure> {
        let answer = self.send(operation)?;
        if (300..400).contains(&answer.status) {
            return Err(GitHubFailure::Redirected);
        }
        if !(200..300).contains(&answer.status) {
            let message = decode_error_message(&answer.body, answer.status);
            return Ok(GitHubReply::new(
                answer.rate,
                GitHubOutcome::Rejected(GitHubRejection::new(
                    answer.status,
                    message,
                    &answer.rate,
                    answer.retry_after_seconds,
                )),
            ));
        }
        if !answer.json {
            return Err(GitHubFailure::UnexpectedContentType);
        }
        let etag = answer.etag.ok_or(GitHubFailure::MissingField)?;
        let etag = EntityTag::new(&etag).map_err(|_| GitHubFailure::FieldOutOfBounds)?;
        Ok(GitHubReply::new(
            answer.rate,
            GitHubOutcome::Accepted(Versioned::new(decode(&answer.body)?, etag)),
        ))
    }

    /// Issue one request and return its status, window and bounded body.
    ///
    /// The credential is rendered into an `Authorization` header inside the
    /// callback and dropped when it returns; it is never stored on the request
    /// builder beyond that, never logged, and never named in a failure.
    fn send(&self, operation: &GitHubOperation) -> Result<Answer, GitHubFailure> {
        self.send_parts(
            operation.method(),
            &operation.path(),
            operation.body().as_deref(),
            operation.if_match().map(EntityTag::as_str),
        )
    }

    fn send_parts(
        &self,
        method: HttpMethod,
        path: &str,
        body: Option<&str>,
        if_match: Option<&str>,
    ) -> Result<Answer, GitHubFailure> {
        let url = format!("{}{}", self.base.origin(), path);
        let body = body.unwrap_or_default();
        let mut response = self
            .token
            .authorization()
            .with_header_value(|authorization| match method {
                HttpMethod::Get => self
                    .prepared(self.agent.get(&url), authorization, false, if_match)
                    .call(),
                HttpMethod::Post => self
                    .prepared(self.agent.post(&url), authorization, true, if_match)
                    .send(body),
                HttpMethod::Patch => self
                    .prepared(self.agent.patch(&url), authorization, true, if_match)
                    .send(body),
                HttpMethod::Put => self
                    .prepared(self.agent.put(&url), authorization, true, if_match)
                    .send(body),
                HttpMethod::Delete if body.is_empty() => self
                    .prepared(self.agent.delete(&url), authorization, false, if_match)
                    .call(),
                HttpMethod::Delete => self
                    .prepared(self.agent.delete(&url), authorization, true, if_match)
                    .force_send_body()
                    .send(body),
            })
            .map_err(map_ureq_error)?;

        let status = response.status().as_u16();
        let headers = response.headers();
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        };
        let rate = RateLimit::new(
            header("x-ratelimit-remaining").and_then(|value| value.parse().ok()),
            header("x-ratelimit-limit").and_then(|value| value.parse().ok()),
            header("x-ratelimit-reset").and_then(|value| value.parse().ok()),
        );
        let retry_after_seconds = header("retry-after").and_then(|value| value.parse().ok());
        let json = header("content-type").is_some_and(|value| is_github_json(&value));
        let etag = header("etag");

        let reader = response
            .body_mut()
            .with_config()
            .limit((MAX_GITHUB_RESPONSE_BYTES + 1) as u64)
            .reader();
        Ok(Answer {
            status,
            rate,
            retry_after_seconds,
            json,
            etag,
            body: read_bounded_body(reader, MAX_GITHUB_RESPONSE_BYTES)?,
        })
    }

    /// Apply the four fixed headers and the request budget.
    ///
    /// Written once, generically over ureq's body typestate, so a `GET` and a
    /// `PUT` cannot drift apart in what they send.
    fn prepared<Any>(
        &self,
        builder: ureq::RequestBuilder<Any>,
        authorization: &str,
        has_body: bool,
        if_match: Option<&str>,
    ) -> ureq::RequestBuilder<Any> {
        let builder = builder
            .header("authorization", authorization)
            .header("accept", GITHUB_ACCEPT)
            .header("x-github-api-version", GITHUB_API_VERSION)
            .header("user-agent", GITHUB_USER_AGENT);
        let builder = if has_body {
            builder.header("content-type", "application/json")
        } else {
            builder
        };
        let builder = if let Some(if_match) = if_match {
            builder.header("if-match", if_match)
        } else {
            builder
        };
        builder.config().timeout_global(Some(self.timeout)).build()
    }
}

/// One raw answer, before it is classified.
struct Answer {
    status: u16,
    rate: RateLimit,
    retry_after_seconds: Option<u32>,
    json: bool,
    etag: Option<String>,
    body: Vec<u8>,
}

/// No field of this client is safe to print except the origin, so `Debug`
/// prints that and says so about the rest.
impl fmt::Debug for GitHubClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GitHubClient")
            .field("origin", &self.base.origin())
            .field("authorization", &"<redacted>")
            .finish()
    }
}

/// Whether a content type is the JSON GitHub answers with.
///
/// GitHub sends `application/json; charset=utf-8` for a payload and the
/// versioned media type is only ever *requested*, so both spellings are
/// admitted and nothing else is.
fn is_github_json(value: &str) -> bool {
    let mut fields = value.split(';');
    if !fields.next().is_some_and(|mime| {
        let mime = mime.trim();
        mime.eq_ignore_ascii_case("application/json") || mime.eq_ignore_ascii_case(GITHUB_ACCEPT)
    }) {
        return false;
    }
    fields.all(|parameter| {
        let Some((name, value)) = parameter.trim().split_once('=') else {
            return false;
        };
        name.trim().eq_ignore_ascii_case("charset")
            && value.trim().trim_matches('"').eq_ignore_ascii_case("utf-8")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::Page;
    use crate::target::{IssueNumber, RepoTarget};
    use crate::ticket::{IssueBodyText, IssueTitle};

    const SECRET: &str = "ghp_fixture-secret-never-print";

    fn client(base: &str) -> GitHubClient {
        GitHubClient::new(
            GitHubBase::new(base).expect("base"),
            GitHubToken::new(SECRET.as_bytes().to_vec()).expect("token"),
        )
    }

    fn create() -> GitHubOperation {
        GitHubOperation::CreateIssue(
            CreateIssueRequest::new(
                RepoTarget::parse("example-org", "example-repo").expect("target"),
                IssueTitle::new("Panne de paiement").expect("title"),
                IssueBodyText::new("corps").expect("body"),
                Vec::new(),
            )
            .expect("create"),
        )
    }

    #[test]
    fn an_endpoint_is_the_locked_origin_plus_the_operations_own_path() {
        let client = client("https://api.github.com");
        assert_eq!(
            client.endpoint(&create()),
            "https://api.github.com/repos/example-org/example-repo/issues"
        );
        assert_eq!(
            client.endpoint(&GitHubOperation::Whoami),
            "https://api.github.com/user"
        );
        assert_eq!(client.base().origin(), "https://api.github.com");
    }

    #[test]
    fn a_tls_base_yields_a_direct_verified_non_redirecting_agent() {
        let client = client("https://api.github.com");
        let config = client.agent.config();
        assert!(config.https_only());
        assert!(config.proxy().is_none());
        assert_eq!(config.max_redirects(), 0);
        assert!(!config.http_status_as_error());
        assert_eq!(config.max_response_header_size(), MAX_RESPONSE_HEADER_BYTES);
        assert!(matches!(
            config.tls_config().root_certs(),
            RootCerts::WebPki
        ));
        assert!(log::STATIC_MAX_LEVEL <= log::LevelFilter::Debug);
    }

    #[test]
    fn only_a_loopback_base_relaxes_https_only() {
        assert!(client("https://api.github.com").agent.config().https_only());
        assert!(!client("http://127.0.0.1:8080").agent.config().https_only());
    }

    #[test]
    fn the_credential_never_reaches_debug_an_endpoint_or_a_body() {
        let client = client("https://api.github.com");
        let rendered = format!(
            "{client:?}|{}|{}|{:?}|{}",
            client.endpoint(&create()),
            create().body().unwrap_or_default(),
            GitHubFailure::Unavailable,
            GitHubFailure::Unavailable
        );
        assert!(!rendered.contains(SECRET), "rendered: {rendered}");
        assert!(!rendered.contains("ghp_"), "rendered: {rendered}");
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn the_request_budget_may_only_be_tightened_never_extended() {
        let ceiling = Duration::from_secs(GITHUB_REQUEST_TIMEOUT_SECONDS);
        let tighten = |timeout| {
            GitHubClient::with_request_timeout(
                GitHubBase::production(),
                GitHubToken::new(b"ghp_fixture".to_vec()).expect("token"),
                timeout,
            )
            .request_timeout()
        };
        assert_eq!(client("https://api.github.com").request_timeout(), ceiling);
        assert_eq!(tighten(Duration::from_secs(1)), Duration::from_secs(1));
        assert_eq!(tighten(Duration::from_secs(3600)), ceiling);
        assert_eq!(tighten(Duration::ZERO), ceiling);
    }

    #[test]
    fn the_response_content_type_is_closed() {
        assert!(is_github_json("application/json"));
        assert!(is_github_json("Application/Json; charset=UTF-8"));
        assert!(is_github_json("application/vnd.github+json; charset=utf-8"));
        assert!(!is_github_json("text/json"));
        assert!(!is_github_json("application/json; profile=secret"));
        assert!(!is_github_json("application/json; charset=latin1"));
        assert!(!is_github_json("text/html"));
    }

    #[test]
    fn the_body_cap_accepts_the_boundary_and_refuses_one_over() {
        let at_limit = vec![b'a'; MAX_GITHUB_RESPONSE_BYTES];
        assert_eq!(
            read_bounded_body(std::io::Cursor::new(&at_limit), MAX_GITHUB_RESPONSE_BYTES)
                .expect("at limit"),
            at_limit
        );
        assert_eq!(
            read_bounded_body(
                std::io::Cursor::new(vec![b'a'; MAX_GITHUB_RESPONSE_BYTES + 1]),
                MAX_GITHUB_RESPONSE_BYTES,
            )
            .map_err(GitHubFailure::from),
            Err(GitHubFailure::ResponseTooLarge)
        );
    }

    #[test]
    fn every_operation_has_an_endpoint_under_the_locked_origin() {
        let client = client("https://api.github.com");
        let target = RepoTarget::parse("example-org", "example-repo").expect("target");
        let number = IssueNumber::new(42).expect("number");
        let page = Page::new(1, 30).expect("page");
        let operations = [
            create(),
            GitHubOperation::Comment(CommentRequest::new(
                target.clone(),
                number,
                IssueBodyText::new("merci").expect("body"),
            )),
            GitHubOperation::SetState(SetStateRequest::new(
                target.clone(),
                number,
                crate::IssueState::Closed,
            )),
            GitHubOperation::ReplaceLabels(
                ReplaceLabelsRequest::new(target.clone(), number, Vec::new()).expect("labels"),
            ),
            GitHubOperation::GetIssue(GetIssueRequest::new(target.clone(), number)),
            GitHubOperation::UpdateIssueBody(UpdateIssueBodyRequest::new(
                target.clone(),
                number,
                IssueBodyText::new("nouveau corps").expect("body"),
                EntityTag::new("\"issue-v1\"").expect("etag"),
            )),
            GitHubOperation::GetComments(GetCommentsRequest::new(target.clone(), number, page)),
            GitHubOperation::GetIssueComment(GetIssueCommentRequest::new(
                target.clone(),
                crate::CommentId::new(9_001).expect("comment id"),
            )),
            GitHubOperation::UpdateIssueComment(UpdateIssueCommentRequest::new(
                target.clone(),
                crate::CommentId::new(9_001).expect("comment id"),
                IssueBodyText::new("fait").expect("body"),
                EntityTag::new("\"comment-v1\"").expect("etag"),
            )),
            GitHubOperation::ListLabels(ListLabelsRequest::new(target.clone(), page)),
            GitHubOperation::ListIssues(ListIssuesRequest::new(
                target,
                crate::IssueFilter::default(),
                page,
            )),
            GitHubOperation::SearchIssues(SearchIssuesRequest::new("panne", page).expect("search")),
            GitHubOperation::Whoami,
        ];
        for operation in operations {
            let endpoint = client.endpoint(&operation);
            assert!(
                endpoint.starts_with("https://api.github.com/"),
                "{endpoint} leaves the locked origin"
            );
            assert!(!endpoint.contains(SECRET));
        }
    }
}
