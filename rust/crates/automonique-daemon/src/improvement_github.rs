// SPDX-License-Identifier: Elastic-2.0

//! Host-owned GitHub publication for improvement plans and pull requests.
//!
//! Candidate workers never receive this capability. The broker fixes both
//! repositories at construction, uses only argument-vector `gh api` calls, and
//! reconciles deterministic issue/branch/file/PR identities before creating
//! them. Model-authored Markdown travels on stdin as JSON data and can never
//! become an executable, endpoint, repository, or method.

use std::error::Error;
use std::fmt;
use std::io::Write;
use std::process::{Command, Stdio};

use automonique_github_connector::RepoTarget;
use serde_json::{Value, json};

use crate::improvements::RenderedPlan;

const GH: &str = "/usr/bin/gh";
const MAX_REQUEST_BYTES: usize = 128 * 1024;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_RECONCILE_PAGES: u32 = 10;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanPublication {
    pub issue_number: u64,
    pub issue_url: String,
    pub plan_pr_number: u64,
    pub plan_pr_url: String,
    pub plan_head_sha: String,
    pub branch: String,
    pub recovered: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PullRequestPublication {
    pub number: u64,
    pub url: String,
    pub head_sha: String,
    pub recovered: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeReceipt {
    pub merged_sha: String,
    pub merged_tree_sha: String,
    pub recovered: bool,
}

#[derive(Debug)]
pub struct ImprovementGitHubBroker<A = GhCli> {
    api: A,
    planning_repo: RepoTarget,
    source_repo: RepoTarget,
    planning_base: String,
    source_base: String,
}

impl ImprovementGitHubBroker<GhCli> {
    pub fn production(
        planning_repo: RepoTarget,
        source_repo: RepoTarget,
        planning_base: &str,
        source_base: &str,
    ) -> Result<Self, ImprovementGitHubError> {
        Self::new(
            GhCli,
            planning_repo,
            source_repo,
            planning_base,
            source_base,
        )
    }
}

impl<A: GitHubApi> ImprovementGitHubBroker<A> {
    pub fn new(
        api: A,
        planning_repo: RepoTarget,
        source_repo: RepoTarget,
        planning_base: &str,
        source_base: &str,
    ) -> Result<Self, ImprovementGitHubError> {
        validate_branch(planning_base)?;
        validate_branch(source_base)?;
        Ok(Self {
            api,
            planning_repo,
            source_repo,
            planning_base: planning_base.to_owned(),
            source_base: source_base.to_owned(),
        })
    }

    /// Publish one plan revision to a private issue and plan-only pull request.
    /// Repeating the call reconciles the deterministic marker, branch, path and
    /// head rather than creating duplicates.
    pub fn publish_plan(
        &mut self,
        public_id: &str,
        revision: u64,
        title: &str,
        plan: &RenderedPlan,
    ) -> Result<PlanPublication, ImprovementGitHubError> {
        validate_public_id(public_id)?;
        validate_text(title, "title", 256)?;
        if revision == 0 {
            return Err(ImprovementGitHubError::InvalidField("revision"));
        }
        self.require_private(self.planning_repo.clone())?;
        let marker = format!("<!-- automonique-improvement:{public_id} -->");
        let issue_body = format!(
            "{marker}\n\nCanonical plan revisions are reviewed in the linked plan-only pull request. The approved implementation scope is the exact merged plan digest."
        );
        let (issue_number, issue_url, issue_recovered) =
            self.ensure_issue(self.planning_repo.clone(), title, &issue_body, &marker)?;
        let branch = format!("automonique/{public_id}-plan-r{revision}");
        validate_branch(&branch)?;
        self.ensure_branch(
            self.planning_repo.clone(),
            &self.planning_base.clone(),
            &branch,
        )?;
        let commit_sha = self.ensure_file(
            self.planning_repo.clone(),
            &branch,
            &plan.repository_path,
            &plan.markdown,
            &format!("{public_id}: plan revision {revision}"),
        )?;
        let pr_title = format!("{public_id}: {title}");
        let pr_body = format!(
            "{marker}\n\nCloses no issue automatically. Plan discussion: #{}\n\nPlan digest: `{}`",
            issue_number, plan.sha256
        );
        let pr = self.ensure_pull_request(
            self.planning_repo.clone(),
            &branch,
            &self.planning_base.clone(),
            &pr_title,
            &pr_body,
        )?;
        if pr.head_sha != commit_sha {
            return Err(ImprovementGitHubError::Conflict("plan PR head"));
        }
        Ok(PlanPublication {
            issue_number,
            issue_url,
            plan_pr_number: pr.number,
            plan_pr_url: pr.url,
            plan_head_sha: pr.head_sha,
            branch,
            recovered: issue_recovered || pr.recovered,
        })
    }

    /// Read the immutable source base that the plan and lab worktree must bind.
    pub fn source_base_sha(&mut self) -> Result<String, ImprovementGitHubError> {
        self.require_public(self.source_repo.clone())?;
        let reference = self.api.get(&format!(
            "repos/{}/git/ref/heads/{}",
            self.source_repo, self.source_base
        ))?;
        let sha = reference
            .pointer("/object/sha")
            .and_then(Value::as_str)
            .ok_or(ImprovementGitHubError::InvalidResponse("source base SHA"))?;
        validate_sha1(sha, "source base SHA")?;
        Ok(sha.to_owned())
    }

    /// Open or reconcile the source repository PR after the host-side Git
    /// publisher has pushed the candidate's exact tested commit to `branch`.
    pub fn publish_implementation_pr(
        &mut self,
        public_id: &str,
        branch: &str,
        title: &str,
        body: &str,
    ) -> Result<PullRequestPublication, ImprovementGitHubError> {
        validate_public_id(public_id)?;
        validate_branch(branch)?;
        validate_text(title, "title", 256)?;
        validate_text(body, "body", 64 * 1024)?;
        self.require_public(self.source_repo.clone())?;
        let marker = format!("<!-- automonique-improvement:{public_id} -->");
        self.ensure_pull_request(
            self.source_repo.clone(),
            branch,
            &self.source_base.clone(),
            title,
            &format!("{marker}\n\n{body}"),
        )
    }

    /// Merge exactly the approved PR head. A branch that advanced after the
    /// Telegram gate is refused by GitHub's `sha` precondition.
    pub fn merge_plan(
        &mut self,
        number: u64,
        approved_head_sha: &str,
    ) -> Result<MergeReceipt, ImprovementGitHubError> {
        validate_number(number)?;
        validate_sha1(approved_head_sha, "approved_head_sha")?;
        self.merge(self.planning_repo.clone(), number, approved_head_sha)
    }

    pub fn merge_implementation(
        &mut self,
        number: u64,
        approved_head_sha: &str,
    ) -> Result<MergeReceipt, ImprovementGitHubError> {
        validate_number(number)?;
        validate_sha1(approved_head_sha, "approved_head_sha")?;
        self.merge(self.source_repo.clone(), number, approved_head_sha)
    }

    fn require_private(&mut self, repo: RepoTarget) -> Result<(), ImprovementGitHubError> {
        let value = self.api.get(&format!("repos/{repo}"))?;
        if value.get("private").and_then(Value::as_bool) != Some(true) {
            return Err(ImprovementGitHubError::Visibility);
        }
        Ok(())
    }

    fn require_public(&mut self, repo: RepoTarget) -> Result<(), ImprovementGitHubError> {
        let value = self.api.get(&format!("repos/{repo}"))?;
        if value.get("private").and_then(Value::as_bool) != Some(false) {
            return Err(ImprovementGitHubError::Visibility);
        }
        Ok(())
    }

    fn ensure_issue(
        &mut self,
        repo: RepoTarget,
        title: &str,
        body: &str,
        marker: &str,
    ) -> Result<(u64, String, bool), ImprovementGitHubError> {
        for page in 1..=MAX_RECONCILE_PAGES {
            let endpoint = format!("repos/{repo}/issues?state=all&per_page=100&page={page}");
            let values = array(self.api.get(&endpoint)?, "issues")?;
            for issue in &values {
                if issue.get("pull_request").is_some() {
                    continue;
                }
                if issue
                    .get("body")
                    .and_then(Value::as_str)
                    .is_some_and(|text| text.contains(marker))
                {
                    return Ok((number(issue)?, url(issue)?, true));
                }
            }
            if values.len() < 100 {
                break;
            }
        }
        let created = self.api.send(
            "POST",
            &format!("repos/{repo}/issues"),
            &json!({"title": title, "body": body}),
        )?;
        Ok((number(&created)?, url(&created)?, false))
    }

    fn ensure_branch(
        &mut self,
        repo: RepoTarget,
        base: &str,
        branch: &str,
    ) -> Result<(), ImprovementGitHubError> {
        let endpoint = format!("repos/{repo}/git/ref/heads/{branch}");
        if self.api.get_optional(&endpoint)?.is_some() {
            return Ok(());
        }
        let base_ref = self
            .api
            .get(&format!("repos/{repo}/git/ref/heads/{base}"))?;
        let sha = base_ref
            .pointer("/object/sha")
            .and_then(Value::as_str)
            .ok_or(ImprovementGitHubError::InvalidResponse("base ref SHA"))?;
        validate_sha1(sha, "base ref SHA")?;
        self.api.send(
            "POST",
            &format!("repos/{repo}/git/refs"),
            &json!({"ref": format!("refs/heads/{branch}"), "sha": sha}),
        )?;
        Ok(())
    }

    fn ensure_file(
        &mut self,
        repo: RepoTarget,
        branch: &str,
        path: &str,
        content: &str,
        message: &str,
    ) -> Result<String, ImprovementGitHubError> {
        validate_plan_path(path)?;
        validate_text(content, "plan content", 64 * 1024)?;
        let endpoint = format!("repos/{repo}/contents/{path}");
        let encoded = base64(content.as_bytes());
        let existing = self.api.get_optional(&format!("{endpoint}?ref={branch}"))?;
        if let Some(existing) = existing {
            let recorded = existing
                .get("content")
                .and_then(Value::as_str)
                .ok_or(ImprovementGitHubError::InvalidResponse("file content"))?
                .bytes()
                .filter(|byte| !byte.is_ascii_whitespace())
                .map(char::from)
                .collect::<String>();
            if recorded == encoded {
                let commit = self.api.get(&format!("repos/{repo}/commits/{branch}"))?;
                return sha(&commit);
            }
            return Err(ImprovementGitHubError::Conflict(
                "plan path already differs",
            ));
        }
        let created = self.api.send(
            "PUT",
            &endpoint,
            &json!({"message": message, "content": encoded, "branch": branch}),
        )?;
        let commit = created
            .get("commit")
            .ok_or(ImprovementGitHubError::InvalidResponse("content commit"))?;
        sha(commit)
    }

    fn ensure_pull_request(
        &mut self,
        repo: RepoTarget,
        branch: &str,
        base: &str,
        title: &str,
        body: &str,
    ) -> Result<PullRequestPublication, ImprovementGitHubError> {
        let head = format!("{}:{branch}", repo.owner().as_str());
        let encoded_head = percent_query(&head);
        let endpoint = format!("repos/{repo}/pulls?state=all&head={encoded_head}&per_page=100");
        let pulls = self.api.get(&endpoint)?;
        if let Some(pull) = array(pulls, "pulls")?.first() {
            return pull_publication(pull, true);
        }
        let created = self.api.send(
            "POST",
            &format!("repos/{repo}/pulls"),
            &json!({"title": title, "body": body, "head": branch, "base": base, "draft": false}),
        )?;
        pull_publication(&created, false)
    }

    fn merge(
        &mut self,
        repo: RepoTarget,
        number: u64,
        approved_head_sha: &str,
    ) -> Result<MergeReceipt, ImprovementGitHubError> {
        let pull = self.api.get(&format!("repos/{repo}/pulls/{number}"))?;
        let current_head = pull
            .pointer("/head/sha")
            .and_then(Value::as_str)
            .ok_or(ImprovementGitHubError::InvalidResponse("pull head SHA"))?;
        if current_head != approved_head_sha {
            return Err(ImprovementGitHubError::Conflict("approved PR head moved"));
        }
        if pull.get("merged_at").is_some_and(|value| !value.is_null()) {
            let merged_sha = pull
                .get("merge_commit_sha")
                .and_then(Value::as_str)
                .ok_or(ImprovementGitHubError::InvalidResponse("merge SHA"))?;
            validate_sha1(merged_sha, "merge SHA")?;
            return self.merge_receipt(repo, merged_sha, true);
        }
        let endpoint = format!("repos/{repo}/pulls/{number}/merge");
        let response = self.api.send(
            "PUT",
            &endpoint,
            &json!({"sha": approved_head_sha, "merge_method": "squash"}),
        )?;
        if response.get("merged").and_then(Value::as_bool) != Some(true) {
            return Err(ImprovementGitHubError::Conflict("pull request not merged"));
        }
        let merged_sha = response
            .get("sha")
            .and_then(Value::as_str)
            .ok_or(ImprovementGitHubError::InvalidResponse("merge SHA"))?;
        validate_sha1(merged_sha, "merge SHA")?;
        self.merge_receipt(repo, merged_sha, false)
    }

    fn merge_receipt(
        &mut self,
        repo: RepoTarget,
        merged_sha: &str,
        recovered: bool,
    ) -> Result<MergeReceipt, ImprovementGitHubError> {
        let commit = self
            .api
            .get(&format!("repos/{repo}/git/commits/{merged_sha}"))?;
        let merged_tree_sha = commit
            .pointer("/tree/sha")
            .and_then(Value::as_str)
            .ok_or(ImprovementGitHubError::InvalidResponse("merge tree SHA"))?;
        validate_sha1(merged_tree_sha, "merge tree SHA")?;
        Ok(MergeReceipt {
            merged_sha: merged_sha.to_owned(),
            merged_tree_sha: merged_tree_sha.to_owned(),
            recovered,
        })
    }
}

pub trait GitHubApi {
    fn get(&mut self, endpoint: &str) -> Result<Value, ImprovementGitHubError>;
    fn get_optional(&mut self, endpoint: &str) -> Result<Option<Value>, ImprovementGitHubError>;
    fn send(
        &mut self,
        method: &'static str,
        endpoint: &str,
        body: &Value,
    ) -> Result<Value, ImprovementGitHubError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GhCli;

impl GitHubApi for GhCli {
    fn get(&mut self, endpoint: &str) -> Result<Value, ImprovementGitHubError> {
        gh("GET", endpoint, None)?.ok_or(ImprovementGitHubError::NotFound)
    }

    fn get_optional(&mut self, endpoint: &str) -> Result<Option<Value>, ImprovementGitHubError> {
        gh("GET", endpoint, None)
    }

    fn send(
        &mut self,
        method: &'static str,
        endpoint: &str,
        body: &Value,
    ) -> Result<Value, ImprovementGitHubError> {
        gh(method, endpoint, Some(body))?.ok_or(ImprovementGitHubError::NotFound)
    }
}

fn gh(
    method: &'static str,
    endpoint: &str,
    body: Option<&Value>,
) -> Result<Option<Value>, ImprovementGitHubError> {
    if !matches!(method, "GET" | "POST" | "PUT") || !safe_endpoint(endpoint) {
        return Err(ImprovementGitHubError::InvalidField("GitHub request"));
    }
    let mut command = Command::new(GH);
    command.args(["api", "--method", method, endpoint]);
    if body.is_some() {
        command.args(["--input", "-"]);
    }
    let mut child = command
        .stdin(if body.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(ImprovementGitHubError::Io)?;
    if let Some(body) = body {
        let encoded = serde_json::to_vec(body)
            .map_err(|_| ImprovementGitHubError::InvalidField("GitHub JSON"))?;
        if encoded.len() > MAX_REQUEST_BYTES {
            return Err(ImprovementGitHubError::InvalidField("GitHub JSON"));
        }
        child
            .stdin
            .take()
            .ok_or(ImprovementGitHubError::InvalidResponse("gh stdin"))?
            .write_all(&encoded)
            .map_err(ImprovementGitHubError::Io)?;
    }
    let output = child
        .wait_with_output()
        .map_err(ImprovementGitHubError::Io)?;
    if output.stdout.len() > MAX_RESPONSE_BYTES || output.stderr.len() > MAX_RESPONSE_BYTES {
        return Err(ImprovementGitHubError::InvalidResponse("gh output limit"));
    }
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("HTTP 404") {
            return Ok(None);
        }
        return Err(ImprovementGitHubError::ApiRefused);
    }
    serde_json::from_slice(&output.stdout)
        .map(Some)
        .map_err(|_| ImprovementGitHubError::InvalidResponse("gh JSON"))
}

fn safe_endpoint(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 2_048
        && value.starts_with("repos/")
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'/' | b'-' | b'_' | b'.' | b'?' | b'=' | b'&' | b'%')
        })
        && !value.contains("..")
        && !value.contains("//")
}

fn pull_publication(
    value: &Value,
    recovered: bool,
) -> Result<PullRequestPublication, ImprovementGitHubError> {
    let head_sha = value
        .pointer("/head/sha")
        .and_then(Value::as_str)
        .ok_or(ImprovementGitHubError::InvalidResponse("pull head SHA"))?;
    validate_sha1(head_sha, "pull head SHA")?;
    Ok(PullRequestPublication {
        number: number(value)?,
        url: url(value)?,
        head_sha: head_sha.to_owned(),
        recovered,
    })
}

fn array(value: Value, field: &'static str) -> Result<Vec<Value>, ImprovementGitHubError> {
    value
        .as_array()
        .cloned()
        .ok_or(ImprovementGitHubError::InvalidResponse(field))
}

fn number(value: &Value) -> Result<u64, ImprovementGitHubError> {
    let number = value
        .get("number")
        .and_then(Value::as_u64)
        .ok_or(ImprovementGitHubError::InvalidResponse("number"))?;
    validate_number(number)?;
    Ok(number)
}

fn url(value: &Value) -> Result<String, ImprovementGitHubError> {
    let url = value
        .get("html_url")
        .and_then(Value::as_str)
        .ok_or(ImprovementGitHubError::InvalidResponse("URL"))?;
    if !url.starts_with("https://github.com/") || url.len() > 2_048 {
        return Err(ImprovementGitHubError::InvalidResponse("URL"));
    }
    Ok(url.to_owned())
}

fn sha(value: &Value) -> Result<String, ImprovementGitHubError> {
    let sha = value
        .get("sha")
        .and_then(Value::as_str)
        .ok_or(ImprovementGitHubError::InvalidResponse("SHA"))?;
    validate_sha1(sha, "SHA")?;
    Ok(sha.to_owned())
}

fn validate_public_id(value: &str) -> Result<(), ImprovementGitHubError> {
    if value.len() != 10
        || !value.starts_with("IMP-")
        || !value[4..].bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ImprovementGitHubError::InvalidField("public_id"));
    }
    Ok(())
}

fn validate_branch(value: &str) -> Result<(), ImprovementGitHubError> {
    if value.is_empty()
        || value.len() > 160
        || value.starts_with('/')
        || value.ends_with('/')
        || value.contains("..")
        || value.contains("//")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_'))
    {
        return Err(ImprovementGitHubError::InvalidField("branch"));
    }
    Ok(())
}

fn validate_plan_path(value: &str) -> Result<(), ImprovementGitHubError> {
    let valid = value.starts_with("plans/IMP-")
        && value.ends_with(".md")
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_' | b'.'));
    if !valid {
        return Err(ImprovementGitHubError::InvalidField("plan path"));
    }
    Ok(())
}

fn validate_text(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<(), ImprovementGitHubError> {
    if value.trim().is_empty() || value.len() > max || value.contains('\0') {
        return Err(ImprovementGitHubError::InvalidField(field));
    }
    Ok(())
}

fn validate_number(number: u64) -> Result<(), ImprovementGitHubError> {
    if number == 0 || number > 9_999_999 {
        Err(ImprovementGitHubError::InvalidField("number"))
    } else {
        Ok(())
    }
}

fn validate_sha1(value: &str, field: &'static str) -> Result<(), ImprovementGitHubError> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ImprovementGitHubError::InvalidField(field));
    }
    Ok(())
}

fn percent_query(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') {
            encoded.push(char::from(byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = *chunk.get(1).unwrap_or(&0);
        let third = *chunk.get(2).unwrap_or(&0);
        output.push(char::from(TABLE[usize::from(first >> 2)]));
        output.push(char::from(
            TABLE[usize::from(((first & 3) << 4) | (second >> 4))],
        ));
        output.push(if chunk.len() > 1 {
            char::from(TABLE[usize::from(((second & 15) << 2) | (third >> 6))])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(TABLE[usize::from(third & 63)])
        } else {
            '='
        });
    }
    output
}

#[derive(Debug)]
pub enum ImprovementGitHubError {
    InvalidField(&'static str),
    InvalidResponse(&'static str),
    Visibility,
    Conflict(&'static str),
    NotFound,
    ApiRefused,
    Io(std::io::Error),
}

impl fmt::Display for ImprovementGitHubError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => {
                write!(formatter, "invalid improvement GitHub field: {field}")
            }
            Self::InvalidResponse(field) => {
                write!(formatter, "invalid improvement GitHub response: {field}")
            }
            Self::Visibility => {
                formatter.write_str("improvement repository visibility does not match policy")
            }
            Self::Conflict(reason) => write!(formatter, "improvement GitHub conflict: {reason}"),
            Self::NotFound => formatter.write_str("improvement GitHub resource not found"),
            Self::ApiRefused => formatter.write_str("GitHub refused improvement operation"),
            Self::Io(error) => write!(formatter, "improvement GitHub I/O error: {error}"),
        }
    }
}

impl Error for ImprovementGitHubError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_and_endpoint_grammars_are_deterministic() {
        assert_eq!(base64(b"plan"), "cGxhbg==");
        assert!(safe_endpoint(
            "repos/bext-stack/automonique/pulls?state=all&page=1"
        ));
        assert!(!safe_endpoint("repos/bext-stack/../secrets"));
        assert_eq!(
            percent_query("bext-stack:automonique/IMP-000001"),
            "bext-stack%3Aautomonique%2FIMP-000001"
        );
    }

    #[test]
    fn only_canonical_improvement_coordinates_are_accepted() {
        assert!(validate_public_id("IMP-000001").is_ok());
        assert!(validate_public_id("IMP-1").is_err());
        assert!(validate_branch("automonique/IMP-000001-plan-r2").is_ok());
        assert!(validate_branch("../../main").is_err());
        assert!(validate_plan_path("plans/IMP-000001.md").is_ok());
    }
}
