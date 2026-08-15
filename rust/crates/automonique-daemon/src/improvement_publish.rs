// SPDX-License-Identifier: Elastic-2.0

//! Host-only publication of an exact tested candidate commit.
//!
//! The sandboxed candidate never receives this object or GitHub credentials.
//! The destination URL is derived from a validated, fixed repository target;
//! neither model output nor plan Markdown can select a remote or refspec.

use std::error::Error;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use automonique_github_connector::RepoTarget;

const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidatePushReceipt {
    pub branch: String,
    pub candidate_sha: String,
    pub candidate_tree: String,
}

pub trait GitPush {
    fn push(
        &mut self,
        worktree: &Path,
        remote_url: &str,
        refspec: &str,
    ) -> Result<(), CandidatePublishError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GitCliPush;

impl GitPush for GitCliPush {
    fn push(
        &mut self,
        worktree: &Path,
        remote_url: &str,
        refspec: &str,
    ) -> Result<(), CandidatePublishError> {
        let output = bounded_output(
            Command::new("git")
                .arg("-C")
                .arg(worktree)
                .args(["push", remote_url, refspec]),
        )?;
        if !output.status.success() {
            return Err(CandidatePublishError::PushRefused);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct CandidatePublisher<P = GitCliPush> {
    repository: RepoTarget,
    push: P,
}

impl CandidatePublisher<GitCliPush> {
    #[must_use]
    pub const fn production(repository: RepoTarget) -> Self {
        Self {
            repository,
            push: GitCliPush,
        }
    }
}

impl<P: GitPush> CandidatePublisher<P> {
    #[must_use]
    pub const fn new(repository: RepoTarget, push: P) -> Self {
        Self { repository, push }
    }

    pub fn publish(
        &mut self,
        worktree: impl AsRef<Path>,
        public_id: &str,
        revision: u64,
        candidate_sha: &str,
        candidate_tree: &str,
    ) -> Result<CandidatePushReceipt, CandidatePublishError> {
        validate_public_id(public_id)?;
        if revision == 0 {
            return Err(CandidatePublishError::InvalidInput);
        }
        validate_object_id(candidate_sha)?;
        validate_object_id(candidate_tree)?;
        let worktree = canonical_worktree(worktree.as_ref())?;
        if git_text(&worktree, &["rev-parse", "HEAD"])? != candidate_sha
            || git_text(&worktree, &["rev-parse", "HEAD^{tree}"])? != candidate_tree
        {
            return Err(CandidatePublishError::CandidateMismatch);
        }
        let status = bounded_output(
            Command::new("git")
                .arg("-C")
                .arg(&worktree)
                .args(["status", "--porcelain=v1"]),
        )?;
        if !status.status.success() || !status.stdout.is_empty() {
            return Err(CandidatePublishError::CandidateMismatch);
        }
        // A release-gate change request advances the durable revision and may
        // produce a sibling commit from the same pinned source base. Giving
        // each attempt its own branch keeps retries non-force and reviewable.
        let branch = format!("automonique/{public_id}-implementation-r{revision}");
        let remote_url = format!(
            "https://github.com/{}/{}.git",
            self.repository.owner().as_str(),
            self.repository.repo().as_str()
        );
        let refspec = format!("{candidate_sha}:refs/heads/{branch}");
        self.push.push(&worktree, &remote_url, &refspec)?;
        Ok(CandidatePushReceipt {
            branch,
            candidate_sha: candidate_sha.to_owned(),
            candidate_tree: candidate_tree.to_owned(),
        })
    }
}

fn canonical_worktree(path: &Path) -> Result<PathBuf, CandidatePublishError> {
    if !path.is_absolute() {
        return Err(CandidatePublishError::UnsafePath);
    }
    let path = fs::canonicalize(path).map_err(CandidatePublishError::Io)?;
    if !path.is_dir() || !path.join(".git").exists() {
        return Err(CandidatePublishError::UnsafePath);
    }
    Ok(path)
}

fn git_text(repository: &Path, arguments: &[&str]) -> Result<String, CandidatePublishError> {
    let output = bounded_output(
        Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(arguments),
    )?;
    if !output.status.success() {
        return Err(CandidatePublishError::GitQuery);
    }
    let value = std::str::from_utf8(&output.stdout)
        .map_err(|_| CandidatePublishError::GitQuery)?
        .trim();
    if value.is_empty() {
        return Err(CandidatePublishError::GitQuery);
    }
    Ok(value.to_owned())
}

fn bounded_output(command: &mut Command) -> Result<Output, CandidatePublishError> {
    let output = command.output().map_err(CandidatePublishError::Io)?;
    if output.stdout.len().saturating_add(output.stderr.len()) > MAX_OUTPUT_BYTES {
        return Err(CandidatePublishError::OutputLimit);
    }
    Ok(output)
}

fn validate_public_id(value: &str) -> Result<(), CandidatePublishError> {
    if value.len() != 10
        || !value.starts_with("IMP-")
        || !value[4..].bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(CandidatePublishError::InvalidInput);
    }
    Ok(())
}

fn validate_object_id(value: &str) -> Result<(), CandidatePublishError> {
    if !matches!(value.len(), 40 | 64)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CandidatePublishError::InvalidInput);
    }
    Ok(())
}

#[derive(Debug)]
pub enum CandidatePublishError {
    InvalidInput,
    UnsafePath,
    CandidateMismatch,
    GitQuery,
    PushRefused,
    OutputLimit,
    Io(std::io::Error),
}

impl fmt::Display for CandidatePublishError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput => formatter.write_str("candidate publication input is invalid"),
            Self::UnsafePath => formatter.write_str("candidate worktree is unsafe"),
            Self::CandidateMismatch => formatter.write_str("candidate commit no longer matches"),
            Self::GitQuery => formatter.write_str("candidate Git query failed"),
            Self::PushRefused => formatter.write_str("candidate push was refused"),
            Self::OutputLimit => formatter.write_str("candidate Git output exceeded limit"),
            Self::Io(error) => write!(formatter, "candidate publication I/O failed: {error}"),
        }
    }
}

impl Error for CandidatePublishError {
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
    use std::fs;

    #[derive(Default)]
    struct FakePush {
        destination: Option<(String, String)>,
    }

    impl GitPush for FakePush {
        fn push(
            &mut self,
            _worktree: &Path,
            remote_url: &str,
            refspec: &str,
        ) -> Result<(), CandidatePublishError> {
            self.destination = Some((remote_url.to_owned(), refspec.to_owned()));
            Ok(())
        }
    }

    #[test]
    fn publisher_binds_the_exact_commit_to_the_fixed_repository_and_branch() {
        let root = tempfile::tempdir().expect("root");
        let repository = root.path().join("candidate");
        run(Command::new("git").arg("init").arg(&repository));
        fs::write(repository.join("README.md"), "candidate\n").expect("write");
        run(Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["add", "--all"]));
        run(Command::new("git")
            .arg("-C")
            .arg(&repository)
            .args(["-c", "user.name=test", "-c", "user.email=test.invalid"])
            .args(["commit", "-m", "candidate"]));
        let sha = git_text(&repository, &["rev-parse", "HEAD"]).expect("sha");
        let tree = git_text(&repository, &["rev-parse", "HEAD^{tree}"]).expect("tree");
        let target = RepoTarget::parse("bext-stack", "automonique").expect("target");
        let mut publisher = CandidatePublisher::new(target, FakePush::default());
        let receipt = publisher
            .publish(&repository, "IMP-000001", 7, &sha, &tree)
            .expect("publish");
        assert_eq!(receipt.branch, "automonique/IMP-000001-implementation-r7");
        assert_eq!(
            publisher.push.destination,
            Some((
                "https://github.com/bext-stack/automonique.git".to_owned(),
                format!("{sha}:refs/heads/automonique/IMP-000001-implementation-r7")
            ))
        );
    }

    fn run(command: &mut Command) {
        assert!(command.output().expect("command").status.success());
    }
}
