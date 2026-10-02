// SPDX-License-Identifier: Elastic-2.0

//! `automonique share`: publish one screenshot for a client-facing recap.
//!
//! [`crate::shot`] proves a visual change to the agent, but the capture stays
//! on the worker's disk and the client reading the GitHub recap cannot see
//! it. This verb uploads one PNG or JPEG to the operator's file-share service
//! and prints a public URL the agent embeds in its comment as `![](url)`.
//!
//! ```text
//! automonique share <image-file> --issue <github-issue-url> [--ttl-days N]
//! MONIQUE_SHARE_OK: https://share.example.test/u/0123456789abcdef.png
//! MONIQUE_SHARE_NOTE: expires 2026-01-31
//! ```
//!
//! # Captures are ephemeral
//!
//! A capture proves a point in a recap; it is not an archive. Every upload
//! asks the service to expire it after `ttl_days` (configuration, default
//! [`DEFAULT_TTL_DAYS`]) or `--ttl-days`, both within
//! [`MIN_TTL_DAYS`]..=[`MAX_TTL_DAYS`]. The second output line says when the
//! link stops working, or `link does not expire` when the service applied no
//! expiry (an older service ignores the request field), so the agent never
//! has to guess how long its recap can lean on the image.
//!
//! # Configuration
//!
//! Everything about the deployment comes from one private frame in the state
//! directory, `share/share.conf`. There is no default host: an absent file
//! means the verb is not configured and it says so.
//!
//! ```text
//! schema=automonique.share/v1
//! ingest_url=https://share.example.test/api/attachments/ingest
//! secret=<the service's ingest secret>
//! public_base=https://share.example.test
//! ttl_days=30
//! end=automonique.share/v1
//! ```
//!
//! `ttl_days` is optional.
//!
//! # What is refused before anything is sent
//!
//! The image must be a regular file (not a symbolic link), at most
//! [`MAX_IMAGE_BYTES`], and a PNG or JPEG by its content rather than its
//! name. `--issue` must be a `https://github.com/<owner>/<repo>/issues/<n>`
//! or `/pull/<n>` URL. The URL the service returns must be `https` and live
//! under `public_base`, so a confused or hostile answer cannot put an
//! arbitrary link in a comment the client reads. The ingest secret is never
//! printed and is redacted in `Debug`.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::Read as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

use crate::ticket_reactions::TicketKey;
use crate::worker_verb::{
    FrameRefusal, HttpReply, JsonPost, VerbOutcome, error_token, frame, header_safe_secret,
    read_private,
};

/// Success marker the agent looks for.
pub const OK_MARKER: &str = "MONIQUE_SHARE_OK:";
/// Failure marker the agent looks for.
pub const FAIL_MARKER: &str = "MONIQUE_SHARE_FAIL:";
/// Usage line printed when the arguments are refused.
pub const USAGE: &str =
    "usage: automonique share <image-file> --issue <github-issue-url> [--ttl-days N]";
/// Marker of the second output line, which says how long the link lives.
pub const NOTE_MARKER: &str = "MONIQUE_SHARE_NOTE:";

/// Shortest lifetime an upload may be given, in days.
pub const MIN_TTL_DAYS: u32 = 1;
/// Longest lifetime an upload may be given, in days.
pub const MAX_TTL_DAYS: u32 = 365;
/// Lifetime used when neither the configuration nor the command names one.
pub const DEFAULT_TTL_DAYS: u32 = 30;
const SECONDS_PER_DAY: u64 = 86_400;

/// Largest image this verb uploads.
pub const MAX_IMAGE_BYTES: u64 = 5 * 1024 * 1024;
/// Whole-call budget for the upload.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Ceiling on the service's answer, which is one small JSON object.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Header the ingest secret travels in.
const SECRET_HEADER: &str = "x-share-ingest-secret";
/// Configuration path beneath the state directory.
const CONFIG_RELATIVE: &str = "share/share.conf";
const CONFIG_HEADER: &str = "schema=automonique.share/v1";
const CONFIG_TERMINATOR: &str = "end=automonique.share/v1";
/// Longest URL admitted in the configuration or accepted from the service.
const MAX_URL_BYTES: usize = 512;
/// Longest scope identifier the service accepts.
const MAX_TARGET_ID_BYTES: usize = 160;

/// Why a present share configuration was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareConfigError {
    /// The file is not a private owner-only regular file within its bound.
    Insecure,
    /// The file could not be read.
    Unreadable,
    /// Bad frame, or an unknown or duplicate key.
    Malformed,
    /// `ingest_url` is absent or is not an `https://` URL.
    IngestUrlInvalid,
    /// `secret` is absent, empty, over-long, or not visible ASCII.
    SecretInvalid,
    /// `public_base` is absent or is not a bare `https://` origin.
    PublicBaseInvalid,
    /// `ttl_days` is not an integer inside [`MIN_TTL_DAYS`] to
    /// [`MAX_TTL_DAYS`].
    TtlInvalid,
}

impl fmt::Display for ShareConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Insecure => "share configuration is not a private owner-only regular file",
            Self::Unreadable => "share configuration is unreadable",
            Self::Malformed => "share configuration frame is malformed or truncated",
            Self::IngestUrlInvalid => "share configuration ingest_url is invalid",
            Self::SecretInvalid => "share configuration secret is invalid",
            Self::PublicBaseInvalid => "share configuration public_base is invalid",
            Self::TtlInvalid => "share configuration ttl_days is invalid",
        })
    }
}

impl std::error::Error for ShareConfigError {}

impl From<FrameRefusal> for ShareConfigError {
    fn from(refusal: FrameRefusal) -> Self {
        match refusal {
            FrameRefusal::Insecure => Self::Insecure,
            FrameRefusal::Unreadable => Self::Unreadable,
            FrameRefusal::Malformed => Self::Malformed,
        }
    }
}

/// A validated share configuration. Holding one means the operator
/// authorized uploads to the service it names.
pub struct ShareConfig {
    ingest_url: String,
    secret: Zeroizing<String>,
    public_base: String,
    ttl_days: u32,
}

impl fmt::Debug for ShareConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ShareConfig")
            .field("ingest_url", &self.ingest_url)
            .field("secret", &"<redacted>")
            .field("public_base", &self.public_base)
            .field("ttl_days", &self.ttl_days)
            .finish()
    }
}

impl ShareConfig {
    /// Configuration file location beneath `state_dir`.
    #[must_use]
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(CONFIG_RELATIVE)
    }

    /// Load the configuration, distinguishing "not configured" (`Ok(None)`)
    /// from "configured but wrong" (`Err`).
    ///
    /// # Errors
    ///
    /// Returns [`ShareConfigError`] naming which part of a present file was
    /// refused.
    pub fn load(state_dir: &Path) -> Result<Option<Self>, ShareConfigError> {
        match read_private(&Self::path(state_dir))? {
            Some(text) => Self::parse(&text).map(Some),
            None => Ok(None),
        }
    }

    pub(crate) fn parse(text: &str) -> Result<Self, ShareConfigError> {
        let mut ingest_url = None;
        let mut secret = None;
        let mut public_base = None;
        let mut ttl_days = None;
        for (key, value) in frame(text, CONFIG_HEADER, CONFIG_TERMINATOR)? {
            match key {
                "ingest_url" if ingest_url.is_none() => {
                    if !https_url(value) {
                        return Err(ShareConfigError::IngestUrlInvalid);
                    }
                    ingest_url = Some(value.to_owned());
                }
                "secret" if secret.is_none() => {
                    if !header_safe_secret(value) {
                        return Err(ShareConfigError::SecretInvalid);
                    }
                    secret = Some(Zeroizing::new(value.to_owned()));
                }
                "public_base" if public_base.is_none() => {
                    let origin = value.strip_suffix('/').unwrap_or(value);
                    if !https_origin(origin) {
                        return Err(ShareConfigError::PublicBaseInvalid);
                    }
                    public_base = Some(origin.to_owned());
                }
                "ttl_days" if ttl_days.is_none() => {
                    ttl_days = Some(parse_ttl_days(value).ok_or(ShareConfigError::TtlInvalid)?);
                }
                _ => return Err(ShareConfigError::Malformed),
            }
        }
        Ok(Self {
            ingest_url: ingest_url.ok_or(ShareConfigError::IngestUrlInvalid)?,
            secret: secret.ok_or(ShareConfigError::SecretInvalid)?,
            public_base: public_base.ok_or(ShareConfigError::PublicBaseInvalid)?,
            ttl_days: ttl_days.unwrap_or(DEFAULT_TTL_DAYS),
        })
    }
}

/// A lifetime in whole days, written in plain decimal digits and inside
/// [`MIN_TTL_DAYS`]..=[`MAX_TTL_DAYS`].
fn parse_ttl_days(value: &str) -> Option<u32> {
    if value.is_empty() || value.len() > 3 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value
        .parse()
        .ok()
        .filter(|days| (MIN_TTL_DAYS..=MAX_TTL_DAYS).contains(days))
}

/// An `https://` URL with a host, no credentials, and nothing that would
/// edit the text it is later embedded in.
fn https_url(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    !authority.is_empty()
        && !authority.contains('@')
        && value.len() <= MAX_URL_BYTES
        && value.bytes().all(|byte| {
            byte.is_ascii_graphic()
                && !matches!(
                    byte,
                    b'"' | b'\'' | b'\\' | b'<' | b'>' | b'(' | b')' | b'[' | b']' | b'`'
                )
        })
}

/// An `https://host[:port]` origin with no path, query or fragment.
fn https_origin(value: &str) -> bool {
    https_url(value)
        && value
            .strip_prefix("https://")
            .is_some_and(|rest| !rest.contains(['/', '?', '#']))
}

/// One parsed invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShareRequest {
    /// The image to upload.
    pub image: PathBuf,
    /// The scope the service files the upload under, derived from the ticket.
    pub target_id: String,
    /// Lifetime named on the command line, overriding the configuration.
    pub ttl_days: Option<u32>,
}

/// Parse `share <image-file> --issue <github-issue-url> [--ttl-days N]`.
///
/// # Errors
///
/// Returns one sentence naming the refused argument.
pub fn parse(values: &[OsString]) -> Result<ShareRequest, String> {
    let mut image = None;
    let mut issue = None;
    let mut ttl_days = None;
    let mut values = values.iter();
    while let Some(value) = values.next() {
        let text = value
            .to_str()
            .ok_or_else(|| String::from("arguments must be UTF-8"))?;
        match text {
            "--issue" if issue.is_none() => {
                issue = Some(
                    values
                        .next()
                        .and_then(|value| value.to_str())
                        .ok_or_else(|| String::from("--issue needs a GitHub issue URL"))?,
                );
            }
            "--ttl-days" if ttl_days.is_none() => {
                ttl_days = Some(
                    values
                        .next()
                        .and_then(|value| value.to_str())
                        .and_then(parse_ttl_days)
                        .ok_or_else(|| {
                            format!(
                                "--ttl-days needs a whole number of days in {MIN_TTL_DAYS}..={MAX_TTL_DAYS}"
                            )
                        })?,
                );
            }
            other if other.starts_with("--") => return Err(format!("unknown option {other}")),
            other if image.is_none() && !other.is_empty() => image = Some(PathBuf::from(other)),
            other => return Err(format!("unexpected argument {other:?}")),
        }
    }
    let image = image.ok_or_else(|| String::from("an image file is required"))?;
    let issue = issue.ok_or_else(|| String::from("--issue <github-issue-url> is required"))?;
    let target_id = issue_target_id(issue).ok_or_else(|| {
        String::from(
            "--issue must be a https://github.com/<owner>/<repo>/issues/<n> or /pull/<n> URL",
        )
    })?;
    Ok(ShareRequest {
        image,
        target_id,
        ttl_days,
    })
}

/// The service scope for one GitHub ticket: `gh:<owner>:<repo>:<number>`.
///
/// The service admits `[A-Za-z0-9._:-]{1,160}` and nothing else, so the
/// ticket's case-folded `owner/repo#number` identity is respelled with `:`
/// separators and any other byte (an underscore in a repository name)
/// becomes `-`. The scope only groups uploads on the service's side; it is
/// never parsed back into a ticket.
fn issue_target_id(url: &str) -> Option<String> {
    let path = url.strip_prefix("https://github.com/")?;
    // Exactly owner/repo/(issues|pull)/<digits>, then at most a fragment or a
    // query: a comment permalink names the same ticket, a longer path does not.
    let mut segments = path.split('/');
    let (_owner, _repo, kind, tail) = (
        segments.next()?,
        segments.next()?,
        segments.next()?,
        segments.next()?,
    );
    if segments.next().is_some() || !matches!(kind, "issues" | "pull") {
        return None;
    }
    let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 || !matches!(tail.as_bytes().get(digits), None | Some(b'#' | b'?')) {
        return None;
    }
    let (key, _) = TicketKey::parse_url(url)?;
    let scope: String = key
        .identity()
        .chars()
        .map(|character| match character {
            '/' | '#' => ':',
            other if other.is_ascii_alphanumeric() || matches!(other, '.' | '-') => other,
            _ => '-',
        })
        .collect();
    let target_id = format!("gh:{scope}");
    (target_id.len() <= MAX_TARGET_ID_BYTES).then_some(target_id)
}

/// The two image formats this verb uploads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageKind {
    Png,
    Jpeg,
}

impl ImageKind {
    const fn content_type(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
        }
    }

    const fn extension(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpg",
        }
    }
}

/// Tell a PNG or a JPEG by its bytes; the file's name is not evidence.
///
/// The checks match what the service itself verifies, so a file accepted
/// here is not refused there: a PNG signature followed by an `IHDR` chunk
/// with non-zero dimensions, or a JPEG that starts with `SOI` and ends with
/// `EOI`.
#[must_use]
pub fn sniff(bytes: &[u8]) -> Option<ImageKind> {
    const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    let word = |at: usize| {
        bytes
            .get(at..at + 4)
            .map(|quad| u32::from_be_bytes([quad[0], quad[1], quad[2], quad[3]]))
    };
    if bytes.starts_with(&PNG_SIGNATURE) {
        let header = word(8) == Some(13) && bytes.get(12..16) == Some(b"IHDR".as_slice());
        let sized =
            word(16).is_some_and(|width| width > 0) && word(20).is_some_and(|height| height > 0);
        return (header && sized).then_some(ImageKind::Png);
    }
    if bytes.len() >= 16 && bytes.starts_with(&[0xff, 0xd8, 0xff]) && bytes.ends_with(&[0xff, 0xd9])
    {
        return Some(ImageKind::Jpeg);
    }
    None
}

/// Read the image, refusing anything this verb must not upload.
///
/// # Errors
///
/// Returns one sentence: missing file, symbolic link, not a regular file,
/// empty, over [`MAX_IMAGE_BYTES`], or neither PNG nor JPEG by content.
pub fn read_image(path: &Path) -> Result<(Vec<u8>, ImageKind), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| String::from("the image file does not exist"))?;
    if metadata.file_type().is_symlink() {
        return Err(String::from(
            "the image must be a regular file, not a symbolic link",
        ));
    }
    if !metadata.is_file() {
        return Err(String::from("the image must be a regular file"));
    }
    if metadata.len() > MAX_IMAGE_BYTES {
        return Err(String::from("the image is larger than 5 MiB"));
    }
    // The path is opened without following a link and the descriptor is
    // checked again, so a file swapped between the two looks is still refused.
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_CLOEXEC | nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| String::from("the image file could not be opened"))?;
    if !file
        .metadata()
        .map_err(|_| String::from("the image file could not be read"))?
        .is_file()
    {
        return Err(String::from("the image must be a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_IMAGE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| String::from("the image file could not be read"))?;
    if bytes.is_empty() {
        return Err(String::from("the image file is empty"));
    }
    if bytes.len() as u64 > MAX_IMAGE_BYTES {
        return Err(String::from("the image is larger than 5 MiB"));
    }
    let kind = sniff(&bytes).ok_or_else(|| {
        String::from("the image must be a PNG or a JPEG (checked by content, not by name)")
    })?;
    Ok((bytes, kind))
}

/// The filename the service stores: the local base name when it is plain,
/// otherwise a neutral one. Never a directory, so no local path leaves the
/// host.
fn upload_filename(path: &Path, kind: ImageKind) -> String {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| {
            !stem.is_empty()
                && stem.len() <= 80
                && !stem.starts_with('.')
                && stem
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
        .unwrap_or("capture");
    format!("{stem}.{}", kind.extension())
}

/// The exact JSON body of one ingest request.
fn ingest_body(request: &ShareRequest, ttl_days: u32, bytes: &[u8], kind: ImageKind) -> String {
    serde_json::json!({
        "target_kind": "issue",
        "target_id": request.target_id,
        "content_type": kind.content_type(),
        "filename": upload_filename(&request.image, kind),
        "owner_sub": "automonique-worker",
        "owner_name": "Monique",
        "expires_in_seconds": u64::from(ttl_days) * SECONDS_PER_DAY,
        "content_base64": crate::improvement_github::base64(bytes),
    })
    .to_string()
}

/// How long a published link lives, as the service reported it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expiry {
    /// The service applied no expiry: an older service ignores the request
    /// field and keeps the upload.
    Never,
    /// The calendar day (`YYYY-MM-DD`) the link stops working.
    On(String),
    /// The service reported an expiry this verb could not read as a date.
    Unreadable,
}

/// One published image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Shared {
    /// Public URL to embed in the recap.
    pub url: String,
    /// When that URL stops working.
    pub expiry: Expiry,
}

impl Shared {
    /// The second output line: what the agent must know about the link's
    /// lifetime before it leans on the image in a recap.
    #[must_use]
    pub fn note(&self) -> String {
        match &self.expiry {
            Expiry::Never => format!("{NOTE_MARKER} link does not expire"),
            Expiry::On(day) => format!("{NOTE_MARKER} expires {day}"),
            Expiry::Unreadable => format!("{NOTE_MARKER} expires (date not reported)"),
        }
    }
}

/// The `YYYY-MM-DD` day an ISO-8601 instant starts with, when it is one.
fn iso_day(instant: &str) -> Option<&str> {
    let day = instant.get(..10)?;
    let bytes = day.as_bytes();
    let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    if !(digits(0..4) && bytes[4] == b'-' && digits(5..7) && bytes[7] == b'-' && digits(8..10)) {
        return None;
    }
    let month: u8 = day[5..7].parse().ok()?;
    let date: u8 = day[8..10].parse().ok()?;
    let followed = matches!(instant.as_bytes().get(10), None | Some(b'T' | b't' | b' '));
    (followed && (1..=12).contains(&month) && (1..=31).contains(&date)).then_some(day)
}

/// Read the public URL and its expiry out of the service's answer.
///
/// # Errors
///
/// Returns one sentence when the service refused, answered something that is
/// not its contract, or returned a URL outside `public_base`.
fn shared(config: &ShareConfig, reply: &HttpReply) -> Result<Shared, String> {
    if reply.status != 200 {
        return Err(match error_token(&reply.body) {
            Some(token) => format!(
                "the share service refused the upload (HTTP {}: {token})",
                reply.status
            ),
            None => format!(
                "the share service refused the upload (HTTP {})",
                reply.status
            ),
        });
    }
    let unusable = || String::from("the share service answered with an unusable response");
    let value: serde_json::Value = serde_json::from_slice(&reply.body).map_err(|_| unusable())?;
    if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(unusable());
    }
    let attachment = value.get("attachment").ok_or_else(unusable)?;
    let url = attachment
        .get("url")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(unusable)?;
    let under_base = url
        .strip_prefix(config.public_base.as_str())
        .is_some_and(|rest| rest.starts_with('/') && rest.len() > 1);
    if !https_url(url) || !under_base {
        return Err(String::from(
            "the share service returned a URL outside the configured public_base",
        ));
    }
    let expiry = match attachment.get("expires_at") {
        None | Some(serde_json::Value::Null) => Expiry::Never,
        Some(reported) => reported
            .as_str()
            .and_then(iso_day)
            .map_or(Expiry::Unreadable, |day| Expiry::On(day.to_owned())),
    };
    Ok(Shared {
        url: url.to_owned(),
        expiry,
    })
}

/// Upload one image and return its public URL and expiry. Every local refusal happens
/// before `transport` is touched.
///
/// # Errors
///
/// Returns one sentence suitable for a failure marker. It never contains the
/// ingest secret.
pub fn publish(
    config: &ShareConfig,
    request: &ShareRequest,
    transport: &dyn JsonPost,
) -> Result<Shared, String> {
    let (bytes, kind) = read_image(&request.image)?;
    let ttl_days = request.ttl_days.unwrap_or(config.ttl_days);
    let body = ingest_body(request, ttl_days, &bytes, kind);
    let reply = transport
        .post_json(
            &config.ingest_url,
            &[(SECRET_HEADER, config.secret.as_str())],
            &body,
        )
        .map_err(|failure| format!("share upload failed: {}", failure.reason()))?;
    shared(config, &reply)
}

/// The whole verb: arguments, configuration, upload, marker line.
#[must_use]
pub fn run(state_dir: Option<&Path>, values: &[OsString], transport: &dyn JsonPost) -> VerbOutcome {
    let request = match parse(values) {
        Ok(request) => request,
        Err(reason) => return VerbOutcome::usage(FAIL_MARKER, &reason, USAGE),
    };
    let Some(state_dir) = state_dir else {
        return VerbOutcome::failed(FAIL_MARKER, "share is not configured on this host");
    };
    let config = match ShareConfig::load(state_dir) {
        Ok(Some(config)) => config,
        Ok(None) => {
            return VerbOutcome::failed(FAIL_MARKER, "share is not configured on this host");
        }
        Err(error) => return VerbOutcome::failed(FAIL_MARKER, &error.to_string()),
    };
    match publish(&config, &request, transport) {
        Ok(shared) => VerbOutcome::ok(vec![format!("{OK_MARKER} {}", shared.url), shared.note()]),
        Err(reason) => VerbOutcome::failed(FAIL_MARKER, &reason),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use crate::worker_verb::PostFailure;
    use crate::worker_verb::testing::FakePost;

    const ISSUE: &str = "https://github.com/example/project/issues/42";
    const SECRET: &str = "fixture-ingest-secret";
    const OK_REPLY: &str = r#"{"ok":true,"attachment":{"id":"0123456789abcdef","url":"https://share.example.test/u/0123456789abcdef.png","viewer_url":"https://share.example.test/s/0123456789abcdef","expires_at":"2026-01-31T09:30:00.000Z"}}"#;
    /// What a service that predates ephemeral uploads answers.
    const PERMANENT_REPLY: &str = r#"{"ok":true,"attachment":{"id":"0123456789abcdef","url":"https://share.example.test/u/0123456789abcdef.png"}}"#;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    fn conf(lines: &[&str]) -> String {
        format!(
            "{CONFIG_HEADER}\n{}\n{CONFIG_TERMINATOR}\n",
            lines.join("\n")
        )
    }

    fn valid_conf() -> String {
        conf(&[
            "ingest_url=https://share.example.test/api/attachments/ingest",
            &format!("secret={SECRET}"),
            "public_base=https://share.example.test",
        ])
    }

    /// The smallest byte string [`sniff`] reads as a PNG.
    fn png() -> Vec<u8> {
        let mut bytes = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
        bytes.extend_from_slice(&13_u32.to_be_bytes());
        bytes.extend_from_slice(b"IHDR");
        bytes.extend_from_slice(&2_u32.to_be_bytes());
        bytes.extend_from_slice(&3_u32.to_be_bytes());
        bytes.extend_from_slice(&[8, 6, 0, 0, 0]);
        bytes
    }

    fn jpeg() -> Vec<u8> {
        let mut bytes = vec![0xff, 0xd8, 0xff, 0xe0];
        bytes.extend_from_slice(&[0; 16]);
        bytes.extend_from_slice(&[0xff, 0xd9]);
        bytes
    }

    /// A state directory holding `text` as a private share configuration.
    fn state_with(text: &str) -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("tempdir");
        let path = ShareConfig::path(root.path());
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(&path, text).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        root
    }

    fn image_in(root: &Path, name: &str, bytes: &[u8]) -> String {
        let path = root.join(name);
        fs::write(&path, bytes).expect("write image");
        path.to_str().expect("utf8 path").to_owned()
    }

    #[test]
    fn the_configuration_frame_is_strict_and_has_no_default_host() {
        let config = ShareConfig::parse(&valid_conf()).expect("valid");
        assert_eq!(
            config.ingest_url,
            "https://share.example.test/api/attachments/ingest"
        );
        assert_eq!(config.public_base, "https://share.example.test");
        assert_eq!(config.ttl_days, DEFAULT_TTL_DAYS);
        let trailing = ShareConfig::parse(&conf(&[
            "ingest_url=https://share.example.test/api/attachments/ingest",
            "secret=s",
            "public_base=https://share.example.test/",
        ]))
        .expect("a trailing slash on the origin is tolerated");
        assert_eq!(trailing.public_base, "https://share.example.test");

        let refused = |lines: &[&str]| ShareConfig::parse(&conf(lines)).expect_err("refused");
        assert_eq!(
            refused(&["secret=s", "public_base=https://share.example.test"]),
            ShareConfigError::IngestUrlInvalid
        );
        assert_eq!(
            refused(&[
                "ingest_url=http://share.example.test/ingest",
                "secret=s",
                "public_base=https://share.example.test"
            ]),
            ShareConfigError::IngestUrlInvalid
        );
        assert_eq!(
            refused(&[
                "ingest_url=https://user@share.example.test/ingest",
                "secret=s",
                "public_base=https://share.example.test"
            ]),
            ShareConfigError::IngestUrlInvalid
        );
        assert_eq!(
            refused(&[
                "ingest_url=https://share.example.test/ingest",
                "public_base=https://share.example.test"
            ]),
            ShareConfigError::SecretInvalid
        );
        assert_eq!(
            refused(&[
                "ingest_url=https://share.example.test/ingest",
                "secret=two words",
                "public_base=https://share.example.test"
            ]),
            ShareConfigError::SecretInvalid
        );
        assert_eq!(
            refused(&["ingest_url=https://share.example.test/ingest", "secret=s"]),
            ShareConfigError::PublicBaseInvalid
        );
        assert_eq!(
            refused(&[
                "ingest_url=https://share.example.test/ingest",
                "secret=s",
                "public_base=https://share.example.test/u"
            ]),
            ShareConfigError::PublicBaseInvalid
        );
        assert_eq!(
            refused(&[
                "ingest_url=https://share.example.test/ingest",
                "secret=s",
                "secret=t",
                "public_base=https://share.example.test"
            ]),
            ShareConfigError::Malformed
        );
        assert_eq!(
            refused(&[
                "ingest_url=https://share.example.test/ingest",
                "secret=s",
                "public_base=https://share.example.test",
                "extra=1"
            ]),
            ShareConfigError::Malformed
        );
        assert_eq!(
            ShareConfig::parse("ingest_url=https://share.example.test/ingest\n")
                .expect_err("no frame"),
            ShareConfigError::Malformed
        );
    }

    #[test]
    fn the_secret_is_redacted_in_debug() {
        let config = ShareConfig::parse(&valid_conf()).expect("valid");
        let rendered = format!("{config:?}");
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains(SECRET));
    }

    #[test]
    fn a_group_readable_configuration_is_refused_and_an_absent_one_is_not_configured() {
        let root = state_with(&valid_conf());
        let path = ShareConfig::path(root.path());
        assert!(ShareConfig::load(root.path()).expect("loads").is_some());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("chmod");
        assert_eq!(
            ShareConfig::load(root.path()).expect_err("insecure"),
            ShareConfigError::Insecure
        );
        let empty = tempfile::tempdir().expect("tempdir");
        assert!(ShareConfig::load(empty.path()).expect("absent").is_none());
    }

    #[test]
    fn only_a_github_issue_or_pull_url_scopes_an_upload() {
        assert_eq!(
            issue_target_id(ISSUE).as_deref(),
            Some("gh:example:project:42")
        );
        assert_eq!(
            issue_target_id("https://github.com/Example/My_Repo.js/pull/7").as_deref(),
            Some("gh:example:my-repo.js:7")
        );
        assert_eq!(
            issue_target_id("https://github.com/example/project/issues/42#issuecomment-9")
                .as_deref(),
            Some("gh:example:project:42")
        );
        for bad in [
            "http://github.com/example/project/issues/42",
            "https://github.com.evil.example/example/project/issues/42",
            "https://evil.example/github.com/example/project/issues/42",
            "https://github.com/example/project/issues/",
            "https://github.com/example/project/issues/42abc",
            "https://github.com/example/project/issues/42/extra",
            "https://github.com/example/project/wiki/42",
            "https://github.com/example/project",
            "example/project#42",
            "",
        ] {
            assert_eq!(issue_target_id(bad), None, "{bad}");
        }
        let scope = issue_target_id(ISSUE).expect("scope");
        assert!(
            scope
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b':' | b'-'))
        );
    }

    #[test]
    fn arguments_are_one_image_and_one_issue() {
        let request = parse(&args(&["/tmp/x.png", "--issue", ISSUE])).expect("parses");
        assert_eq!(request.image, PathBuf::from("/tmp/x.png"));
        assert_eq!(request.target_id, "gh:example:project:42");
        assert_eq!(request.ttl_days, None);
        let reordered = parse(&args(&["--issue", ISSUE, "/tmp/x.png"])).expect("parses");
        assert_eq!(reordered, request);

        assert!(parse(&args(&[])).is_err());
        assert!(parse(&args(&["/tmp/x.png"])).is_err());
        assert!(parse(&args(&["--issue", ISSUE])).is_err());
        assert!(parse(&args(&["/tmp/x.png", "--issue"])).is_err());
        assert!(parse(&args(&["/tmp/x.png", "/tmp/y.png", "--issue", ISSUE])).is_err());
        assert!(parse(&args(&["/tmp/x.png", "--issue", ISSUE, "--bogus"])).is_err());
        assert!(parse(&args(&["/tmp/x.png", "--issue", "https://example.test/1"])).is_err());
    }

    #[test]
    fn an_image_is_told_by_its_bytes_not_its_name() {
        assert_eq!(sniff(&png()), Some(ImageKind::Png));
        assert_eq!(sniff(&jpeg()), Some(ImageKind::Jpeg));
        assert_eq!(sniff(b"<svg xmlns='http://www.w3.org/2000/svg'/>"), None);
        assert_eq!(
            sniff(b"GIF89a\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00"),
            None
        );
        assert_eq!(sniff(&png()[..8]), None, "a bare signature is not an image");
        let mut zero_width = png();
        zero_width[16..20].copy_from_slice(&0_u32.to_be_bytes());
        assert_eq!(sniff(&zero_width), None);
        let mut truncated = jpeg();
        truncated.pop();
        assert_eq!(sniff(&truncated), None, "a JPEG must end with EOI");
        assert_eq!(sniff(&[]), None);
    }

    #[test]
    fn unsafe_files_are_refused_before_any_network_call() {
        let state = state_with(&valid_conf());
        let work = tempfile::tempdir().expect("tempdir");
        let transport = FakePost::answering(200, OK_REPLY);
        let attempt = |path: &str| {
            let outcome = run(
                Some(state.path()),
                &args(&[path, "--issue", ISSUE]),
                &transport,
            );
            assert_eq!(outcome.code, 1, "{path}");
            assert_eq!(outcome.lines.len(), 1);
            assert!(outcome.lines[0].starts_with("MONIQUE_SHARE_FAIL: "));
            outcome.lines[0].clone()
        };

        let missing = work.path().join("missing.png");
        assert!(attempt(missing.to_str().expect("utf8")).contains("does not exist"));

        let real = image_in(work.path(), "real.png", &png());
        let link = work.path().join("link.png");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(attempt(link.to_str().expect("utf8")).contains("symbolic link"));

        assert!(attempt(work.path().to_str().expect("utf8")).contains("regular file"));

        let renamed = image_in(
            work.path(),
            "page.png",
            b"<html><body>not an image</body></html>",
        );
        assert!(attempt(&renamed).contains("PNG or a JPEG"));

        let empty = image_in(work.path(), "empty.png", b"");
        assert!(attempt(&empty).contains("empty"));

        let mut oversized = png();
        oversized.resize(MAX_IMAGE_BYTES as usize + 1, 0);
        let oversized = image_in(work.path(), "big.png", &oversized);
        assert!(attempt(&oversized).contains("larger than 5 MiB"));

        assert_eq!(transport.calls(), 0, "nothing was sent for a refused file");
    }

    #[test]
    fn a_missing_or_refused_configuration_fails_without_a_network_call() {
        let work = tempfile::tempdir().expect("tempdir");
        let image = image_in(work.path(), "ok.png", &png());
        let transport = FakePost::answering(200, OK_REPLY);
        let values = args(&[&image, "--issue", ISSUE]);

        let unconfigured = tempfile::tempdir().expect("tempdir");
        for outcome in [
            run(Some(unconfigured.path()), &values, &transport),
            run(None, &values, &transport),
        ] {
            assert_eq!(outcome.code, 1);
            assert_eq!(
                outcome.lines,
                vec![String::from(
                    "MONIQUE_SHARE_FAIL: share is not configured on this host"
                )]
            );
        }

        let broken = state_with("schema=automonique.share/v1\ningest_url=ftp://x\n");
        let outcome = run(Some(broken.path()), &values, &transport);
        assert_eq!(outcome.code, 1);
        assert!(outcome.lines[0].starts_with("MONIQUE_SHARE_FAIL: share configuration"));

        let usage = run(Some(unconfigured.path()), &args(&[&image]), &transport);
        assert_eq!(usage.code, 2);
        assert_eq!(usage.usage, Some(USAGE));
        assert!(usage.lines[0].starts_with("MONIQUE_SHARE_FAIL: "));

        assert_eq!(transport.calls(), 0);
    }

    #[test]
    fn a_successful_upload_prints_the_public_url_and_sends_the_service_contract() {
        let state = state_with(&valid_conf());
        let work = tempfile::tempdir().expect("tempdir");
        let image = image_in(work.path(), "monique-demande-1.png", &png());
        let transport = FakePost::answering(200, OK_REPLY);
        let outcome = run(
            Some(state.path()),
            &args(&[&image, "--issue", ISSUE]),
            &transport,
        );
        assert_eq!(outcome.code, 0);
        assert_eq!(
            outcome.lines,
            vec![
                String::from("MONIQUE_SHARE_OK: https://share.example.test/u/0123456789abcdef.png"),
                String::from("MONIQUE_SHARE_NOTE: expires 2026-01-31"),
            ]
        );

        let sent = transport.sent.borrow();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].url,
            "https://share.example.test/api/attachments/ingest"
        );
        assert_eq!(
            sent[0].headers,
            vec![(String::from("x-share-ingest-secret"), String::from(SECRET))]
        );
        let body: serde_json::Value = serde_json::from_str(&sent[0].body).expect("json body");
        assert_eq!(body["target_kind"], "issue");
        assert_eq!(body["target_id"], "gh:example:project:42");
        assert_eq!(body["content_type"], "image/png");
        assert_eq!(body["expires_in_seconds"], 30 * 86_400);
        assert_eq!(body["filename"], "monique-demande-1.png");
        assert_eq!(
            body["content_base64"],
            crate::improvement_github::base64(&png())
        );
        assert!(
            !sent[0].body.contains(work.path().to_str().expect("utf8")),
            "the local directory never leaves the host"
        );
        assert!(!sent[0].body.contains(SECRET));
        assert!(!outcome.lines.join("\n").contains(SECRET));
    }

    #[test]
    fn a_jpeg_is_sent_as_a_jpeg_whatever_its_name() {
        let state = state_with(&valid_conf());
        let work = tempfile::tempdir().expect("tempdir");
        let image = image_in(work.path(), "odd name!.png", &jpeg());
        let transport = FakePost::answering(200, OK_REPLY);
        let outcome = run(
            Some(state.path()),
            &args(&[&image, "--issue", ISSUE]),
            &transport,
        );
        assert_eq!(outcome.code, 0);
        let sent = transport.sent.borrow();
        let body: serde_json::Value = serde_json::from_str(&sent[0].body).expect("json body");
        assert_eq!(body["content_type"], "image/jpeg");
        assert_eq!(body["filename"], "capture.jpg");
    }

    #[test]
    fn the_returned_url_must_be_https_under_the_public_base() {
        let config = ShareConfig::parse(&valid_conf()).expect("valid");
        let answer = |status: u16, body: &str| {
            shared(
                &config,
                &HttpReply {
                    status,
                    body: body.as_bytes().to_vec(),
                },
            )
            .map(|shared| shared.url)
        };
        assert_eq!(
            answer(200, OK_REPLY).as_deref(),
            Ok("https://share.example.test/u/0123456789abcdef.png")
        );
        for url in [
            "http://share.example.test/u/a.png",
            "https://share.example.test.evil.example/u/a.png",
            "https://evil.example/u/a.png",
            "https://share.example.test",
            "https://share.example.test/",
            "https://share.example.test/u/a.png) [x](https://evil.example",
            "https://share.example.test/u/a b.png",
            "javascript:alert(1)",
        ] {
            let body = serde_json::json!({"ok": true, "attachment": {"url": url}}).to_string();
            assert_eq!(
                answer(200, &body),
                Err(String::from(
                    "the share service returned a URL outside the configured public_base"
                )),
                "{url}"
            );
        }
        for body in [
            "not json",
            "{}",
            r#"{"ok":false,"attachment":{"url":"https://share.example.test/u/a.png"}}"#,
            r#"{"ok":true}"#,
            r#"{"ok":true,"attachment":{"url":7}}"#,
            r#"{"ok":true,"attachment":{"expires_at":"2026-01-31T09:30:00Z"}}"#,
        ] {
            assert_eq!(
                answer(200, body),
                Err(String::from(
                    "the share service answered with an unusable response"
                )),
                "{body}"
            );
        }
        assert_eq!(
            answer(415, r#"{"ok":false,"error":"unsupported_type"}"#),
            Err(String::from(
                "the share service refused the upload (HTTP 415: unsupported_type)"
            ))
        );
        assert_eq!(
            answer(400, r#"{"ok":false,"error":"invalid_expiry"}"#),
            Err(String::from(
                "the share service refused the upload (HTTP 400: invalid_expiry)"
            ))
        );
        assert_eq!(
            answer(502, "<html>bad gateway</html>"),
            Err(String::from(
                "the share service refused the upload (HTTP 502)"
            ))
        );
    }

    #[test]
    fn a_transport_failure_is_one_marker_line_without_the_secret() {
        let state = state_with(&valid_conf());
        let work = tempfile::tempdir().expect("tempdir");
        let image = image_in(work.path(), "ok.png", &png());
        for (failure, expected) in [
            (PostFailure::TimedOut, "did not answer in time"),
            (PostFailure::ResponseTooLarge, "oversized response"),
            (PostFailure::Unavailable, "unreachable"),
        ] {
            let transport = FakePost::failing(failure);
            let outcome = run(
                Some(state.path()),
                &args(&[&image, "--issue", ISSUE]),
                &transport,
            );
            assert_eq!(outcome.code, 1);
            assert_eq!(outcome.lines.len(), 1, "a failure carries no note line");
            assert!(outcome.lines[0].starts_with("MONIQUE_SHARE_FAIL: share upload failed: "));
            assert!(outcome.lines[0].contains(expected));
            assert!(!outcome.lines[0].contains(SECRET));
        }
    }

    #[test]
    fn the_lifetime_is_bounded_in_the_configuration_and_on_the_command_line() {
        for (text, days) in [("1", 1), ("30", 30), ("365", 365), ("007", 7)] {
            assert_eq!(parse_ttl_days(text), Some(days), "{text}");
        }
        for bad in [
            "", "0", "366", "1000", "-1", "+5", "1.5", " 7", "7d", "seven",
        ] {
            assert_eq!(parse_ttl_days(bad), None, "{bad}");
            let lines = [
                "ingest_url=https://share.example.test/api/attachments/ingest",
                "secret=s",
                "public_base=https://share.example.test",
                &format!("ttl_days={bad}"),
            ];
            assert_eq!(
                ShareConfig::parse(&conf(&lines)).expect_err("refused"),
                ShareConfigError::TtlInvalid,
                "{bad}"
            );
            assert!(
                parse(&args(&["/tmp/x.png", "--issue", ISSUE, "--ttl-days", bad])).is_err(),
                "{bad}"
            );
        }
        let configured = ShareConfig::parse(&conf(&[
            "ingest_url=https://share.example.test/api/attachments/ingest",
            "secret=s",
            "ttl_days=7",
            "public_base=https://share.example.test",
        ]))
        .expect("valid");
        assert_eq!(configured.ttl_days, 7);
        assert_eq!(
            ShareConfig::parse(&conf(&[
                "ingest_url=https://share.example.test/api/attachments/ingest",
                "secret=s",
                "ttl_days=7",
                "ttl_days=8",
                "public_base=https://share.example.test",
            ]))
            .expect_err("duplicate"),
            ShareConfigError::Malformed
        );

        let request = parse(&args(&[
            "/tmp/x.png",
            "--ttl-days",
            "365",
            "--issue",
            ISSUE,
        ]))
        .expect("parses");
        assert_eq!(request.ttl_days, Some(365));
        assert!(parse(&args(&["/tmp/x.png", "--issue", ISSUE, "--ttl-days"])).is_err());
        assert!(
            parse(&args(&[
                "/tmp/x.png",
                "--issue",
                ISSUE,
                "--ttl-days",
                "1",
                "--ttl-days",
                "2"
            ]))
            .is_err()
        );
    }

    #[test]
    fn every_upload_asks_for_an_expiry_and_the_flag_overrides_the_configuration() {
        let work = tempfile::tempdir().expect("tempdir");
        let image = image_in(work.path(), "ok.png", &png());
        let sent_seconds = |conf_text: &str, extra: &[&str]| {
            let state = state_with(conf_text);
            let transport = FakePost::answering(200, OK_REPLY);
            let mut values = vec![image.as_str(), "--issue", ISSUE];
            values.extend_from_slice(extra);
            let outcome = run(Some(state.path()), &args(&values), &transport);
            assert_eq!(outcome.code, 0);
            let sent = transport.sent.borrow();
            let body: serde_json::Value = serde_json::from_str(&sent[0].body).expect("json body");
            body["expires_in_seconds"].as_u64().expect("an integer")
        };
        let with_ttl = conf(&[
            "ingest_url=https://share.example.test/api/attachments/ingest",
            "secret=s",
            "public_base=https://share.example.test",
            "ttl_days=7",
        ]);
        assert_eq!(sent_seconds(&valid_conf(), &[]), 30 * 86_400, "default");
        assert_eq!(sent_seconds(&with_ttl, &[]), 7 * 86_400, "configuration");
        assert_eq!(sent_seconds(&with_ttl, &["--ttl-days", "2"]), 2 * 86_400);
        assert_eq!(sent_seconds(&valid_conf(), &["--ttl-days", "1"]), 86_400);
        assert_eq!(
            sent_seconds(&valid_conf(), &["--ttl-days", "365"]),
            31_536_000,
            "the longest lifetime is the service's own ceiling"
        );
    }

    #[test]
    fn the_note_line_says_when_the_link_expires_or_that_it_does_not() {
        let state = state_with(&valid_conf());
        let work = tempfile::tempdir().expect("tempdir");
        let image = image_in(work.path(), "ok.png", &png());
        let lines = |reply: &str| {
            let transport = FakePost::answering(200, reply);
            let outcome = run(
                Some(state.path()),
                &args(&[&image, "--issue", ISSUE]),
                &transport,
            );
            assert_eq!(outcome.code, 0, "{reply}");
            assert_eq!(
                outcome.lines[0],
                "MONIQUE_SHARE_OK: https://share.example.test/u/0123456789abcdef.png"
            );
            assert_eq!(outcome.lines.len(), 2);
            outcome.lines[1].clone()
        };
        assert_eq!(lines(OK_REPLY), "MONIQUE_SHARE_NOTE: expires 2026-01-31");
        assert_eq!(
            lines(PERMANENT_REPLY),
            "MONIQUE_SHARE_NOTE: link does not expire",
            "an older service ignores the expiry and the upload still succeeds"
        );
        let with_expiry = |expires_at: serde_json::Value| {
            serde_json::json!({"ok": true, "attachment": {
                "url": "https://share.example.test/u/0123456789abcdef.png",
                "expires_at": expires_at,
            }})
            .to_string()
        };
        assert_eq!(
            lines(&with_expiry(serde_json::Value::Null)),
            "MONIQUE_SHARE_NOTE: link does not expire"
        );
        assert_eq!(
            lines(&with_expiry(serde_json::json!("2026-12-01"))),
            "MONIQUE_SHARE_NOTE: expires 2026-12-01"
        );
        for unreadable in [
            serde_json::json!("soon"),
            serde_json::json!("2026-13-01T00:00:00Z"),
            serde_json::json!("2026-01-31\nMONIQUE_SHARE_OK: https://evil.example/"),
            serde_json::json!(1_800_000_000),
        ] {
            assert_eq!(
                lines(&with_expiry(unreadable)),
                "MONIQUE_SHARE_NOTE: expires (date not reported)"
            );
        }
        assert_eq!(iso_day("2026-01-31T09:30:00.000Z"), Some("2026-01-31"));
        assert_eq!(iso_day("2026-01-31"), Some("2026-01-31"));
        assert_eq!(iso_day("2026-01-3"), None);
        assert_eq!(iso_day("2026-01-311"), None);
        assert_eq!(iso_day("2026/01/31"), None);
        assert_eq!(iso_day("2026-00-10"), None);
        assert_eq!(iso_day("é026-01-31"), None);
    }
}
