// SPDX-License-Identifier: Elastic-2.0

//! The parts every outbound connector was writing for itself.
//!
//! Six helper families had been copied between the GitHub, Slack, fleet,
//! Telegram and chat-provider connectors — in one case, credential scrubbing,
//! three byte-identical times. Copies of a security-relevant routine are worse
//! than a shared one even when they agree today: a fix applied to one copy is
//! silently absent from the others, and nothing in the build says so.
//!
//! What this crate deliberately does *not* do is unify the callers' error
//! types. Each connector keeps its own closed vocabulary, because a GitHub
//! refusal and a Slack refusal are different things to a reader even when they
//! are spelled the same; the shared code returns [`http::TransportFailure`] and
//! each consumer converts. Nor does it unify the callers' limits: the response
//! ceilings differ per service on purpose, so [`http::read_bounded_body`] takes
//! the ceiling as an argument rather than owning a constant.
//!
//! `automonique-protocol` is *not* a consumer and must not become one. It has
//! zero dependencies by design, which is the property that lets it be the one
//! crate everything else can depend on.

pub mod json;
pub mod secret;
pub mod url;

#[cfg(feature = "automonique_http")]
pub mod http;
