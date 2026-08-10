// SPDX-License-Identifier: Elastic-2.0

use automonique_protocol::{
    BoundedTextError, CheckStatus, DOCTOR_REPORT_SCHEMA_V1, DoctorCheck, DoctorCheckError,
    DoctorReportError, DoctorReportV1, FindingCode, FindingMessage, MAX_DOCTOR_CHECKS,
    MAX_FINDING_CODE_BYTES, MAX_FINDING_MESSAGE_BYTES, ReportStatus,
};

fn check(code: &str, status: CheckStatus, reason: Option<&str>) -> DoctorCheck {
    DoctorCheck::new(
        FindingCode::new(code).expect("valid test code"),
        status,
        reason.map(|value| FindingMessage::new(value).expect("valid test reason")),
    )
    .expect("coherent test check")
}

#[test]
fn status_spelling_and_severity_are_stable() {
    assert_eq!(ReportStatus::Healthy.as_str(), "healthy");
    assert_eq!(ReportStatus::Degraded.as_str(), "degraded");
    assert_eq!(ReportStatus::Failed.as_str(), "failed");
    assert_eq!(CheckStatus::Healthy.as_str(), "healthy");
    assert_eq!(CheckStatus::Finding.as_str(), "finding");
    assert_eq!(CheckStatus::Unavailable.as_str(), "unavailable");
}

#[test]
fn finding_code_has_a_small_ascii_grammar_and_byte_bound() {
    let code = FindingCode::new("runtime.socket-ready").expect("valid code");
    assert_eq!(code.as_str(), "runtime.socket-ready");
    assert_eq!(FindingCode::new(""), Err(BoundedTextError::Empty));
    assert_eq!(
        FindingCode::new("A.bad"),
        Err(BoundedTextError::InvalidCharacter)
    );
    assert_eq!(
        FindingCode::new("runtime/bad"),
        Err(BoundedTextError::InvalidCharacter)
    );
    assert_eq!(
        FindingCode::new("a".repeat(MAX_FINDING_CODE_BYTES + 1)),
        Err(BoundedTextError::TooLong {
            max_bytes: MAX_FINDING_CODE_BYTES,
            actual_bytes: MAX_FINDING_CODE_BYTES + 1,
        })
    );
}

#[test]
fn finding_message_is_single_line_unicode_with_a_utf8_byte_bound() {
    let message = FindingMessage::new("ready ✓").expect("valid message");
    assert_eq!(message.as_str(), "ready ✓");
    assert_eq!(FindingMessage::new(""), Err(BoundedTextError::Empty));
    assert_eq!(
        FindingMessage::new("two\nlines"),
        Err(BoundedTextError::InvalidCharacter)
    );
    let oversized = "é".repeat((MAX_FINDING_MESSAGE_BYTES / 2) + 1);
    assert_eq!(
        FindingMessage::new(oversized.clone()),
        Err(BoundedTextError::TooLong {
            max_bytes: MAX_FINDING_MESSAGE_BYTES,
            actual_bytes: oversized.len(),
        })
    );
}

#[test]
fn check_reason_presence_is_truthful() {
    let code = FindingCode::new("runtime.path").expect("code");
    assert_eq!(
        DoctorCheck::new(
            code.clone(),
            CheckStatus::Healthy,
            Some(FindingMessage::new("contradiction").expect("reason")),
        ),
        Err(DoctorCheckError::HealthyReasonForbidden)
    );
    assert_eq!(
        DoctorCheck::new(code, CheckStatus::Unavailable, None),
        Err(DoctorCheckError::ReasonRequired)
    );
}

#[test]
fn report_order_and_aggregate_status_do_not_depend_on_input_order() {
    let expected = DoctorReportV1::new([
        check("a.check", CheckStatus::Healthy, None),
        check("m.check", CheckStatus::Finding, Some("blocked")),
        check("z.check", CheckStatus::Unavailable, Some("not supported")),
    ])
    .expect("report");
    let reordered = DoctorReportV1::new([
        check("z.check", CheckStatus::Unavailable, Some("not supported")),
        check("a.check", CheckStatus::Healthy, None),
        check("m.check", CheckStatus::Finding, Some("blocked")),
    ])
    .expect("report");

    assert_eq!(expected, reordered);
    assert_eq!(expected.schema(), DOCTOR_REPORT_SCHEMA_V1);
    assert_eq!(expected.status(), ReportStatus::Failed);
    assert_eq!(
        expected
            .checks()
            .iter()
            .map(|item| item.code().as_str())
            .collect::<Vec<_>>(),
        ["a.check", "m.check", "z.check"]
    );
}

#[test]
fn unavailable_is_degraded_and_empty_duplicate_oversized_reports_fail_closed() {
    let unavailable = DoctorReportV1::new([check(
        "runtime.check",
        CheckStatus::Unavailable,
        Some("not supported"),
    )])
    .expect("report");
    assert_eq!(unavailable.status(), ReportStatus::Degraded);
    assert_eq!(DoctorReportV1::new([]), Err(DoctorReportError::NoChecks));

    let duplicate = DoctorReportV1::new([
        check("same.code", CheckStatus::Healthy, None),
        check("same.code", CheckStatus::Finding, Some("failed")),
    ]);
    assert_eq!(
        duplicate,
        Err(DoctorReportError::DuplicateCode(
            FindingCode::new("same.code").expect("code")
        ))
    );

    let too_many = (0..=MAX_DOCTOR_CHECKS)
        .map(|index| check(&format!("check.{index}"), CheckStatus::Healthy, None));
    assert_eq!(
        DoctorReportV1::new(too_many),
        Err(DoctorReportError::TooManyChecks)
    );
}
