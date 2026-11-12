// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use std::error::Error;

use neotales_ssh::{EnvironmentPlan, EnvironmentPlanError, SshConfig};

#[test]
fn send_env_patterns_and_setenv_overrides_keep_send_order() -> Result<(), Box<dyn Error>> {
    let plan = EnvironmentPlan::from_send_and_set(
        ["LANG", "LC_*", "-LC_ALL", "TERM"],
        ["MODE=test", "LANG=C.UTF-8"],
        [
            ("LC_ALL", &b"C"[..]),
            ("LANG", &b"en_US"[..]),
            ("LC_TIME", &b"C"[..]),
            ("OTHER", &b"skip"[..]),
            ("TERM", &b"xterm"[..]),
        ],
    )?;

    let sent: Vec<_> = plan
        .assignments()
        .iter()
        .map(|assignment| {
            (
                std::str::from_utf8(assignment.name()).unwrap_or(""),
                std::str::from_utf8(assignment.value()).unwrap_or(""),
            )
        })
        .collect();
    assert_eq!(
        sent,
        [
            ("LANG", "C.UTF-8"),
            ("LC_TIME", "C"),
            ("TERM", "xterm"),
            ("MODE", "test"),
        ]
    );
    Ok(())
}

#[test]
fn removal_can_be_readded_and_question_marks_match_one_byte() -> Result<(), Box<dyn Error>> {
    let plan = EnvironmentPlan::from_send_and_set(
        ["*", "-LC_*", "LC_T?ME"],
        Vec::<&str>::new(),
        [("LC_TIME", &b"C"[..]), ("LANG", &b"en"[..])],
    )?;
    let names: Vec<_> = plan
        .assignments()
        .iter()
        .map(|assignment| assignment.name().to_vec())
        .collect();
    assert_eq!(names, [b"LANG".to_vec(), b"LC_TIME".to_vec()]);
    Ok(())
}

#[test]
fn invalid_send_entries_are_skipped_and_invalid_setenv_fails() {
    let skipped = EnvironmentPlan::from_send_and_set(
        ["*"],
        Vec::<&str>::new(),
        [
            ("OK", &b"yes"[..]),
            ("BAD=NAME", &b"no"[..]),
            ("NUL", &b"a\0b"[..]),
        ],
    )
    .expect("invalid supplied entries are not selected");
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped.assignments()[0].name(), b"OK");

    assert_eq!(
        EnvironmentPlan::from_send_and_set(["-"], Vec::<&str>::new(), Vec::<(&str, &[u8])>::new()),
        Err(EnvironmentPlanError::InvalidPattern)
    );
    assert_eq!(
        EnvironmentPlan::from_send_and_set(
            Vec::<&str>::new(),
            ["MODE"],
            Vec::<(&str, &[u8])>::new()
        ),
        Err(EnvironmentPlanError::InvalidAssignment)
    );
}

#[test]
fn resolved_config_builds_the_same_plan() -> Result<(), Box<dyn Error>> {
    let config = SshConfig::parse("Host *\n  SendEnv LANG LC_*\n  SetEnv MODE=test\n")?;
    let resolved = config.resolve("example.test", "user")?;
    let plan = resolved.environment_plan([("LANG", &b"en"[..]), ("LC_ALL", &b"C"[..])])?;
    assert_eq!(plan.len(), 3);
    assert_eq!(plan.assignments()[2].name(), b"MODE");
    assert_eq!(plan.assignments()[2].value(), b"test");
    let rendered = format!("{plan:?}");
    assert!(rendered.contains("assignment_count"));
    assert!(!rendered.contains("MODE"));
    Ok(())
}
