// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[path = "../src/ssh_config.rs"]
mod ssh_config;

use std::error::Error;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use ssh_config::{SshConfigError, parse};

#[test]
fn resolved_algorithm_keywords_build_a_narrowed_implemented_only_proposal()
-> Result<(), Box<dyn Error>> {
    let config = parse("Host *\n KexAlgorithms curve25519-sha256\n Ciphers aes128-ctr\n MACs hmac-sha2-256\n HostKeyAlgorithms rsa-sha2-512\n ProxyCommand never-execute-this %h\n SendEnv LANG\n SetEnv MODE=test\n")?.resolve("peer", "user")?;
    let proposal = config.to_kexinit()?;
    assert_eq!(
        proposal.encryption_algorithms_client_to_server,
        ["aes128-ctr"]
    );
    assert_eq!(
        proposal.encryption_algorithms_server_to_client,
        ["aes128-ctr"]
    );
    assert_eq!(proposal.mac_algorithms_client_to_server, ["hmac-sha2-256"]);
    assert_eq!(proposal.server_host_key_algorithms, ["rsa-sha2-512"]);
    assert_eq!(
        proposal.kex_algorithms,
        ["curve25519-sha256", "kex-strict-c-v00@openssh.com"]
    );
    assert_eq!(
        config.environment_plan([("LANG", b"C".as_slice())])?.len(),
        2
    );
    for keyword in [
        "Ciphers aes192-ctr",
        "HostKeyAlgorithms ssh-rsa",
        "KexAlgorithms unknown",
        "MACs hmac-sha1",
        "Ciphers +aes128-ctr",
        "Ciphers aes128-ctr,aes128-ctr",
    ] {
        assert_eq!(
            parse(&format!("Host *\n {keyword}\n"))?
                .resolve("peer", "user")?
                .to_kexinit(),
            Err(SshConfigError::InvalidAlgorithm)
        );
    }
    assert_eq!(parse("Include anything"), Err(SshConfigError::Include));
    Ok(())
}

#[test]
fn host_wildcards_and_negation_apply_only_to_the_original_host() -> Result<(), Box<dyn Error>> {
    let config = parse("Host api?.example,!skip.example\n  User deploy\n")?;
    let selected = config.resolve("api1.example", "default")?;
    let negated = config.resolve("skip.example", "default")?;
    let miss = config.resolve("api12.example", "default")?;

    assert_eq!(selected.user, "deploy");
    assert_eq!(negated.user, "default");
    assert_eq!(miss.user, "default");
    Ok(())
}

#[test]
fn first_hostname_wins_and_h_n_have_distinct_expansion_meanings() -> Result<(), Box<dyn Error>> {
    let config = parse(
        "Host app\n  HostName backend.example\n  IdentityFile keys/%h-%n\n\
         Host *\n  HostName later.example\n  IdentityFile keys/later\n",
    )?;
    let resolved = config.resolve("app", "default")?;

    assert_eq!(resolved.hostname, "backend.example");
    assert_eq!(
        resolved.identity_files,
        ["keys/backend.example-app", "keys/later"]
    );
    assert_eq!(
        config.resolve("other", "default")?.hostname,
        "later.example"
    );
    Ok(())
}

#[test]
fn identity_file_expands_port_user_and_literal_percent() -> Result<(), Box<dyn Error>> {
    let config = parse("Host app\n  User deploy\n  Port 2200\n  IdentityFile keys/%p-%r-%%\n")?;
    let resolved = config.resolve("app", "default")?;

    assert_eq!(resolved.port, 2200);
    assert_eq!(resolved.identity_files, ["keys/2200-deploy-%"]);
    Ok(())
}

#[test]
fn match_exec_does_not_select_its_stanza() -> Result<(), Box<dyn Error>> {
    let config = parse("Host *\n  User selected\nMatch exec true\n  User ignored\n  Port 2200\n")?;
    let resolved = config.resolve("app", "default")?;

    assert_eq!(resolved.user, "selected");
    assert_eq!(resolved.port, 22);
    Ok(())
}

#[test]
fn include_is_rejected_without_being_read() {
    assert!(matches!(
        parse("Host app\n  Include /path/that/must/not/be/read\n"),
        Err(SshConfigError::Include)
    ));
}

#[test]
fn directory_loader_reads_nested_include_and_rejects_outside_symlink() -> Result<(), Box<dyn Error>>
{
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let base = std::env::temp_dir().join(format!("ssh-config-include-{unique}"));
    let root = base.join("root");
    fs::create_dir_all(root.join("nested"))?;
    fs::write(root.join("nested/config"), "Host app\n User nested-user\n")?;
    let outside = base.join("outside");
    fs::write(&outside, "Host app\n User outside-user\n")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, root.join("escape"))?;

    let mut loader = ssh_config::directory_include_loader(&root);
    let config = ssh_config::SshConfig::parse_with_loader("Include nested/config\n", &mut loader)?;
    assert_eq!(config.resolve("app", "default")?.user, "nested-user");
    #[cfg(unix)]
    assert_eq!(
        ssh_config::SshConfig::parse_with_loader("Include escape\n", &mut loader),
        Err(SshConfigError::InvalidInclude)
    );
    assert_eq!(
        fs::read_to_string(&outside)?,
        "Host app\n User outside-user\n"
    );
    fs::remove_dir_all(base)?;
    Ok(())
}

#[test]
fn unknown_keywords_are_retained_without_changing_typed_values() -> Result<(), Box<dyn Error>> {
    let config = parse("Host app\n  VendorFlag enabled\n  Port=2200\n")?;
    let resolved = config.resolve("app", "default")?;

    assert_eq!(resolved.port, 2200);
    assert_eq!(
        resolved.unknown_keywords,
        [("VendorFlag".to_owned(), "enabled".to_owned())]
    );
    Ok(())
}

#[test]
fn proxy_command_is_returned_as_text_and_quoted_spaces_are_preserved() -> Result<(), Box<dyn Error>>
{
    let config =
        parse("Host app\n  ProxyCommand \"helper --name value\" # retained command text\n")?;
    let resolved = config.resolve("app", "default")?;

    assert_eq!(
        resolved.proxy_command.as_deref(),
        Some("helper --name value")
    );
    Ok(())
}

#[test]
fn match_host_uses_an_earlier_hostname_and_supports_case_insensitivity()
-> Result<(), Box<dyn Error>> {
    let config =
        parse("Host alias\n  HostName REMOTE.example\nMatch host remote.*\n  Port 2222\n")?;
    let resolved = config.resolve("alias", "default")?;

    assert_eq!(resolved.port, 2222);
    Ok(())
}

#[test]
fn scalar_and_accumulative_keywords_keep_the_required_order() -> Result<(), Box<dyn Error>> {
    let config = parse(
        "Host *\n  IdentityFile one two\n  CertificateFile cert-a cert-b\n\
         SendEnv LANG LC_*\n  SetEnv MODE=test\n  Port 22\n\
         Host app\n  IdentityFile three\n  Port 2200\n",
    )?;
    let resolved = config.resolve("app", "default")?;

    assert_eq!(resolved.port, 22);
    assert_eq!(resolved.identity_files, ["one", "two", "three"]);
    assert_eq!(resolved.certificate_files, ["cert-a", "cert-b"]);
    assert_eq!(resolved.send_env, ["LANG", "LC_*"]);
    assert_eq!(resolved.set_env, ["MODE=test"]);
    Ok(())
}
