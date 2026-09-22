// Copyright (C) 2026 AnalyseDeCircuit
// SPDX-License-Identifier: GPL-3.0-only

//! Open-and-connect mapping for Xshell `.xsh` / `.xts` session files.
//!
//! Import into the connection store still lives in `oxideterm-connections`.
//! This module only builds ephemeral `TemporarySshLaunch` values for CLI /
//! native file-open, matching Netcatty's host/port/username deep-link behavior
//! while also accepting empty passwords for bastion one-shot flows.

use std::{collections::BTreeMap, fs, io::Read, path::Path};

use zeroize::Zeroizing;

use crate::{DEFAULT_SSH_PORT, NativeConnectionLaunch, TemporarySshLaunch};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseXshellSessionError {
    Empty,
    InvalidPath,
    Read,
    Parse,
    UnsupportedProtocol,
    MissingHost,
    EmptyArchive,
}

impl std::fmt::Display for ParseXshellSessionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => formatter.write_str("Xshell session content is empty"),
            Self::InvalidPath => formatter.write_str("path is not an Xshell .xsh or .xts session"),
            Self::Read => formatter.write_str("failed to read Xshell session file"),
            Self::Parse => formatter.write_str("failed to parse Xshell session file"),
            Self::UnsupportedProtocol => formatter.write_str("Xshell session protocol is not SSH"),
            Self::MissingHost => formatter.write_str("Xshell session is missing a host"),
            Self::EmptyArchive => {
                formatter.write_str("Xshell archive contains no SSH session files")
            }
        }
    }
}

impl std::error::Error for ParseXshellSessionError {}

/// True when `path` looks like an Xshell session file (`.xsh` or `.xts`).
pub fn is_xshell_session_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("xsh") || extension.eq_ignore_ascii_case("xts")
        })
}

/// Parse a filesystem `.xsh` / `.xts` path into a temporary SSH launch.
pub fn parse_xshell_session_path(
    path: &Path,
    default_username: Option<&str>,
) -> Result<NativeConnectionLaunch, ParseXshellSessionError> {
    if !is_xshell_session_path(path) {
        return Err(ParseXshellSessionError::InvalidPath);
    }
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    if extension.eq_ignore_ascii_case("xts") {
        return parse_xshell_archive_path(path, default_username);
    }
    let content = fs::read_to_string(path).map_err(|_| ParseXshellSessionError::Read)?;
    parse_xshell_session_text(&content, default_username).map(NativeConnectionLaunch::Ssh)
}

/// Parse Xshell session INI text into a temporary SSH launch.
pub fn parse_xshell_session_text(
    text: &str,
    default_username: Option<&str>,
) -> Result<TemporarySshLaunch, ParseXshellSessionError> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err(ParseXshellSessionError::Empty);
    }

    let sections = parse_ini_sections(trimmed);
    let connection = section_fields(&sections, &["CONNECTION", "Connection"]);
    let authentication = section_fields(
        &sections,
        &[
            "CONNECTION:AUTHENTICATION",
            "CONNECTION:Authentication",
            "AUTHENTICATION",
            "Authentication",
        ],
    );

    let protocol = first_field(&connection, &["Protocol", "protocol"])
        .or_else(|| first_field(&authentication, &["Protocol", "protocol"]));
    if let Some(protocol) = protocol
        && !protocol.eq_ignore_ascii_case("ssh")
    {
        return Err(ParseXshellSessionError::UnsupportedProtocol);
    }

    let host = first_field(&connection, &["Host", "host", "Hostname", "hostname"])
        .filter(|value| !value.trim().is_empty())
        .ok_or(ParseXshellSessionError::MissingHost)?
        .trim()
        .to_string();

    let port = first_field(&connection, &["Port", "port", "SshPort", "sshport"])
        .and_then(|value| value.trim().parse::<u16>().ok())
        .filter(|port| *port > 0)
        .unwrap_or(DEFAULT_SSH_PORT);

    let username = first_field(
        &authentication,
        &["UserName", "Username", "userName", "User", "user"],
    )
    .or_else(|| {
        first_field(
            &connection,
            &["UserName", "Username", "userName", "User", "user"],
        )
    })
    .map(|value| value.trim().to_string())
    .filter(|value| !value.is_empty())
    .or_else(|| {
        default_username
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    })
    .unwrap_or_default();

    let key_path = first_field(
        &authentication,
        &[
            "PrivateKey",
            "privatekey",
            "IdentityFile",
            "identityfile",
            "KeyFile",
            "keyfile",
        ],
    )
    .or_else(|| {
        first_field(
            &connection,
            &[
                "PrivateKey",
                "privatekey",
                "IdentityFile",
                "identityfile",
                "KeyFile",
                "keyfile",
            ],
        )
    })
    .map(|value| value.trim().to_string())
    .filter(|value| !value.is_empty());

    // Xshell encrypts non-empty Password values. Empty Password= is intentional
    // for bastion / local-forward one-shots and must become a runtime empty
    // password, not Agent auth and not a vault lookup.
    let password = match password_field(&authentication)
        .or_else(|| password_field(&connection))
        .unwrap_or(PasswordField::Omitted)
    {
        PasswordField::Empty => Some(Zeroizing::new(String::new())),
        PasswordField::Omitted | PasswordField::Encrypted => None,
    };

    // Netcatty parity: bastion-issued .xsh sessions land on loopback with an
    // encrypted (unusable) or omitted Password. Xshell accepts Enter at the
    // password prompt; mirror that with an empty password instead of falling
    // through to SSH agent. Do not override an explicit key path.
    let password = match password {
        Some(password) => Some(password),
        None if key_path.is_none() && is_loopback_host(&host) => {
            Some(Zeroizing::new(String::new()))
        }
        None => None,
    };

    Ok(TemporarySshLaunch {
        username,
        host,
        port,
        password,
        key_path,
    })
}

fn is_loopback_host(host: &str) -> bool {
    let host = host
        .trim()
        .trim_matches(|ch| ch == '[' || ch == ']')
        .to_ascii_lowercase();
    matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PasswordField {
    Omitted,
    Empty,
    Encrypted,
}

fn password_field(fields: &BTreeMap<String, String>) -> Option<PasswordField> {
    let (key, value) = fields.iter().find(|(key, _)| {
        let normalized = normalize_key(key);
        normalized == "password" || normalized.starts_with("password")
    })?;
    let _ = key;
    if value.trim().is_empty() {
        Some(PasswordField::Empty)
    } else {
        // Encrypted ciphertext is never treated as a usable secret.
        Some(PasswordField::Encrypted)
    }
}

fn parse_xshell_archive_path(
    path: &Path,
    default_username: Option<&str>,
) -> Result<NativeConnectionLaunch, ParseXshellSessionError> {
    let file = fs::File::open(path).map_err(|_| ParseXshellSessionError::Read)?;
    let mut archive = zip::ZipArchive::new(file).map_err(|_| ParseXshellSessionError::Parse)?;
    let mut first_launch = None;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|_| ParseXshellSessionError::Parse)?;
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().replace('\\', "/");
        if !name.to_ascii_lowercase().ends_with(".xsh") {
            continue;
        }
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|_| ParseXshellSessionError::Read)?;
        let content = String::from_utf8_lossy(&bytes);
        match parse_xshell_session_text(&content, default_username) {
            Ok(launch) => {
                first_launch = Some(launch);
                break;
            }
            Err(ParseXshellSessionError::UnsupportedProtocol) => continue,
            Err(ParseXshellSessionError::MissingHost) => continue,
            Err(error) => return Err(error),
        }
    }
    first_launch
        .map(NativeConnectionLaunch::Ssh)
        .ok_or(ParseXshellSessionError::EmptyArchive)
}

fn parse_ini_sections(text: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut sections: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current = String::new();
    sections.insert(current.clone(), BTreeMap::new());

    for raw_line in text.split('\n') {
        let line = raw_line.trim().trim_end_matches('\r');
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        {
            current = name.trim().to_string();
            sections.entry(current.clone()).or_default();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        sections
            .entry(current.clone())
            .or_default()
            .insert(key.to_string(), unquote(value.trim()));
    }
    sections
}

fn section_fields<'a>(
    sections: &'a BTreeMap<String, BTreeMap<String, String>>,
    names: &[&str],
) -> BTreeMap<String, String> {
    for name in names {
        if let Some(fields) = sections.get(*name) {
            return fields.clone();
        }
        if let Some((_, fields)) = sections
            .iter()
            .find(|(section, _)| section.eq_ignore_ascii_case(name))
        {
            return fields.clone();
        }
    }
    BTreeMap::new()
}

fn first_field(fields: &BTreeMap<String, String>, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = fields.get(*key) {
            return Some(value.clone());
        }
        if let Some((_, value)) = fields
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(key))
        {
            return Some(value.clone());
        }
    }
    None
}

fn normalize_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

fn unquote(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 {
        let bytes = trimmed.as_bytes();
        if (bytes[0] == b'"' && bytes[trimmed.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[trimmed.len() - 1] == b'\'')
        {
            return trimmed[1..trimmed.len() - 1].to_string();
        }
    }
    trimmed.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NETCATTY_SAMPLE: &str = "[CONNECTION]\n\
Port=59759\n\
Protocol=SSH\n\
Host=127.0.0.1\n\
\n\
[CONNECTION:AUTHENTICATION]\n\
UserName=root\n\
Password=PCZencryptedNotUsable\n";

    #[test]
    fn is_xshell_session_path_matches_extensions() {
        assert!(is_xshell_session_path(Path::new(
            r"C:\Users\a\Sessions\root(SSH)@1.2.3.4.xsh"
        )));
        assert!(is_xshell_session_path(Path::new("session.XSH")));
        assert!(is_xshell_session_path(Path::new("bundle.xts")));
        assert!(!is_xshell_session_path(Path::new("readme.txt")));
    }

    #[test]
    fn parse_maps_host_port_username_and_loopback_encrypted_becomes_empty_password() {
        let launch = parse_xshell_session_text(NETCATTY_SAMPLE, None).unwrap();
        assert_eq!(launch.host, "127.0.0.1");
        assert_eq!(launch.port, 59759);
        assert_eq!(launch.username, "root");
        // Bastion loopback: encrypted Password is unusable → empty password (Netcatty).
        assert_eq!(
            launch.password.as_ref().map(|value| value.as_str()),
            Some("")
        );
        assert!(launch.key_path.is_none());
    }

    #[test]
    fn omitted_password_on_loopback_becomes_empty_password() {
        let launch = parse_xshell_session_text(
            "[CONNECTION]\nHost=127.0.0.1\nPort=49839\nProtocol=SSH\n\n             [CONNECTION:AUTHENTICATION]\nUserName=root\n",
            None,
        )
        .unwrap();
        assert_eq!(launch.host, "127.0.0.1");
        assert_eq!(launch.port, 49839);
        assert_eq!(launch.username, "root");
        assert_eq!(
            launch.password.as_ref().map(|value| value.as_str()),
            Some("")
        );
        assert!(launch.key_path.is_none());
    }

    #[test]
    fn encrypted_password_on_non_loopback_stays_none() {
        let launch = parse_xshell_session_text(
            "[CONNECTION]\nHost=10.0.0.8\nPort=22\nProtocol=SSH\n\n             [CONNECTION:AUTHENTICATION]\nUserName=root\nPassword=PCZencryptedNotUsable\n",
            None,
        )
        .unwrap();
        assert_eq!(launch.host, "10.0.0.8");
        assert!(launch.password.is_none());
        assert!(launch.key_path.is_none());
    }

    #[test]
    fn loopback_with_explicit_key_does_not_force_empty_password() {
        let launch = parse_xshell_session_text(
            "[CONNECTION]\nHost=127.0.0.1\nPort=2222\nProtocol=SSH\n\n             [AUTHENTICATION]\nUserName=root\nPrivateKey=/tmp/id_rsa\nPassword=PCZencrypted\n",
            None,
        )
        .unwrap();
        assert_eq!(launch.key_path.as_deref(), Some("/tmp/id_rsa"));
        assert!(launch.password.is_none());
    }

    #[test]
    fn empty_password_becomes_ephemeral_empty_secret() {
        let launch = parse_xshell_session_text(
            "[CONNECTION]\nHost=127.0.0.1\nPort=2222\nProtocol=SSH\n\n\
             [CONNECTION:AUTHENTICATION]\nUserName=ops\nPassword=\n",
            None,
        )
        .unwrap();
        assert_eq!(launch.username, "ops");
        assert_eq!(launch.host, "127.0.0.1");
        assert_eq!(launch.port, 2222);
        assert_eq!(
            launch.password.as_ref().map(|value| value.as_str()),
            Some("")
        );
        assert!(launch.key_path.is_none());
    }

    #[test]
    fn omitted_password_leaves_agent_auth() {
        let launch = parse_xshell_session_text(
            "[CONNECTION]\nHost=10.0.0.8\nPort=22\nUserName=ubuntu\n",
            Some("fallback"),
        )
        .unwrap();
        assert_eq!(launch.username, "ubuntu");
        assert!(launch.password.is_none());
    }

    #[test]
    fn private_key_path_is_preserved_for_launch() {
        let launch = parse_xshell_session_text(
            "[CONNECTION]\nHost=10.0.0.8\nPort=22\nUserName=ubuntu\n\n\
             [AUTHENTICATION]\nPrivateKey=/Users/ubuntu/.ssh/id_rsa\nPassword=redacted\n",
            None,
        )
        .unwrap();
        assert_eq!(
            launch.key_path.as_deref(),
            Some("/Users/ubuntu/.ssh/id_rsa")
        );
        assert!(launch.password.is_none());
    }

    #[test]
    fn rejects_non_ssh_protocols() {
        assert_eq!(
            parse_xshell_session_text(
                "[CONNECTION]\nProtocol=TELNET\nHost=127.0.0.1\nPort=23\n",
                None
            )
            .unwrap_err(),
            ParseXshellSessionError::UnsupportedProtocol
        );
    }

    #[test]
    fn path_helper_rejects_non_session_files() {
        assert_eq!(
            parse_xshell_session_path(Path::new("notes.txt"), None).unwrap_err(),
            ParseXshellSessionError::InvalidPath
        );
    }

    #[test]
    fn parse_to_native_launch_uses_ssh_kind() {
        let launch = parse_xshell_session_text(NETCATTY_SAMPLE, None).unwrap();
        let native = NativeConnectionLaunch::Ssh(launch);
        assert!(matches!(native, NativeConnectionLaunch::Ssh(_)));
    }

    #[test]
    fn xts_archive_opens_first_ssh_session() {
        use std::io::Write;
        let dir =
            std::env::temp_dir().join(format!("oxideterm-xsh-archive-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let archive_path = dir.join("sessions.xts");
        {
            let file = fs::File::create(&archive_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default();
            zip.start_file("ignored.txt", options).unwrap();
            zip.write_all(b"nope").unwrap();
            zip.start_file("prod/bastion.xsh", options).unwrap();
            zip.write_all(
                b"[CONNECTION]\nHost=127.0.0.1\nPort=2222\nProtocol=SSH\n\n[CONNECTION:AUTHENTICATION]\nUserName=root\nPassword=\n",
            )
            .unwrap();
            zip.finish().unwrap();
        }
        let launch = parse_xshell_session_path(&archive_path, None).unwrap();
        match launch {
            NativeConnectionLaunch::Ssh(ssh) => {
                assert_eq!(ssh.host, "127.0.0.1");
                assert_eq!(ssh.port, 2222);
                assert_eq!(ssh.username, "root");
                assert_eq!(ssh.password.as_ref().map(|value| value.as_str()), Some(""));
            }
            other => panic!("expected SSH launch, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
