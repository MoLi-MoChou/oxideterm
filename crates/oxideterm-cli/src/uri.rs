// Copyright (C) 2026 AnalyseDeCircuit
// SPDX-License-Identifier: GPL-3.0-only

use std::{fmt, path::Path};

use clap::Args;
use oxideterm_ssh_launch::{
    is_xshell_session_path, parse_connection_uri, parse_xshell_session_path,
};
use zeroize::Zeroizing;

use crate::{
    error::{CliError, CliResult},
    ssh::{current_username, launch_request},
};

#[derive(Args)]
pub struct ConnectionUriArgs {
    #[arg(
        value_name = "TARGET",
        help = "Connection URI (ssh://, telnet://, mosh://, rdp://, vnc://) or Xshell session file (.xsh / .xts)"
    )]
    pub uri: String,
}

impl fmt::Debug for ConnectionUriArgs {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConnectionUriArgs([redacted target])")
    }
}

pub fn run(args: ConnectionUriArgs) -> CliResult<i32> {
    let target = Zeroizing::new(args.uri);
    let trimmed = target.trim().trim_matches(|ch| matches!(ch, '"' | '\''));
    let path = Path::new(trimmed);
    let launch = if is_xshell_session_path(path) {
        parse_xshell_session_path(path, current_username().as_deref()).map_err(|error| {
            CliError::new("invalid_xshell_session", error.to_string(), false)
        })?
    } else {
        parse_connection_uri(trimmed, current_username().as_deref())
            .map_err(|error| CliError::new("invalid_connection_uri", error.to_string(), false))?
    };
    launch_request(&launch)?;
    if is_xshell_session_path(path) {
        println!("Opening Xshell session in OxideTerm");
    } else {
        println!("Opening temporary connection in OxideTerm");
    }
    Ok(0)
}
