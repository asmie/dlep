use std::ffi::OsString;

use clap::{Parser, Subcommand};

/// DLEP (RFC 8175) router and modem daemons.
#[derive(Parser)]
#[command(version, about, subcommand_required = true)]
struct Cli {
    #[command(subcommand)]
    role: Role,
}

#[derive(Subcommand)]
enum Role {
    /// Run the router; use `dlep router --help` for router options.
    #[command(disable_help_flag = true)]
    Router {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
    /// Run the modem; use `dlep modem --help` for modem options.
    #[command(disable_help_flag = true)]
    Modem {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<OsString>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().role {
        Role::Router { args } => {
            dlep_router::run_from(std::iter::once(OsString::from("dlep router")).chain(args)).await
        }
        Role::Modem { args } => {
            dlep_modem::run_from(std::iter::once(OsString::from("dlep modem")).chain(args)).await
        }
    }
}
