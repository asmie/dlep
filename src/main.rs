use std::ffi::OsString;

use clap::{CommandFactory, Parser, Subcommand};

/// DLEP (RFC 8175) router and modem daemons.
#[derive(Parser)]
#[command(
    version,
    about,
    arg_required_else_help = true,
    args_conflicts_with_subcommands = true
)]
struct Cli {
    /// Print a shell completion script and exit without loading configuration.
    #[arg(long, value_enum, value_name = "SHELL")]
    generate_completions: Option<clap_complete::Shell>,

    #[command(subcommand)]
    role: Option<Role>,
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

fn generate_completions(shell: clap_complete::Shell) -> anyhow::Result<()> {
    // Runtime parsing forwards role arguments unchanged. Completion generation
    // needs the actual role definitions instead of those passthrough arguments.
    let mut command = Cli::command()
        .mut_subcommand("router", |_| dlep_router::command().name("router"))
        .mut_subcommand("modem", |_| dlep_modem::command().name("modem"));
    let mut script = Vec::new();
    clap_complete::generate(shell, &mut command, "dlep", &mut script);
    std::io::Write::write_all(&mut std::io::stdout().lock(), &script)?;
    Ok(())
}

fn role_completion_shell(
    command: clap::Command,
    args: &[OsString],
) -> Option<clap_complete::Shell> {
    if !args.iter().any(|arg| {
        arg.to_str().is_some_and(|arg| {
            arg == "--generate-completions" || arg.starts_with("--generate-completions=")
        })
    }) {
        return None;
    }
    // Validate with the same parser as run_from, while retaining the launcher's
    // binary name in scripts requested through either of its subcommands.
    command
        .get_matches_from(std::iter::once(OsString::from("dlep")).chain(args.iter().cloned()))
        .get_one::<clap_complete::Shell>("generate_completions")
        .copied()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    if let Some(shell) = cli.generate_completions {
        return generate_completions(shell);
    }
    let role = cli.role.expect("clap requires a role or completion shell");
    let shell = match &role {
        Role::Router { args } => role_completion_shell(dlep_router::command(), args),
        Role::Modem { args } => role_completion_shell(dlep_modem::command(), args),
    };
    if let Some(shell) = shell {
        return generate_completions(shell);
    }
    match role {
        Role::Router { args } => {
            dlep_router::run_from(std::iter::once(OsString::from("dlep router")).chain(args)).await
        }
        Role::Modem { args } => {
            dlep_modem::run_from(std::iter::once(OsString::from("dlep modem")).chain(args)).await
        }
    }
}
