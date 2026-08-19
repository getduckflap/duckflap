use std::{ffi::OsString, path::PathBuf};

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "duckflap", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Allocate detected services and print their generated environment.
    Env(EnvArgs),
    /// Start the detected stack as a managed runtime.
    Run(RunArgs),
    /// Show existing Duckflap state without changing it.
    Status(OutputArgs),
    /// Wait for this project instance's managed runtime to become ready.
    Wait(WaitArgs),
    /// Inspect one IPv4 TCP port without changing Duckflap state.
    Inspect(InspectArgs),
    /// Diagnose this worktree without changing Duckflap state.
    Doctor(OutputArgs),
    /// Stop this project instance's managed runtime.
    Stop(OutputArgs),
    /// Atomically replace this project instance's detected service allocations.
    Reallocate(OutputArgs),
    /// Release this project instance's allocations.
    Release(OutputArgs),
    /// Run one foreground command with Duckflap's generated environment.
    Exec(ExecArgs),
    /// Print the latest recorded log for a service.
    Logs(LogsArgs),
    #[command(name = "__gated-exec", hide = true)]
    InternalGatedExec(InternalGatedExecArgs),
}

#[derive(Debug, Args)]
pub struct InternalGatedExecArgs {
    #[arg(long)]
    pub executable: PathBuf,

    #[arg(long)]
    pub workdir: PathBuf,

    #[arg(long)]
    pub exec_error_path: PathBuf,

    #[arg(last = true)]
    pub arguments: Vec<OsString>,
}

#[derive(Debug, Args)]
pub struct EnvArgs {
    #[arg(long, conflicts_with = "shell", required_unless_present = "shell")]
    pub json: bool,

    #[arg(long, value_name = "NAME", conflicts_with = "json")]
    pub shell: Option<Shell>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Shell {
    Sh,
    Bash,
    Zsh,
}

#[derive(Debug, Args)]
pub struct OutputArgs {
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RunArgs {
    #[arg(long)]
    pub detach: bool,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct WaitArgs {
    #[arg(long, default_value_t = 30, value_name = "SECONDS", value_parser = parse_positive_timeout)]
    pub timeout: u64,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct InspectArgs {
    #[arg(value_parser = parse_positive_port)]
    pub port: u16,

    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ExecArgs {
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<OsString>,
}

#[derive(Debug, Args)]
pub struct LogsArgs {
    pub service: String,

    #[arg(
        long,
        default_value_t = 200,
        value_parser = parse_positive_line_count
    )]
    pub tail: usize,
}

fn parse_positive_line_count(value: &str) -> Result<usize, String> {
    let lines = value
        .parse::<usize>()
        .map_err(|_| "tail must be a positive integer".to_owned())?;
    if lines == 0 {
        Err("tail must be greater than zero".to_owned())
    } else {
        Ok(lines)
    }
}

fn parse_positive_timeout(value: &str) -> Result<u64, String> {
    let seconds = value
        .parse::<u64>()
        .map_err(|_| "timeout must be a positive integer number of seconds".to_owned())?;
    if seconds == 0 {
        Err("timeout must be greater than zero".to_owned())
    } else {
        Ok(seconds)
    }
}

fn parse_positive_port(value: &str) -> Result<u16, String> {
    let port = value
        .parse::<u16>()
        .map_err(|_| "port must be an integer from 1 through 65535".to_owned())?;
    if port == 0 {
        Err("port must be greater than zero".to_owned())
    } else {
        Ok(port)
    }
}

impl Cli {
    pub fn command_name(&self) -> &'static str {
        match &self.command {
            Command::Env(_) => "env",
            Command::Run(_) => "run",
            Command::Status(_) => "status",
            Command::Wait(_) => "wait",
            Command::Inspect(_) => "inspect",
            Command::Doctor(_) => "doctor",
            Command::Stop(_) => "stop",
            Command::Reallocate(_) => "reallocate",
            Command::Release(_) => "release",
            Command::Exec(_) => "exec",
            Command::Logs(_) => "logs",
            Command::InternalGatedExec(_) => "internal-gated-exec",
        }
    }

    pub fn requests_json(&self) -> bool {
        match &self.command {
            Command::Env(args) => args.json,
            Command::Run(args) => args.json,
            Command::Status(args)
            | Command::Doctor(args)
            | Command::Stop(args)
            | Command::Reallocate(args)
            | Command::Release(args) => args.json,
            Command::Wait(args) => args.json,
            Command::Inspect(args) => args.json,
            Command::Exec(_) => false,
            Command::Logs(_) => false,
            Command::InternalGatedExec(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::Cli;

    #[test]
    fn env_requires_an_output_format() {
        assert!(Cli::try_parse_from(["duckflap", "env"]).is_err());
        assert!(Cli::try_parse_from(["duckflap", "env", "--json"]).is_ok());
        assert!(Cli::try_parse_from(["duckflap", "env", "--shell", "zsh"]).is_ok());
    }

    #[test]
    fn env_accepts_only_supported_posix_shells() {
        for shell in ["sh", "bash", "zsh"] {
            assert!(Cli::try_parse_from(["duckflap", "env", "--shell", shell]).is_ok());
        }
        assert!(Cli::try_parse_from(["duckflap", "env", "--shell", "fish"]).is_err());
    }

    #[test]
    fn output_modes_are_mutually_exclusive() {
        assert!(Cli::try_parse_from(["duckflap", "env", "--json", "--shell", "zsh"]).is_err());
    }

    #[test]
    fn exec_requires_a_command_after_the_delimiter() {
        assert!(Cli::try_parse_from(["duckflap", "exec"]).is_err());
        assert!(Cli::try_parse_from(["duckflap", "exec", "echo"]).is_err());
        assert!(Cli::try_parse_from(["duckflap", "exec", "--"]).is_err());
        assert!(Cli::try_parse_from(["duckflap", "exec", "--", "echo", "-n", "hello"]).is_ok());
    }

    #[test]
    fn detached_run_accepts_json_mode() {
        assert!(Cli::try_parse_from(["duckflap", "run", "--detach", "--json"]).is_ok());
    }

    #[test]
    fn wait_accepts_only_positive_integer_seconds() {
        assert!(Cli::try_parse_from(["duckflap", "wait", "--json"]).is_ok());
        assert!(Cli::try_parse_from(["duckflap", "wait", "--timeout", "2", "--json"]).is_ok());
        assert!(Cli::try_parse_from(["duckflap", "wait", "--timeout", "0", "--json"]).is_err());
        assert!(Cli::try_parse_from(["duckflap", "wait", "--timeout", "soon", "--json"]).is_err());
    }

    #[test]
    fn inspect_requires_a_valid_tcp_port() {
        assert!(Cli::try_parse_from(["duckflap", "inspect", "20000", "--json"]).is_ok());
        assert!(Cli::try_parse_from(["duckflap", "inspect", "0", "--json"]).is_err());
        assert!(Cli::try_parse_from(["duckflap", "inspect", "65536", "--json"]).is_err());
    }

    #[test]
    fn doctor_accepts_json_mode() {
        assert!(Cli::try_parse_from(["duckflap", "doctor", "--json"]).is_ok());
    }

    #[test]
    fn logs_requires_a_service_and_positive_tail() {
        assert!(Cli::try_parse_from(["duckflap", "logs"]).is_err());
        assert!(Cli::try_parse_from(["duckflap", "logs", "web"]).is_ok());
        assert!(Cli::try_parse_from(["duckflap", "logs", "web", "--tail", "20"]).is_ok());
        assert!(Cli::try_parse_from(["duckflap", "logs", "web", "--tail", "0"]).is_err());
    }
}
