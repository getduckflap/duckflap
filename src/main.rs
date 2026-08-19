use std::{
    env,
    ffi::{OsStr, OsString},
    io::{self, Write},
    process::ExitCode,
    time::Duration,
};

use clap::{Parser, error::ErrorKind};
use duckflap::{
    cli::{Cli, Command},
    commands::{
        CommandData, InspectData, StatusData, run_detached, run_doctor, run_env, run_exec,
        run_inspect, run_logs, run_reallocate, run_release, run_status, run_stop, run_wait,
    },
    error::{AppError, CommandFailure},
    output::{ErrorResponse, SuccessResponse, write_json, write_posix_shell_environment},
};

fn main() -> ExitCode {
    let arguments = env::args_os().collect::<Vec<_>>();
    let cli = match Cli::try_parse_from(arguments.iter().cloned()) {
        Ok(cli) => cli,
        Err(error) => return handle_parse_error(&arguments, error),
    };
    let command = cli.command_name();
    let requests_json = cli.requests_json();
    let result = match cli.command {
        Command::InternalGatedExec(args) => {
            return match duckflap::runtime::run_gated_exec_helper(
                &args.executable,
                &args.workdir,
                &args.exec_error_path,
                &args.arguments,
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("duckflap: failed to run internal gated executable: {error}");
                    ExitCode::from(127)
                }
            };
        }
        Command::Exec(args) => match run_exec(&args.command) {
            Ok(()) => return ExitCode::SUCCESS,
            Err(failure) => {
                eprintln!("duckflap: {}", failure.error);
                return ExitCode::FAILURE;
            }
        },
        Command::Logs(args) => {
            return match run_logs(&args.service, args.tail) {
                Ok(output) => match io::stdout().lock().write_all(&output) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => {
                        eprintln!("duckflap: failed to write log output: {error}");
                        ExitCode::from(2)
                    }
                },
                Err(failure) => {
                    eprintln!("duckflap: {}: {}", failure.error.code(), failure.error);
                    ExitCode::FAILURE
                }
            };
        }
        Command::Inspect(args) if !args.json => {
            return match run_inspect(args.port) {
                Ok(success) => match write_human_inspection(io::stdout().lock(), &success.data) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => {
                        eprintln!("duckflap: failed to write inspection output: {error}");
                        ExitCode::from(2)
                    }
                },
                Err(failure) => {
                    eprintln!("duckflap: {}: {}", failure.error.code(), failure.error);
                    ExitCode::FAILURE
                }
            };
        }
        Command::Env(args) if args.shell.is_some() => {
            return match run_env() {
                Ok(success) => match write_posix_shell_environment(
                    io::stdout().lock(),
                    &success.data.environment,
                ) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => {
                        eprintln!("duckflap: failed to write shell environment: {error}");
                        ExitCode::from(2)
                    }
                },
                Err(failure) => {
                    eprintln!("duckflap: {}: {}", failure.error.code(), failure.error);
                    ExitCode::FAILURE
                }
            };
        }
        Command::Status(args) if !args.json => {
            return match run_status() {
                Ok(success) => match write_human_status(io::stdout().lock(), &success.data) {
                    Ok(()) => ExitCode::SUCCESS,
                    Err(error) => {
                        eprintln!("duckflap: failed to write status output: {error}");
                        ExitCode::from(2)
                    }
                },
                Err(failure) => {
                    eprintln!("duckflap: {}: {}", failure.error.code(), failure.error);
                    ExitCode::FAILURE
                }
            };
        }
        Command::Env(args) if args.json => run_env().map(|success| success.map(CommandData::Env)),
        Command::Run(args) if args.detach && args.json => {
            run_detached().map(|success| success.map(CommandData::Run))
        }
        Command::Status(args) if args.json => {
            run_status().map(|success| success.map(CommandData::Status))
        }
        Command::Wait(args) if args.json => run_wait(Duration::from_secs(args.timeout))
            .map(|success| success.map(CommandData::Wait)),
        Command::Inspect(args) if args.json => {
            run_inspect(args.port).map(|success| success.map(CommandData::Inspect))
        }
        Command::Doctor(args) if args.json => {
            run_doctor().map(|success| success.map(CommandData::Doctor))
        }
        Command::Stop(args) if args.json => {
            run_stop().map(|success| success.map(CommandData::Stop))
        }
        Command::Reallocate(args) if args.json => {
            run_reallocate().map(|success| success.map(CommandData::Reallocate))
        }
        Command::Release(args) if args.json => {
            run_release().map(|success| success.map(CommandData::Release))
        }
        Command::Env(_)
        | Command::Run(_)
        | Command::Status(_)
        | Command::Wait(_)
        | Command::Inspect(_)
        | Command::Doctor(_)
        | Command::Stop(_)
        | Command::Reallocate(_)
        | Command::Release(_) => Err(CommandFailure::from(AppError::not_implemented(command))),
    };

    match result {
        Ok(success) => {
            let response = SuccessResponse::new(command, success.changed, success.data);
            if let Err(write_error) = write_json(io::stdout().lock(), &response) {
                eprintln!("duckflap: failed to write JSON response: {write_error}");
                return ExitCode::from(2);
            }
            ExitCode::SUCCESS
        }
        Err(failure) if requests_json => {
            let response = ErrorResponse::new(
                command,
                failure.changed,
                failure.error.code(),
                failure.error.to_string(),
            );
            if let Err(write_error) = write_json(io::stdout().lock(), &response) {
                eprintln!("duckflap: failed to write JSON response: {write_error}");
                return ExitCode::from(2);
            }
            ExitCode::FAILURE
        }
        Err(failure) => {
            eprintln!("duckflap: {}", failure.error);
            ExitCode::FAILURE
        }
    }
}

fn write_human_inspection(mut writer: impl Write, data: &InspectData) -> io::Result<()> {
    writeln!(writer, "{} {}: {}", data.protocol, data.port, data.state)?;
    match data.allocation.as_ref() {
        Some(allocation) => writeln!(
            writer,
            "allocation: {} ({}, {})",
            allocation.service_key, allocation.project_instance_id, allocation.worktree_root
        )?,
        None => writeln!(writer, "allocation: none")?,
    }
    for process in &data.processes {
        writeln!(
            writer,
            "process: {} {}",
            process.pid,
            process.command.as_deref().unwrap_or("unknown")
        )?;
    }
    if data.state != "free" && data.processes.is_empty() {
        writeln!(writer, "process evidence: {}", data.process_evidence)?;
    }
    Ok(())
}

fn write_human_status(mut writer: impl Write, data: &StatusData) -> io::Result<()> {
    match data.project_id.as_ref() {
        Some(project_id) => writeln!(writer, "project: {project_id}")?,
        None => writeln!(writer, "project: none")?,
    }
    match data.project_instance_id.as_ref() {
        Some(project_instance_id) => writeln!(writer, "project instance: {project_instance_id}")?,
        None => writeln!(writer, "project instance: none")?,
    }
    match data.runtime_session_id.as_ref() {
        Some(runtime_session_id) => writeln!(writer, "runtime session: {runtime_session_id}")?,
        None => writeln!(writer, "runtime session: none")?,
    }
    if data.services.is_empty() {
        writeln!(writer, "service: none")?;
    } else {
        for service in &data.services {
            writeln!(
                writer,
                "service: {} {}/{} {} {}",
                service.service_key,
                service.protocol,
                service.port,
                service.readiness,
                service.url.as_deref().unwrap_or("-")
            )?;
        }
    }
    Ok(())
}

fn handle_parse_error(arguments: &[OsString], error: clap::Error) -> ExitCode {
    let is_help_or_version = matches!(
        error.kind(),
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
    );
    if requests_json(arguments) && !is_help_or_version {
        let response = ErrorResponse::new(
            requested_command(arguments),
            false,
            "INVALID_ARGUMENTS",
            error.to_string(),
        );
        return match write_json(io::stdout().lock(), &response) {
            Ok(()) => ExitCode::FAILURE,
            Err(write_error) => {
                eprintln!("duckflap: failed to write JSON response: {write_error}");
                ExitCode::from(2)
            }
        };
    }

    let exit_code = u8::try_from(error.exit_code()).unwrap_or(2);
    if let Err(print_error) = error.print() {
        eprintln!("duckflap: failed to write command output: {print_error}");
        return ExitCode::from(2);
    }
    ExitCode::from(exit_code)
}

fn requests_json(arguments: &[OsString]) -> bool {
    !matches!(requested_command(arguments), "exec" | "logs")
        && arguments
            .iter()
            .skip(1)
            .any(|argument| argument == OsStr::new("--json"))
}

fn requested_command(arguments: &[OsString]) -> &'static str {
    match arguments.get(1).and_then(|argument| argument.to_str()) {
        Some("env") => "env",
        Some("run") => "run",
        Some("status") => "status",
        Some("wait") => "wait",
        Some("inspect") => "inspect",
        Some("doctor") => "doctor",
        Some("stop") => "stop",
        Some("reallocate") => "reallocate",
        Some("release") => "release",
        Some("exec") => "exec",
        Some("logs") => "logs",
        _ => "cli",
    }
}
