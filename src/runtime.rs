use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    os::unix::{
        fs::{OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{self, Child, ChildStdin, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use rustix::{
    io::Errno,
    process::{Pid, Signal, getpgid, kill_process_group, test_kill_process_group},
};
use thiserror::Error;

use crate::state::ensure_private_directory;

pub const READINESS_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(50);
const GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(2);
const FORCE_STOP_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug)]
pub struct GatedRuntime {
    pub child: Child,
    gate: Option<ChildStdin>,
    exec_error_path: PathBuf,
    pub pid: u32,
    pub process_group_id: u32,
    pub process_start: String,
    pub executable: String,
    pub log_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub process_start: String,
}

impl GatedRuntime {
    pub fn release(&mut self) -> Result<(), RuntimeError> {
        let mut gate = self.gate.take().ok_or(RuntimeError::StartGateUnavailable)?;
        if let Err(source) = gate.write_all(b"\n") {
            drop(gate);
            self.cancel();
            return Err(RuntimeError::ReleaseStartGate { source });
        }
        drop(gate);
        Ok(())
    }

    pub fn cancel(&mut self) {
        self.gate.take();
        let _ = terminate_process_group(self.process_group_id);
        let _ = self.child.wait();
    }

    pub fn take_exec_error(&self) -> Result<Option<io::Error>, RuntimeError> {
        let message = match fs::read_to_string(&self.exec_error_path) {
            Ok(message) => message,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(RuntimeError::ReadExecError {
                    path: self.exec_error_path.clone(),
                    source,
                });
            }
        };
        fs::remove_file(&self.exec_error_path).map_err(|source| RuntimeError::RemoveExecError {
            path: self.exec_error_path.clone(),
            source,
        })?;
        Ok(Some(io::Error::other(message)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessOwnership {
    Owned,
    LeaderExited,
    Gone,
    Mismatch,
}

pub fn create_log_file(path: &Path) -> Result<File, RuntimeError> {
    let parent = path
        .parent()
        .ok_or_else(|| RuntimeError::InvalidLogPath(path.to_path_buf()))?;
    ensure_private_directory(parent).map_err(|source| RuntimeError::CreateLogDirectory {
        path: parent.to_path_buf(),
        source,
    })?;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| RuntimeError::CreateLog {
            path: path.to_path_buf(),
            source,
        })
}

pub fn spawn_gated_logged(
    program: &Path,
    arguments: &[String],
    environment: &BTreeMap<String, String>,
    worktree_root: &Path,
    log_path: &Path,
) -> Result<GatedRuntime, RuntimeError> {
    let log = create_log_file(log_path)?;
    let stderr = log.try_clone().map_err(|source| RuntimeError::CloneLog {
        path: log_path.to_path_buf(),
        source,
    })?;
    let arguments = arguments.iter().map(OsString::from).collect::<Vec<_>>();
    spawn_gated_with_stdio(
        program,
        &arguments,
        environment,
        worktree_root,
        log_path,
        log,
        stderr,
    )
}

pub(crate) fn spawn_gated_with_stdio(
    program: &Path,
    arguments: &[OsString],
    environment: &BTreeMap<String, String>,
    worktree_root: &Path,
    log_path: &Path,
    log: File,
    stderr: File,
) -> Result<GatedRuntime, RuntimeError> {
    let metadata = fs::metadata(program).map_err(|source| RuntimeError::Launch {
        program: program.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(RuntimeError::Launch {
            program: program.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::PermissionDenied,
                "runtime executable is not an executable file",
            ),
        });
    }
    let helper = env::current_exe().map_err(RuntimeError::CurrentExecutable)?;
    let exec_error_path = log_path.with_extension("exec-error");
    let mut command = Command::new(&helper);
    command
        .arg("__gated-exec")
        .arg("--executable")
        .arg(program)
        .arg("--workdir")
        .arg(worktree_root)
        .arg("--exec-error-path")
        .arg(&exec_error_path)
        .arg("--")
        .args(arguments)
        .current_dir(worktree_root)
        .envs(environment)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr));
    // A session boundary keeps the managed process group isolated from the
    // launcher's job-control session. The helper is not yet a group leader, so
    // setsid makes its PID both the session ID and process group ID.
    // SAFETY: setsid is async-signal-safe, and the closure only invokes setsid
    // and reads errno before exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = command.spawn().map_err(|source| RuntimeError::LaunchGate {
        helper: helper.clone(),
        source,
    })?;

    let gate = match child.stdin.take() {
        Some(gate) => gate,
        None => {
            let _ = terminate_process_group(child.id());
            let _ = child.wait();
            return Err(RuntimeError::StartGateUnavailable);
        }
    };

    let pid = child.id();
    let process_start = match wait_for_process_start(pid, &mut child) {
        Ok(process_start) => process_start,
        Err(error) => {
            if let Some(group) = pid_from_u32(pid) {
                let _ = kill_process_group(group, Signal::KILL);
            }
            let _ = child.wait();
            return Err(error);
        }
    };

    Ok(GatedRuntime {
        child,
        gate: Some(gate),
        exec_error_path,
        pid,
        process_group_id: pid,
        process_start,
        executable: program.to_string_lossy().into_owned(),
        log_path: log_path.to_path_buf(),
    })
}

pub fn run_gated_exec_helper(
    executable: &Path,
    worktree_root: &Path,
    exec_error_path: &Path,
    arguments: &[OsString],
) -> io::Result<()> {
    let mut signal = [0_u8; 1];
    match io::stdin().lock().read_exact(&mut signal) {
        Ok(()) => {}
        Err(source) if source.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
        Err(source) => return Err(source),
    }

    let source = Command::new(executable)
        .args(arguments)
        .current_dir(worktree_root)
        .exec();
    if let Err(marker_error) = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(exec_error_path)
        .and_then(|mut marker| marker.write_all(source.to_string().as_bytes()))
    {
        eprintln!(
            "duckflap: failed to record gated executable error at {exec_error_path:?}: {marker_error}"
        );
    }
    Err(source)
}

pub fn probe_tcp_port(port: u16) -> Result<(), RuntimeError> {
    let loopback = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
        .map_err(|source| RuntimeError::PortUnavailable { port, source })?;
    drop(loopback);
    let unspecified = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
        .map_err(|source| RuntimeError::PortUnavailable { port, source })?;
    drop(unspecified);
    Ok(())
}

pub fn tcp_port_is_ready(port: u16) -> bool {
    TcpStream::connect_timeout(
        &SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into(),
        Duration::from_millis(100),
    )
    .is_ok()
}

pub fn process_group_ownership(
    pid: u32,
    process_group_id: u32,
    expected_start: &str,
) -> Result<ProcessOwnership, RuntimeError> {
    let Some(group) = pid_from_u32(process_group_id) else {
        return Ok(ProcessOwnership::Mismatch);
    };
    let group_exists = process_group_exists(group)?;
    let Some(process) = pid_from_u32(pid) else {
        return Ok(ProcessOwnership::Mismatch);
    };
    let Some(actual_start) = process_start(process)? else {
        return Ok(if group_exists {
            ProcessOwnership::LeaderExited
        } else {
            ProcessOwnership::Gone
        });
    };
    let actual_group = match getpgid(Some(process)) {
        Ok(actual_group) => actual_group,
        Err(Errno::SRCH) => {
            return Ok(if group_exists {
                ProcessOwnership::LeaderExited
            } else {
                ProcessOwnership::Gone
            });
        }
        Err(source) => return Err(RuntimeError::InspectProcessGroup { pid, source }),
    };

    let identity_matches = if actual_start == expected_start {
        true
    } else if is_stable_process_start(expected_start) {
        false
    } else {
        legacy_process_start(process)?.as_deref() == Some(expected_start)
    };
    if identity_matches && actual_group == group {
        Ok(ProcessOwnership::Owned)
    } else {
        Ok(ProcessOwnership::Mismatch)
    }
}

pub fn current_process_identity() -> Result<ProcessIdentity, RuntimeError> {
    let pid = process::id();
    let process = pid_from_u32(pid).ok_or(RuntimeError::InvalidProcessId(pid))?;
    let process_start =
        process_start(process)?.ok_or(RuntimeError::ProcessIdentityUnavailable { pid })?;
    Ok(ProcessIdentity { pid, process_start })
}

pub fn process_identity_matches(
    pid: u32,
    expected_process_start: &str,
) -> Result<bool, RuntimeError> {
    let Some(process) = pid_from_u32(pid) else {
        return Ok(false);
    };
    process_start(process).map(|actual| actual.as_deref() == Some(expected_process_start))
}

pub fn terminate_process_group(process_group_id: u32) -> Result<(), RuntimeError> {
    let group =
        pid_from_u32(process_group_id).ok_or(RuntimeError::InvalidProcessId(process_group_id))?;
    if !process_group_exists(group)? {
        return Ok(());
    }

    signal_group(group, Signal::TERM)?;
    if wait_for_group_exit(group, GRACEFUL_STOP_TIMEOUT)? {
        return Ok(());
    }

    signal_group(group, Signal::KILL)?;
    if wait_for_group_exit(group, FORCE_STOP_TIMEOUT)? {
        Ok(())
    } else {
        Err(RuntimeError::StopTimeout { process_group_id })
    }
}

pub(crate) fn wait_for_process_start(pid: u32, child: &mut Child) -> Result<String, RuntimeError> {
    let process = pid_from_u32(pid).ok_or(RuntimeError::InvalidProcessId(pid))?;
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(start) = process_start(process)? {
            return Ok(start);
        }
        if let Some(status) = child.try_wait().map_err(RuntimeError::Wait)? {
            return Err(RuntimeError::ExitedBeforeRecord {
                status: status.code(),
            });
        }
        if Instant::now() >= deadline {
            return Err(RuntimeError::ProcessIdentityUnavailable { pid });
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn process_start(pid: Pid) -> Result<Option<String>, RuntimeError> {
    #[cfg(target_os = "linux")]
    {
        linux_process_start(pid)
    }
    #[cfg(target_os = "macos")]
    {
        macos_process_start(pid)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        portable_ps_process_start(pid, "ps", Some("UTC"))
            .map(|start| start.map(|start| format!("unix-v1:{start}")))
    }
}

fn is_stable_process_start(process_start: &str) -> bool {
    process_start.starts_with("linux-v1:")
        || process_start.starts_with("macos-v1:")
        || process_start.starts_with("unix-v1:")
}

#[cfg(target_os = "linux")]
fn linux_process_start(pid: Pid) -> Result<Option<String>, RuntimeError> {
    let stat_path = PathBuf::from(format!("/proc/{}/stat", pid.as_raw_pid()));
    let stat = match fs::read_to_string(&stat_path) {
        Ok(stat) => stat,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(RuntimeError::InspectProcess(source)),
    };
    let start_ticks = parse_linux_start_ticks(&stat).map_err(RuntimeError::InspectProcess)?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(RuntimeError::InspectProcess)?;
    let boot_id = boot_id.trim();
    if boot_id.is_empty() {
        return Err(RuntimeError::InspectProcess(io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux boot ID is empty",
        )));
    }
    Ok(Some(format!("linux-v1:{boot_id}:{start_ticks}")))
}

#[cfg(target_os = "linux")]
fn parse_linux_start_ticks(stat: &str) -> io::Result<&str> {
    let command_end = stat.rfind(')').ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Linux process stat has no command terminator",
        )
    })?;
    stat[command_end + 1..]
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Linux process stat has no start-time field",
            )
        })
}

#[cfg(target_os = "macos")]
fn macos_process_start(pid: Pid) -> Result<Option<String>, RuntimeError> {
    let buffer_size = i32::try_from(std::mem::size_of::<libc::proc_bsdinfo>())
        .expect("proc_bsdinfo fits in a C integer");
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: proc_pidinfo receives a correctly sized, writable proc_bsdinfo buffer.
    let read = unsafe {
        libc::proc_pidinfo(
            pid.as_raw_pid(),
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            buffer_size,
        )
    };
    if read == 0 {
        let source = io::Error::last_os_error();
        return if source.raw_os_error() == Some(libc::ESRCH) {
            Ok(None)
        } else {
            Err(RuntimeError::InspectProcess(source))
        };
    }
    if read != buffer_size {
        return Err(RuntimeError::InspectProcess(io::Error::new(
            io::ErrorKind::InvalidData,
            "macOS returned an incomplete process identity",
        )));
    }
    // SAFETY: proc_pidinfo reported that it initialized the complete buffer.
    let info = unsafe { info.assume_init() };
    if info.pbi_pid != u32::try_from(pid.as_raw_pid()).unwrap_or_default() {
        return Err(RuntimeError::InspectProcess(io::Error::new(
            io::ErrorKind::InvalidData,
            "macOS returned an identity for a different process",
        )));
    }
    Ok(Some(format!(
        "macos-v1:{}:{}",
        info.pbi_start_tvsec, info.pbi_start_tvusec
    )))
}

fn legacy_process_start(pid: Pid) -> Result<Option<String>, RuntimeError> {
    #[cfg(target_os = "macos")]
    let executable = "/bin/ps";
    #[cfg(not(target_os = "macos"))]
    let executable = "ps";
    portable_ps_process_start(pid, executable, None)
}

fn portable_ps_process_start(
    pid: Pid,
    executable: &str,
    timezone: Option<&str>,
) -> Result<Option<String>, RuntimeError> {
    let mut command = Command::new(executable);
    command
        .env("LC_ALL", "C")
        .args(["-o", "lstart=", "-p"])
        .arg(pid.as_raw_pid().to_string());
    if let Some(timezone) = timezone {
        command.env("TZ", timezone);
    }
    let output = command.output().map_err(RuntimeError::InspectProcess)?;
    if !output.status.success() {
        return Ok(None);
    }
    let start = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    Ok((!start.is_empty()).then_some(start))
}

fn process_group_exists(group: Pid) -> Result<bool, RuntimeError> {
    classify_process_group_probe(group, test_kill_process_group(group))
}

fn classify_process_group_probe(
    group: Pid,
    result: Result<(), Errno>,
) -> Result<bool, RuntimeError> {
    match result {
        Ok(()) | Err(Errno::PERM) => Ok(true),
        Err(Errno::SRCH) => Ok(false),
        Err(source) => Err(RuntimeError::InspectProcessGroup {
            pid: u32::try_from(group.as_raw_pid()).unwrap_or_default(),
            source,
        }),
    }
}

fn signal_group(group: Pid, signal: Signal) -> Result<(), RuntimeError> {
    match kill_process_group(group, signal) {
        Ok(()) | Err(Errno::SRCH) => Ok(()),
        Err(source) => Err(RuntimeError::SignalProcessGroup {
            process_group_id: u32::try_from(group.as_raw_pid()).unwrap_or_default(),
            source,
        }),
    }
}

fn wait_for_group_exit(group: Pid, timeout: Duration) -> Result<bool, RuntimeError> {
    let deadline = Instant::now() + timeout;
    loop {
        if !process_group_exists(group)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn pid_from_u32(pid: u32) -> Option<Pid> {
    i32::try_from(pid).ok().and_then(Pid::from_raw)
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("runtime log path has no parent directory: {0:?}")]
    InvalidLogPath(PathBuf),

    #[error("failed to create runtime log directory {path:?}: {source}")]
    CreateLogDirectory { path: PathBuf, source: io::Error },

    #[error("failed to create runtime log {path:?}: {source}")]
    CreateLog { path: PathBuf, source: io::Error },

    #[error("failed to clone runtime log {path:?}: {source}")]
    CloneLog { path: PathBuf, source: io::Error },

    #[error("failed to determine the current Duckflap executable: {0}")]
    CurrentExecutable(io::Error),

    #[error("failed to launch gated runtime helper {helper:?}: {source}")]
    LaunchGate { helper: PathBuf, source: io::Error },

    #[error("the gated runtime helper has no control pipe")]
    StartGateUnavailable,

    #[error("failed to release the gated runtime helper: {source}")]
    ReleaseStartGate { source: io::Error },

    #[error("failed to launch runtime executable {program:?}: {source}")]
    Launch { program: PathBuf, source: io::Error },

    #[error("failed to read gated executable error marker {path:?}: {source}")]
    ReadExecError { path: PathBuf, source: io::Error },

    #[error("failed to remove gated executable error marker {path:?}: {source}")]
    RemoveExecError { path: PathBuf, source: io::Error },

    #[error("runtime TCP port {port} is unavailable: {source}")]
    PortUnavailable { port: u16, source: io::Error },

    #[error("runtime process exited before its identity was recorded with status {status:?}")]
    ExitedBeforeRecord { status: Option<i32> },

    #[error("runtime process identity for PID {pid} was not available")]
    ProcessIdentityUnavailable { pid: u32 },

    #[error("failed to inspect runtime process: {0}")]
    InspectProcess(io::Error),

    #[error("failed to inspect process group for PID {pid}: {source}")]
    InspectProcessGroup { pid: u32, source: Errno },

    #[error("failed to wait for runtime process: {0}")]
    Wait(io::Error),

    #[error("runtime process ID {0} is invalid")]
    InvalidProcessId(u32),

    #[error("failed to signal runtime process group {process_group_id}: {source}")]
    SignalProcessGroup {
        process_group_id: u32,
        source: Errno,
    },

    #[error("runtime process group {process_group_id} did not stop")]
    StopTimeout { process_group_id: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permission_denied_group_probe_still_means_the_group_exists() {
        let group = pid_from_u32(42).expect("valid process group");

        assert!(
            classify_process_group_probe(group, Err(Errno::PERM))
                .expect("EPERM proves the process group exists")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_process_start_uses_boot_and_kernel_start_identity() {
        let stat = "123 (worker ) name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 0";
        assert_eq!(
            parse_linux_start_ticks(stat).expect("parse start ticks"),
            "424242"
        );

        let identity = current_process_identity().expect("read current process identity");
        assert!(identity.process_start.starts_with("linux-v1:"));
        assert!(!identity.process_start.ends_with(':'));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_process_start_uses_kernel_timestamp() {
        let pid = pid_from_u32(process::id()).expect("valid current PID");
        let first = macos_process_start(pid)
            .expect("read first stable identity")
            .expect("current process exists");
        let second = macos_process_start(pid)
            .expect("read second stable identity")
            .expect("current process still exists");

        assert!(first.starts_with("macos-v1:"));
        assert_eq!(first, second);
    }
}
