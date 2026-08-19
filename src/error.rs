use std::{ffi::OsString, io, path::PathBuf};

use thiserror::Error;

use crate::{
    detection::DetectionError, identity::IdentityError, inspection::InspectionError,
    registry::RegistryError, runtime::RuntimeError, state::StateError, supabase::SupabaseError,
};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("the {command} command is not implemented yet")]
    NotImplemented { command: &'static str },

    #[error("failed to determine the current directory: {0}")]
    CurrentDirectory(io::Error),

    #[error(transparent)]
    State(#[from] StateError),

    #[error(transparent)]
    Identity(#[from] IdentityError),

    #[error(transparent)]
    Detection(#[from] DetectionError),

    #[error(transparent)]
    Registry(#[from] RegistryError),

    #[error(transparent)]
    Runtime(#[from] RuntimeError),

    #[error(transparent)]
    Inspection(#[from] InspectionError),

    #[error("{0}")]
    Supabase(#[source] Box<SupabaseError>),

    #[error("no supported listening services were detected")]
    NoSupportedServices,

    #[error("exec requires a command after --")]
    MissingExecCommand,

    #[error("failed to execute command {program:?}: {source}")]
    CommandExec {
        program: OsString,
        source: io::Error,
    },

    #[error("no runtime log history exists for this project instance")]
    NoRuntimeHistory,

    #[error("no runtime log was recorded for service {service_key}")]
    UnknownLogService { service_key: String },

    #[error("the recorded log for service {service_key} does not exist at {path:?}")]
    LogNotFound { service_key: String, path: PathBuf },

    #[error("the recorded runtime log path is unsafe: {0:?}")]
    UnsafeLogPath(PathBuf),

    #[error("failed to read runtime log {path:?}: {source}")]
    ReadLog { path: PathBuf, source: io::Error },

    #[error("runtime session {session_id} has no recorded process")]
    MissingRuntimeProcess { session_id: Uuid },

    #[error("runtime session {session_id} has no recorded adapter")]
    MissingRuntimeAdapter { session_id: Uuid },

    #[error("runtime session {session_id} uses unsupported adapter {adapter_key}")]
    UnsupportedRuntimeAdapter {
        session_id: Uuid,
        adapter_key: String,
    },

    #[error("the detected project has no web TCP allocation")]
    MissingWebAllocation,

    #[error("no managed runtime was detected")]
    NoManagedRuntime,

    #[error("runtime session {session_id} failed before becoming ready")]
    RuntimeFailed { session_id: Uuid },

    #[error("runtime session {session_id} did not become ready within {timeout_seconds} seconds")]
    RuntimeWaitTimeout {
        session_id: Uuid,
        timeout_seconds: u64,
    },

    #[error("runtime session {session_id} did not become ready on TCP port {port}")]
    RuntimeNotReady { session_id: Uuid, port: u16 },

    #[error("runtime session {session_id} is still starting")]
    RuntimeStartInProgress { session_id: Uuid },

    #[error("runtime session {session_id} is still stopping")]
    RuntimeStopInProgress { session_id: Uuid },

    #[error("runtime session {session_id} PID {pid} no longer matches its recorded identity")]
    RuntimeOwnershipMismatch { session_id: Uuid, pid: u32 },

    #[error("runtime exited before becoming ready ({status}); see {log_path}")]
    RuntimeExitedBeforeReady { status: String, log_path: String },

    #[error("runtime did not become ready on TCP port {port}; see {log_path}")]
    RuntimeReadinessTimeout { port: u16, log_path: String },

    #[error("local Supabase did not expose every persistent local listener; see {log_path}")]
    SupabaseReadinessTimeout { log_path: String },

    #[error("runtime status is invalid: {0}")]
    InvalidRuntimeStatus(String),

    #[error("concurrent runtime operations did not converge")]
    RuntimeConvergence,

    #[error("runtime session {session_id} changed while its process was starting")]
    RuntimeSessionChanged { session_id: Uuid },
}

impl AppError {
    pub fn not_implemented(command: &'static str) -> Self {
        Self::NotImplemented { command }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::NotImplemented { .. } => "NOT_IMPLEMENTED",
            Self::CurrentDirectory(_) => "CURRENT_DIRECTORY_ERROR",
            Self::State(_) => "INVALID_STATE_DIR",
            Self::Identity(IdentityError::NotWorktree { .. }) => "NOT_GIT_WORKTREE",
            Self::Identity(IdentityError::GitUnavailable(_)) => "GIT_UNAVAILABLE",
            Self::Identity(_) => "GIT_IDENTITY_ERROR",
            Self::Detection(DetectionError::InvalidManifest { .. }) => "INVALID_PACKAGE_JSON",
            Self::Detection(DetectionError::AmbiguousDevScript { .. }) => "AMBIGUOUS_NEXT_SCRIPT",
            Self::Detection(DetectionError::ExplicitPort { .. }) => "EXPLICIT_PORT",
            Self::Detection(DetectionError::ExplicitHostname { .. }) => "EXPLICIT_HOSTNAME",
            Self::Detection(DetectionError::ReadManifest { .. }) => "PACKAGE_JSON_READ_ERROR",
            Self::Detection(DetectionError::ReadSupabaseConfig { .. }) => {
                "SUPABASE_CONFIG_READ_ERROR"
            }
            Self::Detection(DetectionError::ReadSupabaseEnvironment { .. }) => {
                "SUPABASE_CONFIG_READ_ERROR"
            }
            Self::Detection(DetectionError::UnsupportedSupabaseTls { .. }) => {
                "UNSUPPORTED_SUPABASE_CONFIG"
            }
            Self::Detection(DetectionError::InvalidSupabaseConfig { .. })
            | Self::Detection(DetectionError::InvalidSupabaseEnvironmentFile { .. })
            | Self::Detection(DetectionError::InvalidSupabaseField { .. })
            | Self::Detection(DetectionError::MissingSupabaseEnvironment { .. })
            | Self::Detection(DetectionError::InvalidSupabaseEnvironment { .. })
            | Self::Detection(DetectionError::AmbiguousSupabaseMailConfig { .. }) => {
                "INVALID_SUPABASE_CONFIG"
            }
            Self::Registry(RegistryError::EstablishedPortOccupied { .. }) => {
                "ESTABLISHED_PORT_OCCUPIED"
            }
            Self::Registry(RegistryError::PortProbeFailed { .. }) => "PORT_PROBE_FAILED",
            Self::Registry(RegistryError::NoPortsAvailable) => "NO_PORTS_AVAILABLE",
            Self::Registry(RegistryError::RuntimeStillStarting(_)) => "RUNTIME_STARTING",
            Self::Registry(RegistryError::RuntimeActive { .. }) => "RUNTIME_ACTIVE",
            Self::Registry(_) => "REGISTRY_ERROR",
            Self::Runtime(
                RuntimeError::Launch { .. }
                | RuntimeError::CurrentExecutable(_)
                | RuntimeError::LaunchGate { .. }
                | RuntimeError::StartGateUnavailable
                | RuntimeError::ReleaseStartGate { .. },
            ) => "RUNTIME_LAUNCH_FAILED",
            Self::Runtime(RuntimeError::PortUnavailable { .. }) => "RUNTIME_PORT_UNAVAILABLE",
            Self::Runtime(RuntimeError::StopTimeout { .. }) => "RUNTIME_STOP_TIMEOUT",
            Self::Runtime(RuntimeError::SignalProcessGroup { .. }) => "RUNTIME_SIGNAL_FAILED",
            Self::Runtime(_) => "RUNTIME_ERROR",
            Self::Inspection(_) => "PORT_INSPECTION_FAILED",
            Self::Supabase(error) => match error.as_ref() {
                SupabaseError::LaunchCli { .. } => "SUPABASE_CLI_UNAVAILABLE",
                SupabaseError::CliFailed {
                    action: "start", ..
                }
                | SupabaseError::WaitForCli {
                    action: "start", ..
                } => "SUPABASE_START_FAILED",
                SupabaseError::CliFailed { action: "stop", .. }
                | SupabaseError::WaitForCli { action: "stop", .. } => "SUPABASE_STOP_FAILED",
                _ => "SUPABASE_RUNTIME_ERROR",
            },
            Self::NoSupportedServices => "NO_SUPPORTED_SERVICES",
            Self::MissingExecCommand => "INVALID_ARGUMENTS",
            Self::CommandExec { .. } => "COMMAND_EXEC_ERROR",
            Self::NoRuntimeHistory => "NO_RUNTIME_HISTORY",
            Self::UnknownLogService { .. } => "UNKNOWN_LOG_SERVICE",
            Self::LogNotFound { .. } => "LOG_NOT_FOUND",
            Self::UnsafeLogPath(_) => "UNSAFE_LOG_PATH",
            Self::ReadLog { .. } => "LOG_READ_ERROR",
            Self::MissingRuntimeProcess { .. } => "INVALID_RUNTIME_RECORD",
            Self::MissingRuntimeAdapter { .. } | Self::UnsupportedRuntimeAdapter { .. } => {
                "INVALID_RUNTIME_RECORD"
            }
            Self::MissingWebAllocation => "MISSING_WEB_ALLOCATION",
            Self::NoManagedRuntime => "NO_MANAGED_RUNTIME",
            Self::RuntimeFailed { .. } => "RUNTIME_FAILED",
            Self::RuntimeWaitTimeout { .. } => "RUNTIME_WAIT_TIMEOUT",
            Self::RuntimeNotReady { .. } => "RUNTIME_NOT_READY",
            Self::RuntimeStartInProgress { .. } => "RUNTIME_STARTING",
            Self::RuntimeStopInProgress { .. } => "RUNTIME_STOPPING",
            Self::RuntimeOwnershipMismatch { .. } => "RUNTIME_OWNERSHIP_MISMATCH",
            Self::RuntimeExitedBeforeReady { .. } => "RUNTIME_EXITED_BEFORE_READY",
            Self::RuntimeReadinessTimeout { .. } => "RUNTIME_READINESS_TIMEOUT",
            Self::SupabaseReadinessTimeout { .. } => "RUNTIME_READINESS_TIMEOUT",
            Self::InvalidRuntimeStatus(_) => "INVALID_RUNTIME_RECORD",
            Self::RuntimeConvergence => "RUNTIME_CONCURRENCY_ERROR",
            Self::RuntimeSessionChanged { .. } => "RUNTIME_SESSION_CHANGED",
        }
    }
}

impl From<SupabaseError> for AppError {
    fn from(error: SupabaseError) -> Self {
        Self::Supabase(Box::new(error))
    }
}

#[derive(Debug)]
pub struct CommandFailure {
    pub error: AppError,
    pub changed: bool,
}

impl CommandFailure {
    pub fn new(error: AppError, changed: bool) -> Self {
        Self { error, changed }
    }
}

impl From<AppError> for CommandFailure {
    fn from(error: AppError) -> Self {
        Self::new(error, false)
    }
}

#[cfg(test)]
mod tests {
    use super::AppError;
    use crate::registry::RegistryError;

    #[test]
    fn port_probe_failure_has_a_stable_public_code() {
        let error = AppError::from(RegistryError::PortProbeFailed {
            port: 20_000,
            source: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        });

        assert_eq!(error.code(), "PORT_PROBE_FAILED");
    }
}
