use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    env,
    ffi::OsString,
    fs::{self, File},
    io::{self, BufRead, BufReader, Read},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command as ProcessCommand, Stdio},
    thread,
    time::{Duration, Instant},
};

use serde::Serialize;
use uuid::Uuid;

use crate::{
    detection::{DetectedProject, LaunchRequirement, PortRequirement, Protocol, detect_project},
    error::{AppError, CommandFailure},
    identity::GitLocation,
    inspection::{TcpPortState, inspect_ipv4_tcp},
    registry::{
        EnsuredAllocation, Registry, RegistryError, RuntimeClaim, RuntimeLogKind, RuntimeOwnerRef,
        StoredAllocation, StoredProjectInstance, StoredRuntimeAdapter, StoredRuntimeLog,
        StoredRuntimeProcess, StoredRuntimeService, StoredRuntimeSession,
    },
    runtime::{
        ProcessIdentity, ProcessOwnership, READINESS_TIMEOUT, RuntimeError,
        current_process_identity, probe_tcp_port, process_group_ownership,
        process_identity_matches, spawn_gated_logged, tcp_port_is_ready, terminate_process_group,
    },
    state::StatePaths,
    supabase::{self, ADAPTER_KEY, STARTUP_PROCESS_KEY},
};

const RUNTIME_POLL_INTERVAL: Duration = Duration::from_millis(50);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const STARTUP_READINESS_STABILITY: Duration = Duration::from_secs(2);
const LOST_READINESS_STABILITY: Duration = Duration::from_millis(250);
const RUNTIME_CONVERGENCE_ATTEMPTS: usize = 6;

#[derive(Debug)]
pub struct CommandSuccess<T> {
    pub changed: bool,
    pub data: T,
}

impl<T> CommandSuccess<T> {
    pub fn map<U>(self, transform: impl FnOnce(T) -> U) -> CommandSuccess<U> {
        CommandSuccess {
            changed: self.changed,
            data: transform(self.data),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum CommandData {
    Env(EnvData),
    Run(RunData),
    Status(StatusData),
    Wait(StatusData),
    Inspect(InspectData),
    Doctor(DoctorData),
    Stop(StopData),
    Reallocate(ReallocateData),
    Release(ReleaseData),
}

#[derive(Debug, Serialize)]
pub struct EnvData {
    pub project_id: Uuid,
    pub project_instance_id: Uuid,
    pub services: Vec<EnvService>,
    pub environment: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct EnvService {
    pub service_key: String,
    pub protocol: &'static str,
    pub port: u16,
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct StatusData {
    pub project_id: Option<Uuid>,
    pub project_instance_id: Option<Uuid>,
    pub services: Vec<StatusService>,
    pub runtime_session_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct StatusService {
    pub service_key: String,
    pub protocol: String,
    pub port: u16,
    pub url: Option<String>,
    pub owner_project_instance_id: Uuid,
    pub readiness: String,
}

#[derive(Debug, Serialize)]
pub struct InspectData {
    pub protocol: &'static str,
    pub port: u16,
    pub state: &'static str,
    pub allocation: Option<InspectAllocation>,
    pub process_evidence: &'static str,
    pub processes: Vec<InspectProcess>,
}

#[derive(Debug, Serialize)]
pub struct InspectAllocation {
    pub project_id: Uuid,
    pub project_instance_id: Uuid,
    pub service_key: String,
    pub worktree_root: String,
}

#[derive(Debug, Serialize)]
pub struct InspectProcess {
    pub pid: u32,
    pub command: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DoctorData {
    pub healthy: bool,
    pub project_id: Option<Uuid>,
    pub project_instance_id: Option<Uuid>,
    pub checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
pub struct DoctorCheck {
    pub code: String,
    pub status: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<DoctorRemediation>,
}

#[derive(Debug, Serialize)]
pub struct DoctorRemediation {
    pub command: String,
    pub changes_allocations: bool,
}

#[derive(Debug, Serialize)]
pub struct RunData {
    pub project_id: Uuid,
    pub project_instance_id: Uuid,
    pub runtime_session_id: Uuid,
    pub services: Vec<RunService>,
}

#[derive(Debug, Serialize)]
pub struct RunService {
    pub service_key: String,
    pub protocol: String,
    pub port: u16,
    pub url: String,
    pub readiness: &'static str,
    pub log_path: String,
}

#[derive(Debug, Serialize)]
pub struct StopData {
    pub project_id: Option<Uuid>,
    pub project_instance_id: Option<Uuid>,
    pub runtime_session_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct ReleaseData {
    pub project_id: Option<Uuid>,
    pub project_instance_id: Option<Uuid>,
    pub released_services: Vec<ReleasedService>,
}

#[derive(Debug, Serialize)]
pub struct ReallocateData {
    pub project_id: Uuid,
    pub project_instance_id: Uuid,
    pub previous_services: Vec<AllocationService>,
    pub services: Vec<AllocationService>,
}

#[derive(Debug, Serialize)]
pub struct AllocationService {
    pub service_key: String,
    pub protocol: String,
    pub port: u16,
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct ReleasedService {
    pub service_key: String,
    pub protocol: String,
    pub port: u16,
}

impl StatusData {
    fn empty() -> Self {
        Self {
            project_id: None,
            project_instance_id: None,
            services: Vec::new(),
            runtime_session_id: None,
        }
    }
}

impl ReleaseData {
    fn empty() -> Self {
        Self {
            project_id: None,
            project_instance_id: None,
            released_services: Vec::new(),
        }
    }
}

impl StopData {
    fn empty() -> Self {
        Self {
            project_id: None,
            project_instance_id: None,
            runtime_session_id: None,
        }
    }
}

struct StatusObservation {
    data: StatusData,
    runtime_status: Option<String>,
}

impl DoctorCheck {
    fn new(code: &str, status: &'static str, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            status,
            message: message.into(),
            service_key: None,
            port: None,
            remediation: None,
        }
    }

    fn service(mut self, service_key: &str, port: Option<u16>) -> Self {
        self.service_key = Some(service_key.to_owned());
        self.port = port;
        self
    }

    fn remediation(mut self, command: impl Into<String>, changes_allocations: bool) -> Self {
        self.remediation = Some(DoctorRemediation {
            command: command.into(),
            changes_allocations,
        });
        self
    }

    fn remediation_for_conflict(self, runtime_status: Option<&str>) -> Self {
        if matches!(runtime_status, Some("starting" | "ready" | "stopping")) {
            self.remediation("duckflap stop --json", false)
        } else {
            self.remediation("duckflap reallocate --json", true)
        }
    }
}

pub fn run_env() -> Result<CommandSuccess<EnvData>, CommandFailure> {
    let location = current_location()?;
    let detected = detect_current_project(&location)?;
    ensure_environment(&location, &detected)
}

fn ensure_environment(
    location: &GitLocation,
    detected: &DetectedProject,
) -> Result<CommandSuccess<EnvData>, CommandFailure> {
    let state_paths = StatePaths::discover()
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let mut registry = Registry::open_mutating(&state_paths)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let identity = registry
        .ensure_project_instance(location)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let service_keys = detected_service_keys(detected);
    let mut allowed_occupied = BTreeSet::new();
    let allocations = loop {
        match registry.ensure_dynamic_tcp_allocations_allowing(
            identity.project_instance_id,
            &service_keys,
            &allowed_occupied,
        ) {
            Ok(allocations) => break allocations,
            Err(source) => {
                let RegistryError::EstablishedPortOccupied {
                    service_key, port, ..
                } = &source
                else {
                    return Err(CommandFailure::new(
                        AppError::from(source),
                        identity.changed,
                    ));
                };
                let validated =
                    validated_managed_allocation(&registry, location, service_key, *port)
                        .map_err(|error| CommandFailure::new(error, identity.changed))?;
                if validated.is_none() || !allowed_occupied.insert((service_key.clone(), *port)) {
                    return Err(CommandFailure::new(
                        AppError::from(source),
                        identity.changed,
                    ));
                }
            }
        }
    };
    let changed = identity.changed || allocations.iter().any(|allocation| allocation.changed);
    let mut services = Vec::with_capacity(allocations.len());
    let mut environment = BTreeMap::new();

    for allocation in allocations {
        let url = service_url(&allocation.service_key, allocation.port);
        let environment_stem = allocation
            .service_key
            .replace('.', "_")
            .to_ascii_uppercase();
        let port = allocation.port.to_string();
        environment.insert(format!("DUCKFLAP_{environment_stem}_PORT"), port.clone());
        environment.insert(format!("DUCKFLAP_{environment_stem}_URL"), url.clone());
        if allocation.service_key == "web" {
            environment.insert("PORT".to_owned(), port.clone());
        }
        services.push(EnvService {
            service_key: allocation.service_key,
            protocol: allocation.protocol,
            port: allocation.port,
            url,
        });
    }

    Ok(CommandSuccess {
        changed,
        data: EnvData {
            project_id: identity.project_id,
            project_instance_id: identity.project_instance_id,
            services,
            environment,
        },
    })
}

fn detected_service_keys(detected: &DetectedProject) -> Vec<String> {
    detected
        .services
        .iter()
        .map(
            |requirement| match (requirement.protocol, requirement.port) {
                (Protocol::Tcp, PortRequirement::Dynamic) => requirement.service_key.clone(),
            },
        )
        .collect()
}

fn validated_managed_allocation(
    registry: &Registry,
    location: &GitLocation,
    service_key: &str,
    port: u16,
) -> Result<Option<EnsuredAllocation>, AppError> {
    let Some(stored) = registry.find_project_instance(location)? else {
        return Ok(None);
    };
    let Some(allocation) = stored
        .allocations
        .iter()
        .find(|allocation| {
            allocation.service_key == service_key
                && allocation.protocol == "tcp"
                && allocation.port == port
        })
        .cloned()
    else {
        return Ok(None);
    };
    let Some(session) = stored.active_runtime else {
        return Ok(None);
    };
    if session.adapter.as_ref().is_some_and(|adapter| {
        adapter.adapter_key == ADAPTER_KEY && adapter_has_service(adapter, service_key, "tcp", port)
    }) && supabase_service_is_persistent(service_key)
        && tcp_port_is_ready(port)
    {
        return Ok(Some(EnsuredAllocation {
            service_key: allocation.service_key,
            protocol: "tcp",
            port: allocation.port,
            changed: false,
        }));
    }
    let Some(process) = session.process else {
        return Ok(None);
    };
    if process.service_key != service_key {
        return Ok(None);
    }

    match process_group_ownership(
        process.pid,
        process.process_group_id,
        &process.process_start,
    )? {
        ProcessOwnership::Owned | ProcessOwnership::LeaderExited if tcp_port_is_ready(port) => {
            Ok(Some(EnsuredAllocation {
                service_key: allocation.service_key.clone(),
                protocol: "tcp",
                port: allocation.port,
                changed: false,
            }))
        }
        ProcessOwnership::Owned | ProcessOwnership::LeaderExited | ProcessOwnership::Gone => {
            Ok(None)
        }
        ProcessOwnership::Mismatch => Err(AppError::RuntimeOwnershipMismatch {
            session_id: session.id,
            pid: process.pid,
        }),
    }
}

pub fn run_detached() -> Result<CommandSuccess<RunData>, CommandFailure> {
    let location = current_location()?;
    let detected = detect_current_project(&location)?;
    let has_supabase = detected
        .services
        .iter()
        .any(|service| service.service_key.starts_with("supabase."));
    if detected.launch.is_none() && !has_supabase {
        return Err(AppError::NoManagedRuntime.into());
    }
    let state_paths = StatePaths::discover()
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let owner = current_process_identity()
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let mut changed = false;

    for _ in 0..RUNTIME_CONVERGENCE_ATTEMPTS {
        let mut predecessor_session_id = None;
        if let Some(stored) = load_stored_instance(&state_paths, &location)?
            && let Some(session) = stored.active_runtime.clone()
        {
            match resolve_existing_runtime(
                &state_paths,
                &location,
                &detected,
                stored,
                session,
                &owner,
            )? {
                ExistingRuntime::Ready(data) => {
                    return Ok(CommandSuccess { changed, data });
                }
                ExistingRuntime::Retry {
                    changed: reconciled,
                } => {
                    changed |= reconciled;
                    continue;
                }
                ExistingRuntime::Replace {
                    predecessor_session_id: predecessor,
                } => {
                    changed = true;
                    predecessor_session_id = Some(predecessor);
                }
            }
        }

        let ensured = match ensure_environment(&location, &detected) {
            Ok(ensured) => ensured,
            Err(failure)
                if predecessor_session_id.is_none()
                    && matches!(
                        failure.error,
                        AppError::Registry(
                            crate::registry::RegistryError::EstablishedPortOccupied { .. }
                        )
                    )
                    && load_stored_instance(&state_paths, &location)?
                        .is_some_and(|stored| stored.active_runtime.is_some()) =>
            {
                continue;
            }
            Err(mut failure) => {
                failure.changed |= changed;
                return Err(abort_replacement(
                    &state_paths,
                    predecessor_session_id,
                    &owner,
                    failure,
                ));
            }
        };
        changed |= ensured.changed;
        let runtime_service = if detected.launch.is_some() {
            ensured
                .data
                .services
                .iter()
                .find(|service| service.service_key == "web" && service.protocol == "tcp")
                .ok_or(AppError::MissingWebAllocation)
        } else {
            ensured
                .data
                .services
                .iter()
                .find(|service| {
                    service.service_key.starts_with("supabase.") && service.protocol == "tcp"
                })
                .ok_or(AppError::NoManagedRuntime)
        };
        let runtime_service = match runtime_service {
            Ok(runtime_service) => runtime_service,
            Err(error) => {
                return Err(abort_replacement(
                    &state_paths,
                    predecessor_session_id,
                    &owner,
                    CommandFailure::new(error, changed),
                ));
            }
        };
        let runtime_service_key = runtime_service.service_key.clone();
        let runtime_protocol = runtime_service.protocol;
        let runtime_port = runtime_service.port;

        let mut registry = match Registry::open_mutating(&state_paths) {
            Ok(registry) => registry,
            Err(source) => {
                return Err(abort_replacement(
                    &state_paths,
                    predecessor_session_id,
                    &owner,
                    CommandFailure::new(AppError::from(source), changed),
                ));
            }
        };
        let claim = match predecessor_session_id {
            Some(predecessor_session_id) => registry.replace_runtime_session_if_current(
                predecessor_session_id,
                ensured.data.project_instance_id,
                RuntimeOwnerRef {
                    pid: owner.pid,
                    process_start: &owner.process_start,
                },
                &runtime_service_key,
                runtime_protocol,
                runtime_port,
            ),
            None => registry
                .claim_runtime_session(
                    ensured.data.project_instance_id,
                    owner.pid,
                    &owner.process_start,
                    &runtime_service_key,
                    runtime_protocol,
                    runtime_port,
                )
                .map(Some),
        };
        let claim = match claim {
            Ok(Some(claim)) => claim,
            Ok(None) => continue,
            Err(RegistryError::RuntimeAllocationChanged { .. })
                if predecessor_session_id.is_none() =>
            {
                continue;
            }
            Err(source) => {
                return Err(abort_replacement(
                    &state_paths,
                    predecessor_session_id,
                    &owner,
                    CommandFailure::new(AppError::from(source), changed),
                ));
            }
        };
        if !claim.changed {
            continue;
        }
        changed = true;

        return start_claimed_stack(
            &mut registry,
            &state_paths,
            &location,
            detected.launch.as_ref(),
            ensured.data,
            claim.session,
            changed,
        );
    }

    Err(CommandFailure::new(AppError::RuntimeConvergence, changed))
}

fn abort_replacement(
    state_paths: &StatePaths,
    predecessor_session_id: Option<Uuid>,
    owner: &ProcessIdentity,
    failure: CommandFailure,
) -> CommandFailure {
    let Some(predecessor_session_id) = predecessor_session_id else {
        return failure;
    };
    let changed = failure.changed;
    let finalized = Registry::open_mutating(state_paths)
        .map_err(AppError::from)
        .map_err(|error| CommandFailure::new(error, changed))
        .and_then(|mut registry| {
            registry
                .mark_runtime_stopped_if_owned(
                    predecessor_session_id,
                    owner.pid,
                    &owner.process_start,
                )
                .map_err(AppError::from)
                .map_err(|error| CommandFailure::new(error, changed))
        });
    match finalized {
        Ok(_) => failure,
        Err(finalization_failure) => finalization_failure,
    }
}

enum ExistingRuntime {
    Ready(RunData),
    Retry { changed: bool },
    Replace { predecessor_session_id: Uuid },
}

fn runtime_owner_matches(session: &StoredRuntimeSession, owner: &ProcessIdentity) -> bool {
    session.launcher_pid == owner.pid
        && session.launcher_process_start.as_deref() == Some(owner.process_start.as_str())
}

fn runtime_owner_is_alive(session: &StoredRuntimeSession) -> Result<bool, CommandFailure> {
    let alive = match session.launcher_process_start.as_deref() {
        Some(process_start) => process_identity_matches(session.launcher_pid, process_start),
        None => Ok(false),
    };
    alive.map_err(AppError::from).map_err(CommandFailure::from)
}

fn resolve_existing_runtime(
    state_paths: &StatePaths,
    location: &GitLocation,
    detected: &DetectedProject,
    stored: StoredProjectInstance,
    session: StoredRuntimeSession,
    owner: &ProcessIdentity,
) -> Result<ExistingRuntime, CommandFailure> {
    match session.status.as_str() {
        "starting" => {
            let deadline = Instant::now() + STARTUP_TIMEOUT;
            loop {
                thread::sleep(RUNTIME_POLL_INTERVAL);
                let Some(current) = load_stored_instance(state_paths, location)? else {
                    return Ok(ExistingRuntime::Retry { changed: false });
                };
                let Some(active) = current.active_runtime.as_ref() else {
                    return Ok(ExistingRuntime::Retry { changed: false });
                };
                if active.id != session.id || active.status != "starting" {
                    return Ok(ExistingRuntime::Retry { changed: false });
                }
                if !runtime_owner_is_alive(active)? {
                    let mut registry = Registry::open_mutating(state_paths)
                        .map_err(AppError::from)
                        .map_err(CommandFailure::from)?;
                    let Some(claim) = registry
                        .claim_abandoned_runtime_stop_if_current(
                            active.project_instance_id,
                            active.id,
                            owner.pid,
                            &owner.process_start,
                        )
                        .map_err(AppError::from)
                        .map_err(CommandFailure::from)?
                    else {
                        return Ok(ExistingRuntime::Retry { changed: false });
                    };
                    if !claim.changed {
                        return Ok(ExistingRuntime::Retry { changed: false });
                    }
                    finish_claimed_failed_start(&mut registry, &claim.session, true)?;
                    return Ok(ExistingRuntime::Retry { changed: true });
                }
                if Instant::now() >= deadline {
                    return Err(AppError::RuntimeStartInProgress {
                        session_id: session.id,
                    }
                    .into());
                }
            }
        }
        "stopping" => {
            let deadline = Instant::now() + READINESS_TIMEOUT;
            loop {
                thread::sleep(RUNTIME_POLL_INTERVAL);
                let Some(current) = load_stored_instance(state_paths, location)? else {
                    return Ok(ExistingRuntime::Retry { changed: false });
                };
                let Some(active) = current.active_runtime.as_ref() else {
                    return Ok(ExistingRuntime::Retry { changed: false });
                };
                if active.id != session.id || active.status != "stopping" {
                    return Ok(ExistingRuntime::Retry { changed: false });
                }

                let owner_pid = active.launcher_pid;
                let owner_is_current = runtime_owner_matches(active, owner);
                let owner_is_alive = owner_is_current || runtime_owner_is_alive(active)?;
                if !owner_is_alive {
                    let mut registry = Registry::open_mutating(state_paths)
                        .map_err(AppError::from)
                        .map_err(CommandFailure::from)?;
                    let Some(claim) = registry
                        .take_over_runtime_stop_if_current(
                            active.project_instance_id,
                            active.id,
                            owner_pid,
                            active.launcher_process_start.as_deref(),
                            owner.pid,
                            &owner.process_start,
                        )
                        .map_err(AppError::from)
                        .map_err(CommandFailure::from)?
                    else {
                        return Ok(ExistingRuntime::Retry { changed: false });
                    };
                    cleanup_claimed_runtime(&claim.session, true)?;
                    return Ok(ExistingRuntime::Replace {
                        predecessor_session_id: claim.session.id,
                    });
                }
                if owner_is_current {
                    cleanup_claimed_runtime(active, true)?;
                    return Ok(ExistingRuntime::Replace {
                        predecessor_session_id: active.id,
                    });
                }
                if Instant::now() >= deadline {
                    return Err(AppError::RuntimeStopInProgress {
                        session_id: session.id,
                    }
                    .into());
                }
            }
        }
        "ready" => {
            if !runtime_matches_detection(&session, detected)? {
                return stop_existing_runtime(state_paths, &stored, &session, owner);
            }
            if runtime_session_is_ready(&stored, &session)? {
                return Ok(ExistingRuntime::Ready(run_data_from_stored(
                    &stored, &session,
                )?));
            }
            thread::sleep(LOST_READINESS_STABILITY);
            if runtime_session_is_ready(&stored, &session)? {
                return Ok(ExistingRuntime::Ready(run_data_from_stored(
                    &stored, &session,
                )?));
            }
            stop_existing_runtime(state_paths, &stored, &session, owner)
        }
        status => Err(AppError::InvalidRuntimeStatus(status.to_owned()).into()),
    }
}

fn stop_existing_runtime(
    state_paths: &StatePaths,
    stored: &StoredProjectInstance,
    session: &StoredRuntimeSession,
    owner: &ProcessIdentity,
) -> Result<ExistingRuntime, CommandFailure> {
    let mut registry = Registry::open_mutating(state_paths)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let Some(claim) = registry
        .claim_runtime_stop_if_current(
            stored.project_instance_id,
            session.id,
            owner.pid,
            &owner.process_start,
        )
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?
    else {
        return Ok(ExistingRuntime::Retry { changed: false });
    };
    if !claim.changed {
        return Ok(ExistingRuntime::Retry { changed: false });
    }
    cleanup_claimed_runtime(&claim.session, true)?;
    Ok(ExistingRuntime::Replace {
        predecessor_session_id: claim.session.id,
    })
}

fn finish_failed_start(
    registry: &mut Registry,
    project_instance_id: Uuid,
    session_id: Uuid,
    changed: bool,
) -> Result<(), CommandFailure> {
    let active = registry
        .find_active_runtime(project_instance_id)
        .map_err(AppError::from)
        .map_err(|error| CommandFailure::new(error, changed))?;
    let Some(active) = active.filter(|active| active.id == session_id) else {
        return Err(CommandFailure::new(
            AppError::RuntimeSessionChanged { session_id },
            changed,
        ));
    };
    cleanup_runtime_components(&active, changed)?;
    mark_failed_start(registry, session_id, changed)
}

fn finish_claimed_failed_start(
    registry: &mut Registry,
    session: &StoredRuntimeSession,
    changed: bool,
) -> Result<(), CommandFailure> {
    cleanup_runtime_components(session, changed)?;
    let marked = registry
        .mark_runtime_failed(session.id)
        .map_err(AppError::from)
        .map_err(|error| CommandFailure::new(error, changed))?;
    if marked {
        Ok(())
    } else {
        Err(CommandFailure::new(
            AppError::RuntimeSessionChanged {
                session_id: session.id,
            },
            changed,
        ))
    }
}

fn mark_failed_start(
    registry: &mut Registry,
    session_id: Uuid,
    changed: bool,
) -> Result<(), CommandFailure> {
    let marked = registry
        .mark_runtime_start_failed(session_id)
        .map_err(AppError::from)
        .map_err(|error| CommandFailure::new(error, changed))?;
    if marked {
        Ok(())
    } else {
        Err(CommandFailure::new(
            AppError::RuntimeSessionChanged { session_id },
            changed,
        ))
    }
}

struct SupabaseStartFailure {
    failure: CommandFailure,
    cleanup_required: bool,
}

impl SupabaseStartFailure {
    fn before_launch(failure: CommandFailure) -> Box<Self> {
        Box::new(Self {
            failure,
            cleanup_required: false,
        })
    }

    fn after_launch(failure: CommandFailure) -> Box<Self> {
        Box::new(Self {
            failure,
            cleanup_required: true,
        })
    }
}

fn cleanup_runtime_components(
    session: &StoredRuntimeSession,
    changed: bool,
) -> Result<(), CommandFailure> {
    let mut failure = None;
    if let Some(startup) = session.adapter_startup.as_ref()
        && let Err(error) = terminate_recorded_process_group(startup, session.id, changed)
    {
        return Err(error);
    }
    if let Some(adapter) = session.adapter.as_ref() {
        if adapter.adapter_key != ADAPTER_KEY {
            failure = Some(CommandFailure::new(
                AppError::UnsupportedRuntimeAdapter {
                    session_id: session.id,
                    adapter_key: adapter.adapter_key.clone(),
                },
                changed,
            ));
        } else if let Err(error) = stop_supabase_component(adapter, changed) {
            failure = Some(error);
        }
    }
    if let Some(process) = session.process.as_ref()
        && let Err(error) = terminate_recorded_process_group(process, session.id, changed)
        && failure.is_none()
    {
        failure = Some(error);
    }
    if let Some(failure) = failure {
        Err(failure)
    } else {
        Ok(())
    }
}

fn stop_supabase_component(
    adapter: &StoredRuntimeAdapter,
    changed: bool,
) -> Result<(), CommandFailure> {
    supabase::stop(
        std::path::Path::new(&adapter.working_directory),
        &adapter.runtime_project_id,
        std::path::Path::new(&adapter.log_path),
    )
    .map_err(AppError::from)
    .map_err(|error| CommandFailure::new(error, changed))
}

fn start_claimed_stack(
    registry: &mut Registry,
    state_paths: &StatePaths,
    location: &GitLocation,
    launch: Option<&LaunchRequirement>,
    environment: EnvData,
    session: StoredRuntimeSession,
    changed: bool,
) -> Result<CommandSuccess<RunData>, CommandFailure> {
    let mut adapter = None;
    if environment
        .services
        .iter()
        .any(|service| service.service_key.starts_with("supabase."))
    {
        match start_supabase_component(
            registry,
            state_paths,
            location,
            &environment,
            &session,
            changed,
        ) {
            Ok(started) => adapter = Some(started),
            Err(start_failure) => {
                if start_failure.cleanup_required {
                    finish_failed_start(
                        registry,
                        environment.project_instance_id,
                        session.id,
                        changed,
                    )?;
                } else {
                    mark_failed_start(registry, session.id, changed)?;
                }
                return Err(start_failure.failure);
            }
        }
    }

    let mut process = None;
    if let Some(launch) = launch {
        match start_web_component(
            registry,
            state_paths,
            location,
            launch,
            &environment,
            &session,
            changed,
        ) {
            Ok(started) => process = Some(started),
            Err(failure) => {
                finish_failed_start(
                    registry,
                    environment.project_instance_id,
                    session.id,
                    changed,
                )?;
                return Err(failure);
            }
        }
    }

    if process.is_some()
        && adapter.is_some()
        && let Err(failure) = wait_for_combined_readiness(
            &environment,
            &session,
            process.as_ref(),
            adapter.as_ref(),
            changed,
        )
    {
        finish_failed_start(
            registry,
            environment.project_instance_id,
            session.id,
            changed,
        )?;
        return Err(failure);
    }

    let marked_ready = match registry.mark_runtime_ready(session.id) {
        Ok(marked_ready) => marked_ready,
        Err(source) => {
            finish_failed_start(
                registry,
                environment.project_instance_id,
                session.id,
                changed,
            )?;
            return Err(CommandFailure::new(AppError::from(source), changed));
        }
    };
    if !marked_ready {
        finish_failed_start(
            registry,
            environment.project_instance_id,
            session.id,
            changed,
        )?;
        return Err(CommandFailure::new(
            AppError::RuntimeSessionChanged {
                session_id: session.id,
            },
            changed,
        ));
    }

    Ok(CommandSuccess {
        changed,
        data: run_data_from_environment(
            environment,
            session.id,
            process.as_ref(),
            adapter.as_ref(),
        ),
    })
}

fn start_web_component(
    registry: &mut Registry,
    state_paths: &StatePaths,
    location: &GitLocation,
    launch: &LaunchRequirement,
    environment: &EnvData,
    session: &StoredRuntimeSession,
    changed: bool,
) -> Result<StoredRuntimeProcess, CommandFailure> {
    let service = environment
        .services
        .iter()
        .find(|service| service.service_key == "web" && service.protocol == "tcp")
        .ok_or(AppError::MissingWebAllocation)?;
    if let Err(error) = probe_tcp_port(service.port) {
        return Err(CommandFailure::new(AppError::from(error), changed));
    }

    let log_path = state_paths
        .sessions()
        .join(session.id.to_string())
        .join("web.log");
    let mut spawned = match spawn_gated_logged(
        &launch.program,
        &launch.arguments,
        &environment.environment,
        location.worktree_root(),
        &log_path,
    ) {
        Ok(spawned) => spawned,
        Err(error) => {
            return Err(CommandFailure::new(AppError::from(error), changed));
        }
    };
    let stored_process = StoredRuntimeProcess {
        service_key: "web".to_owned(),
        pid: spawned.pid,
        process_group_id: spawned.process_group_id,
        process_start: spawned.process_start.clone(),
        executable: spawned.executable.clone(),
        log_path: spawned.log_path.to_string_lossy().into_owned(),
    };
    if let Err(error) = registry.record_runtime_process(session.id, &stored_process) {
        spawned.cancel();
        return Err(CommandFailure::new(AppError::from(error), changed));
    }
    if let Err(error) = spawned.release() {
        terminate_recorded_process_group(&stored_process, session.id, changed)?;
        let _ = spawned.child.wait();
        return Err(CommandFailure::new(AppError::from(error), changed));
    }

    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let mut ready_since = None;
    loop {
        if let Some(status) = spawned
            .child
            .try_wait()
            .map_err(RuntimeError::Wait)
            .map_err(AppError::from)
            .map_err(|error| CommandFailure::new(error, changed))?
        {
            #[cfg(target_os = "macos")]
            eprintln!(
                "duckflap macOS startup diagnostic: runtime pid={} pgid={} exited before readiness with status={status}; log={}",
                stored_process.pid,
                stored_process.process_group_id,
                fs::read_to_string(&stored_process.log_path)
                    .unwrap_or_else(|error| format!("<failed to read log: {error}>")),
            );
            terminate_recorded_process_group(&stored_process, session.id, changed)?;
            if let Some(source) = spawned
                .take_exec_error()
                .map_err(AppError::from)
                .map_err(|error| CommandFailure::new(error, changed))?
            {
                return Err(CommandFailure::new(
                    AppError::from(RuntimeError::Launch {
                        program: PathBuf::from(&stored_process.executable),
                        source,
                    }),
                    changed,
                ));
            }
            return Err(CommandFailure::new(
                AppError::RuntimeExitedBeforeReady {
                    status: status.to_string(),
                    log_path: stored_process.log_path,
                },
                changed,
            ));
        }
        if tcp_port_is_ready(service.port) {
            let first_ready = *ready_since.get_or_insert_with(Instant::now);
            if first_ready.elapsed() >= STARTUP_READINESS_STABILITY {
                drop(thread::spawn(move || {
                    let _ = spawned.child.wait();
                }));
                return Ok(stored_process);
            }
        } else {
            ready_since = None;
        }
        if Instant::now() >= deadline {
            #[cfg(target_os = "macos")]
            eprintln!(
                "duckflap macOS startup diagnostic: runtime pid={} pgid={} timed out waiting for port {}; log={}",
                stored_process.pid,
                stored_process.process_group_id,
                service.port,
                fs::read_to_string(&stored_process.log_path)
                    .unwrap_or_else(|error| format!("<failed to read log: {error}>")),
            );
            terminate_recorded_process_group(&stored_process, session.id, changed)?;
            let _ = spawned.child.wait();
            return Err(CommandFailure::new(
                AppError::RuntimeReadinessTimeout {
                    port: service.port,
                    log_path: stored_process.log_path,
                },
                changed,
            ));
        }
        thread::sleep(RUNTIME_POLL_INTERVAL);
    }
}

fn start_supabase_component(
    registry: &mut Registry,
    state_paths: &StatePaths,
    location: &GitLocation,
    environment: &EnvData,
    session: &StoredRuntimeSession,
    changed: bool,
) -> Result<StoredRuntimeAdapter, Box<SupabaseStartFailure>> {
    let ports = environment
        .services
        .iter()
        .filter(|service| service.service_key.starts_with("supabase."))
        .map(|service| (service.service_key.clone(), service.port))
        .collect::<BTreeMap<_, _>>();
    let materialized = match supabase::materialize(
        location.worktree_root(),
        state_paths,
        environment.project_instance_id,
        session.id,
        &ports,
    ) {
        Ok(materialized) => materialized,
        Err(source) => {
            return Err(SupabaseStartFailure::before_launch(CommandFailure::new(
                AppError::from(source),
                changed,
            )));
        }
    };
    let log_path = state_paths
        .sessions()
        .join(session.id.to_string())
        .join("supabase.log");
    let working_directory = materialized
        .working_directory
        .to_str()
        .ok_or_else(|| {
            SupabaseStartFailure::before_launch(CommandFailure::new(
                AppError::from(supabase::SupabaseError::NonUtf8Path(
                    materialized.working_directory.clone(),
                )),
                changed,
            ))
        })?
        .to_owned();
    let log_path_text = log_path
        .to_str()
        .ok_or_else(|| {
            SupabaseStartFailure::before_launch(CommandFailure::new(
                AppError::from(supabase::SupabaseError::NonUtf8Path(log_path.clone())),
                changed,
            ))
        })?
        .to_owned();
    let adapter = StoredRuntimeAdapter {
        adapter_key: ADAPTER_KEY.to_owned(),
        working_directory,
        runtime_project_id: materialized.project_id,
        log_path: log_path_text,
        services: environment
            .services
            .iter()
            .filter(|service| service.service_key.starts_with("supabase."))
            .map(|service| StoredRuntimeService {
                service_key: service.service_key.clone(),
                protocol: service.protocol.to_owned(),
                port: service.port,
            })
            .collect(),
    };
    if let Err(source) = registry.record_runtime_adapter(session.id, &adapter) {
        return Err(SupabaseStartFailure::before_launch(CommandFailure::new(
            AppError::from(source),
            changed,
        )));
    }
    if let Err(source) = probe_supabase_services(&adapter.services) {
        return Err(SupabaseStartFailure::before_launch(CommandFailure::new(
            AppError::from(source),
            changed,
        )));
    }
    let mut pending = match supabase::prepare_start(
        std::path::Path::new(&adapter.working_directory),
        std::path::Path::new(&adapter.log_path),
    ) {
        Ok(pending) => pending,
        Err(source) => {
            return Err(SupabaseStartFailure::before_launch(CommandFailure::new(
                AppError::from(source),
                changed,
            )));
        }
    };
    let startup_process = StoredRuntimeProcess {
        service_key: STARTUP_PROCESS_KEY.to_owned(),
        pid: pending.pid,
        process_group_id: pending.process_group_id,
        process_start: pending.process_start.clone(),
        executable: pending.executable.clone(),
        log_path: adapter.log_path.clone(),
    };
    if let Err(source) = registry.record_runtime_process(session.id, &startup_process) {
        pending.cancel();
        return Err(SupabaseStartFailure::before_launch(CommandFailure::new(
            AppError::from(source),
            changed,
        )));
    }
    if let Err(source) =
        supabase::release_and_wait_for_start(&mut pending, std::path::Path::new(&adapter.log_path))
    {
        let cleanup_required = source.start_may_have_created_resources();
        let failure = CommandFailure::new(AppError::from(source), changed);
        return Err(if cleanup_required {
            SupabaseStartFailure::after_launch(failure)
        } else {
            SupabaseStartFailure::before_launch(failure)
        });
    }
    match registry.clear_runtime_process(session.id, STARTUP_PROCESS_KEY) {
        Ok(true) => {}
        Ok(false) => {
            return Err(SupabaseStartFailure::after_launch(CommandFailure::new(
                AppError::RuntimeSessionChanged {
                    session_id: session.id,
                },
                changed,
            )));
        }
        Err(source) => {
            return Err(SupabaseStartFailure::after_launch(CommandFailure::new(
                AppError::from(source),
                changed,
            )));
        }
    }

    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let mut ready_since = None;
    loop {
        if adapter
            .services
            .iter()
            .filter(|service| supabase_service_is_persistent(&service.service_key))
            .all(|service| tcp_port_is_ready(service.port))
        {
            let first_ready = *ready_since.get_or_insert_with(Instant::now);
            if first_ready.elapsed() >= STARTUP_READINESS_STABILITY {
                return Ok(adapter);
            }
        } else {
            ready_since = None;
        }
        if Instant::now() >= deadline {
            return Err(SupabaseStartFailure::after_launch(CommandFailure::new(
                AppError::SupabaseReadinessTimeout {
                    log_path: adapter.log_path,
                },
                changed,
            )));
        }
        thread::sleep(RUNTIME_POLL_INTERVAL);
    }
}

fn wait_for_combined_readiness(
    environment: &EnvData,
    session: &StoredRuntimeSession,
    process: Option<&StoredRuntimeProcess>,
    adapter: Option<&StoredRuntimeAdapter>,
    changed: bool,
) -> Result<(), CommandFailure> {
    let process = process.ok_or_else(|| {
        CommandFailure::new(
            AppError::MissingRuntimeProcess {
                session_id: session.id,
            },
            changed,
        )
    })?;
    let adapter = adapter.ok_or_else(|| {
        CommandFailure::new(
            AppError::MissingRuntimeAdapter {
                session_id: session.id,
            },
            changed,
        )
    })?;
    let web_port = environment
        .services
        .iter()
        .find(|service| service.service_key == process.service_key && service.protocol == "tcp")
        .map(|service| service.port)
        .ok_or_else(|| CommandFailure::new(AppError::MissingWebAllocation, changed))?;
    let deadline = Instant::now() + READINESS_TIMEOUT;
    let mut ready_since = None;

    loop {
        let web_ready = recorded_process_is_ready(process, session.id, web_port)
            .map_err(|error| CommandFailure::new(error, changed))?;
        let supabase_ready = supabase_adapter_ports_ready(adapter);
        if web_ready && supabase_ready {
            let first_ready = *ready_since.get_or_insert_with(Instant::now);
            if first_ready.elapsed() >= STARTUP_READINESS_STABILITY {
                return Ok(());
            }
        } else {
            ready_since = None;
        }
        if Instant::now() >= deadline {
            let error = if !supabase_ready {
                AppError::SupabaseReadinessTimeout {
                    log_path: adapter.log_path.clone(),
                }
            } else {
                AppError::RuntimeReadinessTimeout {
                    port: web_port,
                    log_path: process.log_path.clone(),
                }
            };
            return Err(CommandFailure::new(error, changed));
        }
        thread::sleep(RUNTIME_POLL_INTERVAL);
    }
}

pub fn run_status() -> Result<CommandSuccess<StatusData>, CommandFailure> {
    let location = current_location()?;
    let state_paths = StatePaths::discover()
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let observation = observe_status(&state_paths, &location)?;
    Ok(CommandSuccess {
        changed: false,
        data: observation.data,
    })
}

pub fn run_doctor() -> Result<CommandSuccess<DoctorData>, CommandFailure> {
    let cwd = env::current_dir()
        .map_err(AppError::CurrentDirectory)
        .map_err(CommandFailure::from)?;
    let mut checks = Vec::new();
    let location = match GitLocation::discover(cwd) {
        Ok(location) => {
            checks.push(DoctorCheck::new(
                "GIT_IDENTITY_VALID",
                "pass",
                "canonical Git project and worktree identity is available",
            ));
            location
        }
        Err(error) => {
            checks.push(doctor_error_check(AppError::from(error)));
            return Ok(doctor_success(None, None, checks));
        }
    };

    let detected = match detect_project(location.worktree_root()) {
        Ok(Some(detected)) => {
            checks.push(DoctorCheck::new(
                "SERVICES_DETECTED",
                "pass",
                format!("detected {} supported service(s)", detected.services.len()),
            ));
            Some(detected)
        }
        Ok(None) => {
            checks.push(DoctorCheck::new(
                "NO_SUPPORTED_SERVICES",
                "failure",
                "no supported listening services were detected",
            ));
            None
        }
        Err(error) => {
            checks.push(doctor_error_check(AppError::from(error)));
            None
        }
    };

    let state_paths = match StatePaths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            checks.push(doctor_error_check(AppError::from(error)));
            return Ok(doctor_success(None, None, checks));
        }
    };
    let registry = match Registry::open_observational(&state_paths) {
        Ok(registry) => registry,
        Err(error) => {
            checks.push(doctor_error_check(AppError::from(error)));
            return Ok(doctor_success(None, None, checks));
        }
    };
    let Some(registry) = registry else {
        checks.push(DoctorCheck::new(
            "REGISTRY_ABSENT",
            "pass",
            "Duckflap has no registry state yet",
        ));
        add_missing_allocation_checks(&mut checks, detected.as_ref());
        checks.push(DoctorCheck::new(
            "RUNTIME_ABSENT",
            "pass",
            "no managed runtime has been recorded",
        ));
        return Ok(doctor_success(None, None, checks));
    };
    let stored = match registry.find_project_instance(&location) {
        Ok(stored) => stored,
        Err(error) => {
            checks.push(doctor_error_check(AppError::from(error)));
            return Ok(doctor_success(None, None, checks));
        }
    };
    let Some(stored) = stored else {
        checks.push(DoctorCheck::new(
            "PROJECT_INSTANCE_ABSENT",
            "pass",
            "the registry has no state for this worktree",
        ));
        add_missing_allocation_checks(&mut checks, detected.as_ref());
        checks.push(DoctorCheck::new(
            "RUNTIME_ABSENT",
            "pass",
            "no managed runtime has been recorded",
        ));
        return Ok(doctor_success(None, None, checks));
    };

    let project_id = stored.project_id;
    let project_instance_id = stored.project_instance_id;
    checks.push(DoctorCheck::new(
        "REGISTRY_READABLE",
        "pass",
        "the stored project instance is readable",
    ));
    let observation = match status_observation_from_stored(stored.clone()) {
        Ok(observation) => Some(observation),
        Err(failure) => {
            checks.push(doctor_error_check(failure.error));
            None
        }
    };
    let run_changes_allocations = detected.as_ref().is_some_and(|detected| {
        detected_service_keys(detected).iter().any(|service_key| {
            !stored.allocations.iter().any(|allocation| {
                allocation.service_key == *service_key && allocation.protocol == "tcp"
            })
        })
    });
    add_service_checks(
        &mut checks,
        detected.as_ref(),
        &stored,
        observation.as_ref(),
        run_changes_allocations,
    );
    let reported_runtime = stored
        .active_runtime
        .as_ref()
        .or(stored.latest_runtime.as_ref());
    add_runtime_check(
        &mut checks,
        observation.as_ref(),
        reported_runtime,
        run_changes_allocations,
    );

    Ok(doctor_success(
        Some(project_id),
        Some(project_instance_id),
        checks,
    ))
}

fn doctor_success(
    project_id: Option<Uuid>,
    project_instance_id: Option<Uuid>,
    checks: Vec<DoctorCheck>,
) -> CommandSuccess<DoctorData> {
    let healthy = checks.iter().all(|check| check.status != "failure");
    CommandSuccess {
        changed: false,
        data: DoctorData {
            healthy,
            project_id,
            project_instance_id,
            checks,
        },
    }
}

fn doctor_error_check(error: AppError) -> DoctorCheck {
    let code = error.code();
    DoctorCheck::new(code, "failure", error.to_string())
}

fn add_missing_allocation_checks(
    checks: &mut Vec<DoctorCheck>,
    detected: Option<&DetectedProject>,
) {
    let Some(detected) = detected else {
        return;
    };
    for service_key in detected_service_keys(detected) {
        checks.push(
            DoctorCheck::new(
                "ALLOCATION_MISSING",
                "warning",
                "the detected service has no allocation; env or run will create one",
            )
            .service(&service_key, None)
            .remediation("duckflap env --json", true),
        );
    }
}

fn add_service_checks(
    checks: &mut Vec<DoctorCheck>,
    detected: Option<&DetectedProject>,
    stored: &StoredProjectInstance,
    observation: Option<&StatusObservation>,
    run_changes_allocations: bool,
) {
    let runtime_status = stored
        .active_runtime
        .as_ref()
        .or(stored.latest_runtime.as_ref())
        .map(|session| session.status.as_str());
    let runtime_is_active = matches!(runtime_status, Some("starting" | "ready" | "stopping"));
    let desired = detected
        .map(detected_service_keys)
        .unwrap_or_default()
        .into_iter()
        .collect::<BTreeSet<_>>();

    for service_key in &desired {
        let allocation = stored.allocations.iter().find(|allocation| {
            allocation.service_key == *service_key && allocation.protocol == "tcp"
        });
        let Some(allocation) = allocation else {
            checks.push(
                DoctorCheck::new(
                    "ALLOCATION_MISSING",
                    "warning",
                    "the detected service has no allocation; env or run will create one",
                )
                .service(service_key, None)
                .remediation("duckflap env --json", true),
            );
            continue;
        };
        let readiness = observation.and_then(|observation| {
            observation.data.services.iter().find(|service| {
                service.service_key == allocation.service_key
                    && service.protocol == allocation.protocol
                    && service.port == allocation.port
            })
        });
        match inspect_ipv4_tcp(allocation.port) {
            Ok((state, _)) => checks.push(doctor_service_check(
                allocation,
                readiness,
                state,
                runtime_status,
                run_changes_allocations,
            )),
            Err(error) => checks.push(
                doctor_error_check(AppError::from(error))
                    .service(&allocation.service_key, Some(allocation.port)),
            ),
        }
    }

    for allocation in stored
        .allocations
        .iter()
        .filter(|allocation| !desired.contains(&allocation.service_key))
    {
        let check = DoctorCheck::new(
            "HISTORICAL_ALLOCATION",
            "warning",
            "the allocation belongs to a service that is no longer detected",
        )
        .service(&allocation.service_key, Some(allocation.port));
        checks.push(if runtime_is_active {
            check.remediation("duckflap stop --json", false)
        } else {
            check.remediation("duckflap release --json", true)
        });
    }
}

fn doctor_service_check(
    allocation: &StoredAllocation,
    status: Option<&StatusService>,
    port_state: TcpPortState,
    runtime_status: Option<&str>,
    run_changes_allocations: bool,
) -> DoctorCheck {
    let readiness = status.map(|service| service.readiness.as_str());
    let service =
        |check: DoctorCheck| check.service(&allocation.service_key, Some(allocation.port));
    if port_state == TcpPortState::Occupied {
        return service(
            DoctorCheck::new(
                "ALLOCATION_CONFLICT",
                "failure",
                "the allocated IPv4 TCP port is occupied but not reachable on loopback",
            )
            .remediation_for_conflict(runtime_status),
        );
    }

    match (port_state, readiness) {
        (TcpPortState::Listening, Some("ready")) => service(DoctorCheck::new(
            "SERVICE_READY",
            "pass",
            "the managed service is listening and ready",
        )),
        (TcpPortState::Listening, Some("starting" | "stopping")) => service(DoctorCheck::new(
            "SERVICE_TRANSITIONING",
            "warning",
            "the managed service is listening while its runtime is transitioning",
        )),
        (TcpPortState::Listening, _) => service(
            DoctorCheck::new(
                "ALLOCATION_CONFLICT",
                "failure",
                "the allocated IPv4 TCP port has a listener that is not a healthy managed runtime",
            )
            .remediation_for_conflict(runtime_status),
        ),
        (TcpPortState::Free, Some("stale")) if runtime_status == Some("failed") => service(
            DoctorCheck::new(
                "RUNTIME_FAILED",
                "failure",
                "the latest managed runtime failed",
            )
            .remediation("duckflap run --detach --json", run_changes_allocations),
        ),
        (TcpPortState::Free, Some("stale" | "ready")) => service(
            DoctorCheck::new(
                "RUNTIME_STALE",
                "failure",
                "the recorded managed runtime is not listening on its allocated port",
            )
            .remediation("duckflap stop --json", false),
        ),
        (TcpPortState::Free, Some("starting" | "stopping")) => service(DoctorCheck::new(
            "SERVICE_TRANSITIONING",
            "warning",
            "the allocated port is free while its runtime is transitioning",
        )),
        (TcpPortState::Free, _) => service(DoctorCheck::new(
            "ALLOCATION_AVAILABLE",
            "pass",
            "the allocated IPv4 TCP port is available",
        )),
        (TcpPortState::Occupied, _) => unreachable!("occupied handled above"),
    }
}

fn add_runtime_check(
    checks: &mut Vec<DoctorCheck>,
    observation: Option<&StatusObservation>,
    session: Option<&StoredRuntimeSession>,
    run_changes_allocations: bool,
) {
    let Some(observation) = observation else {
        return;
    };
    match observation.runtime_status.as_deref() {
        None => checks.push(DoctorCheck::new(
            "RUNTIME_ABSENT",
            "pass",
            "no managed runtime has been recorded",
        )),
        Some("stopped") => checks.push(DoctorCheck::new(
            "RUNTIME_STOPPED",
            "pass",
            "the latest managed runtime is stopped",
        )),
        Some("starting" | "stopping") => {
            let Some(session) = session else {
                checks.push(DoctorCheck::new(
                    "INVALID_RUNTIME_RECORD",
                    "failure",
                    "the transitioning runtime session is missing",
                ));
                return;
            };
            match runtime_owner_is_alive(session) {
                Ok(true) => checks.push(DoctorCheck::new(
                    "RUNTIME_TRANSITIONING",
                    "warning",
                    "the managed runtime is transitioning",
                )),
                Ok(false) => checks.push(
                    DoctorCheck::new(
                        "RUNTIME_TRANSITION_ABANDONED",
                        "failure",
                        "the process that owned the runtime transition is no longer running",
                    )
                    .remediation("duckflap stop --json", false),
                ),
                Err(failure) => checks.push(doctor_error_check(failure.error)),
            }
        }
        Some("ready")
            if observation
                .data
                .services
                .iter()
                .filter(|service| service.readiness != "not_started")
                .all(|service| service.readiness == "ready") =>
        {
            checks.push(DoctorCheck::new(
                "RUNTIME_READY",
                "pass",
                "the managed runtime is ready",
            ));
        }
        Some("ready") => checks.push(
            DoctorCheck::new(
                "RUNTIME_STALE",
                "failure",
                "the recorded managed runtime is not healthy",
            )
            .remediation("duckflap stop --json", false),
        ),
        Some("failed") => checks.push(
            DoctorCheck::new(
                "RUNTIME_FAILED",
                "failure",
                "the latest managed runtime failed",
            )
            .remediation("duckflap run --detach --json", run_changes_allocations),
        ),
        Some(status) => checks.push(DoctorCheck::new(
            "INVALID_RUNTIME_STATUS",
            "failure",
            format!("the recorded runtime status is invalid: {status}"),
        )),
    }
}

pub fn run_inspect(port: u16) -> Result<CommandSuccess<InspectData>, CommandFailure> {
    let state_paths = StatePaths::discover()
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let allocation = match Registry::open_observational(&state_paths)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?
    {
        Some(registry) => registry
            .find_allocation_by_port("tcp", port)
            .map_err(AppError::from)
            .map_err(CommandFailure::from)?,
        None => None,
    };
    let (state, evidence) = inspect_ipv4_tcp(port)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let process_evidence = if state == TcpPortState::Free {
        "not_applicable"
    } else if evidence.available {
        "available"
    } else {
        "unavailable"
    };

    Ok(CommandSuccess {
        changed: false,
        data: InspectData {
            protocol: "tcp",
            port,
            state: state.as_str(),
            allocation: allocation.map(|allocation| InspectAllocation {
                project_id: allocation.project_id,
                project_instance_id: allocation.project_instance_id,
                service_key: allocation.service_key,
                worktree_root: allocation.worktree_root,
            }),
            process_evidence,
            processes: evidence
                .processes
                .into_iter()
                .map(|process| InspectProcess {
                    pid: process.pid,
                    command: process.command,
                })
                .collect(),
        },
    })
}

pub fn run_wait(timeout: Duration) -> Result<CommandSuccess<StatusData>, CommandFailure> {
    let location = current_location()?;
    let state_paths = StatePaths::discover()
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let started = Instant::now();

    loop {
        let observation = observe_status(&state_paths, &location)?;
        let Some(runtime_status) = observation.runtime_status.as_deref() else {
            return Err(AppError::NoManagedRuntime.into());
        };
        let session_id = observation
            .data
            .runtime_session_id
            .ok_or(AppError::NoManagedRuntime)?;

        match runtime_status {
            "failed" => return Err(AppError::RuntimeFailed { session_id }.into()),
            "stopped" => return Err(AppError::NoManagedRuntime.into()),
            "ready"
                if observation
                    .data
                    .services
                    .iter()
                    .any(|service| service.readiness == "ready")
                    && observation.data.services.iter().all(|service| {
                        matches!(service.readiness.as_str(), "ready" | "not_started")
                    }) =>
            {
                return Ok(CommandSuccess {
                    changed: false,
                    data: observation.data,
                });
            }
            "starting" | "stopping" | "ready" => {}
            status => return Err(AppError::InvalidRuntimeStatus(status.to_owned()).into()),
        }

        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Err(AppError::RuntimeWaitTimeout {
                session_id,
                timeout_seconds: timeout.as_secs(),
            }
            .into());
        }
        thread::sleep(RUNTIME_POLL_INTERVAL.min(timeout - elapsed));
    }
}

fn observe_status(
    state_paths: &StatePaths,
    location: &GitLocation,
) -> Result<StatusObservation, CommandFailure> {
    let Some(registry) = Registry::open_observational(state_paths)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?
    else {
        return Ok(StatusObservation {
            data: StatusData::empty(),
            runtime_status: None,
        });
    };
    let Some(stored) = registry
        .find_project_instance(location)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?
    else {
        return Ok(StatusObservation {
            data: StatusData::empty(),
            runtime_status: None,
        });
    };

    status_observation_from_stored(stored)
}

fn status_observation_from_stored(
    stored: StoredProjectInstance,
) -> Result<StatusObservation, CommandFailure> {
    let reported_runtime = stored
        .active_runtime
        .as_ref()
        .or(stored.latest_runtime.as_ref());
    let runtime_session_id = reported_runtime.map(|session| session.id);
    let runtime_status = reported_runtime.map(|session| session.status.clone());
    let services = stored
        .allocations
        .into_iter()
        .map(|allocation| {
            let readiness = if reported_runtime.is_some_and(|session| {
                runtime_has_service(
                    session,
                    &allocation.service_key,
                    &allocation.protocol,
                    allocation.port,
                )
            }) {
                runtime_readiness(
                    reported_runtime,
                    &allocation.service_key,
                    &allocation.protocol,
                    allocation.port,
                )?
            } else {
                "not_started".to_owned()
            };
            Ok(StatusService {
                url: (allocation.protocol == "tcp")
                    .then(|| service_url(&allocation.service_key, allocation.port)),
                service_key: allocation.service_key,
                protocol: allocation.protocol,
                port: allocation.port,
                owner_project_instance_id: stored.project_instance_id,
                readiness,
            })
        })
        .collect::<Result<Vec<_>, CommandFailure>>()?;

    Ok(StatusObservation {
        data: StatusData {
            project_id: Some(stored.project_id),
            project_instance_id: Some(stored.project_instance_id),
            services,
            runtime_session_id,
        },
        runtime_status,
    })
}

pub fn run_logs(service_key: &str, tail: usize) -> Result<Vec<u8>, CommandFailure> {
    let location = current_location()?;
    let state_paths = StatePaths::discover()
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let Some(registry) = Registry::open_observational(&state_paths)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?
    else {
        return Err(AppError::NoRuntimeHistory.into());
    };
    let Some(stored) = registry
        .find_project_instance(&location)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?
    else {
        return Err(AppError::NoRuntimeHistory.into());
    };
    if stored.latest_runtime.is_none() {
        return Err(AppError::NoRuntimeHistory.into());
    }
    let Some(log) = registry
        .find_latest_runtime_log(stored.project_instance_id, service_key)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?
    else {
        return Err(AppError::UnknownLogService {
            service_key: service_key.to_owned(),
        }
        .into());
    };

    read_runtime_log_tail(&state_paths, service_key, &log, tail).map_err(CommandFailure::from)
}

fn read_runtime_log_tail(
    state_paths: &StatePaths,
    service_key: &str,
    log: &StoredRuntimeLog,
    tail: usize,
) -> Result<Vec<u8>, AppError> {
    let file_name = match log.kind {
        RuntimeLogKind::Process => "web.log",
        RuntimeLogKind::Adapter => "supabase.log",
    };
    let session_path = state_paths.sessions().join(log.session_id.to_string());
    let expected_log_path = session_path.join(file_name);
    let log_path = Path::new(&log.log_path);
    if log_path != expected_log_path {
        return Err(AppError::UnsafeLogPath(log_path.to_path_buf()));
    }
    if !log_path.is_absolute() {
        return Err(AppError::UnsafeLogPath(log_path.to_path_buf()));
    }
    let metadata = match fs::symlink_metadata(log_path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Err(AppError::LogNotFound {
                service_key: service_key.to_owned(),
                path: log_path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(AppError::ReadLog {
                path: log_path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AppError::UnsafeLogPath(log_path.to_path_buf()));
    }

    let canonical_state =
        fs::canonicalize(state_paths.root()).map_err(|source| AppError::ReadLog {
            path: state_paths.root().to_path_buf(),
            source,
        })?;
    let sessions_path = state_paths.sessions();
    let sessions_metadata =
        fs::symlink_metadata(&sessions_path).map_err(|source| AppError::ReadLog {
            path: sessions_path.clone(),
            source,
        })?;
    if sessions_metadata.file_type().is_symlink() || !sessions_metadata.is_dir() {
        return Err(AppError::UnsafeLogPath(sessions_path));
    }
    let canonical_sessions =
        fs::canonicalize(&sessions_path).map_err(|source| AppError::ReadLog {
            path: sessions_path,
            source,
        })?;
    if !canonical_sessions.starts_with(&canonical_state) {
        return Err(AppError::UnsafeLogPath(canonical_sessions));
    }
    let session_metadata = fs::symlink_metadata(&session_path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            AppError::LogNotFound {
                service_key: service_key.to_owned(),
                path: log_path.to_path_buf(),
            }
        } else {
            AppError::ReadLog {
                path: session_path.clone(),
                source,
            }
        }
    })?;
    if session_metadata.file_type().is_symlink() || !session_metadata.is_dir() {
        return Err(AppError::UnsafeLogPath(session_path));
    }
    let canonical_session =
        fs::canonicalize(&session_path).map_err(|source| AppError::ReadLog {
            path: session_path,
            source,
        })?;
    if canonical_session.parent() != Some(canonical_sessions.as_path()) {
        return Err(AppError::UnsafeLogPath(canonical_session));
    }
    let canonical_log = fs::canonicalize(log_path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            AppError::LogNotFound {
                service_key: service_key.to_owned(),
                path: log_path.to_path_buf(),
            }
        } else {
            AppError::ReadLog {
                path: log_path.to_path_buf(),
                source,
            }
        }
    })?;
    if canonical_log.parent() != Some(canonical_session.as_path())
        || canonical_log.file_name() != Some(Path::new(file_name).as_os_str())
    {
        return Err(AppError::UnsafeLogPath(log_path.to_path_buf()));
    }

    tail_file(&canonical_log, tail).map_err(|source| AppError::ReadLog {
        path: canonical_log,
        source,
    })
}

fn tail_file(path: &Path, tail: usize) -> io::Result<Vec<u8>> {
    if tail == 0 {
        return Ok(Vec::new());
    }
    let file = File::open(path)?;
    let snapshot_len = file.metadata()?.len();
    tail_file_snapshot(file, snapshot_len, tail)
}

fn tail_file_snapshot(file: File, snapshot_len: u64, tail: usize) -> io::Result<Vec<u8>> {
    if tail == 0 {
        return Ok(Vec::new());
    }
    let mut reader = BufReader::new(file.take(snapshot_len));
    let mut lines = VecDeque::new();
    loop {
        let mut line = Vec::new();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        if lines.len() == tail {
            lines.pop_front();
        }
        lines.push_back(line);
    }

    let mut output = Vec::with_capacity(lines.iter().map(Vec::len).sum());
    for line in lines {
        output.extend(line);
    }
    Ok(output)
}

pub fn run_stop() -> Result<CommandSuccess<StopData>, CommandFailure> {
    let location = current_location()?;
    let state_paths = StatePaths::discover()
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let Some(stored) = load_stored_instance(&state_paths, &location)? else {
        return Ok(CommandSuccess {
            changed: false,
            data: StopData::empty(),
        });
    };
    let project_id = stored.project_id;
    let project_instance_id = stored.project_instance_id;
    let mut last_session_id = stored.latest_runtime.as_ref().map(|session| session.id);
    if stored.active_runtime.is_none() {
        return Ok(CommandSuccess {
            changed: false,
            data: StopData {
                project_id: Some(project_id),
                project_instance_id: Some(project_instance_id),
                runtime_session_id: last_session_id,
            },
        });
    }
    let owner = current_process_identity()
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;

    let mut registry = Registry::open_mutating(&state_paths)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let mut observed_session_id = None;
    let mut following_replacement = false;
    let mut deadline = Instant::now() + READINESS_TIMEOUT;

    loop {
        let Some(active) = registry
            .find_active_runtime(project_instance_id)
            .map_err(AppError::from)
            .map_err(CommandFailure::from)?
        else {
            return Ok(CommandSuccess {
                changed: false,
                data: StopData {
                    project_id: Some(project_id),
                    project_instance_id: Some(project_instance_id),
                    runtime_session_id: last_session_id,
                },
            });
        };
        last_session_id = Some(active.id);
        if observed_session_id.is_some_and(|observed| observed != active.id) {
            following_replacement = true;
            deadline = Instant::now() + STARTUP_TIMEOUT;
        }
        observed_session_id = Some(active.id);

        if active.status == "stopping" {
            let owner_pid = active.launcher_pid;
            let owner_is_current = runtime_owner_matches(&active, &owner);
            let owner_is_alive = owner_is_current || runtime_owner_is_alive(&active)?;
            if owner_is_alive && !owner_is_current {
                if Instant::now() >= deadline {
                    return Err(AppError::RuntimeStopInProgress {
                        session_id: active.id,
                    }
                    .into());
                }
                thread::sleep(RUNTIME_POLL_INTERVAL);
                continue;
            }
            let claim = if owner_is_current {
                Some(RuntimeClaim {
                    session: active,
                    changed: false,
                })
            } else {
                registry
                    .take_over_runtime_stop_if_current(
                        project_instance_id,
                        active.id,
                        owner_pid,
                        active.launcher_process_start.as_deref(),
                        owner.pid,
                        &owner.process_start,
                    )
                    .map_err(AppError::from)
                    .map_err(CommandFailure::from)?
            };
            let Some(claim) = claim else {
                continue;
            };
            let changed =
                stop_claimed_runtime(&mut registry, &claim.session, &owner, claim.changed)?;
            return Ok(CommandSuccess {
                changed,
                data: StopData {
                    project_id: Some(project_id),
                    project_instance_id: Some(project_instance_id),
                    runtime_session_id: Some(claim.session.id),
                },
            });
        }

        let abandoned_start = if active.status == "starting" && active.process.is_none() {
            if runtime_owner_is_alive(&active)? {
                if !following_replacement || Instant::now() >= deadline {
                    return Err(AppError::RuntimeStartInProgress {
                        session_id: active.id,
                    }
                    .into());
                }
                thread::sleep(RUNTIME_POLL_INTERVAL);
                continue;
            }
            true
        } else {
            false
        };
        let claim = if abandoned_start {
            registry.claim_abandoned_runtime_stop_if_current(
                project_instance_id,
                active.id,
                owner.pid,
                &owner.process_start,
            )
        } else {
            registry.claim_runtime_stop_if_current(
                project_instance_id,
                active.id,
                owner.pid,
                &owner.process_start,
            )
        };
        let Some(claim) = claim
            .map_err(AppError::from)
            .map_err(CommandFailure::from)?
        else {
            continue;
        };
        if !runtime_owner_matches(&claim.session, &owner) {
            if Instant::now() >= deadline {
                return Err(AppError::RuntimeStopInProgress {
                    session_id: claim.session.id,
                }
                .into());
            }
            thread::sleep(RUNTIME_POLL_INTERVAL);
            continue;
        }
        let changed = stop_claimed_runtime(&mut registry, &claim.session, &owner, claim.changed)?;
        return Ok(CommandSuccess {
            changed,
            data: StopData {
                project_id: Some(project_id),
                project_instance_id: Some(project_instance_id),
                runtime_session_id: Some(claim.session.id),
            },
        });
    }
}

fn stop_claimed_runtime(
    registry: &mut Registry,
    session: &StoredRuntimeSession,
    owner: &ProcessIdentity,
    changed: bool,
) -> Result<bool, CommandFailure> {
    cleanup_claimed_runtime(session, changed)?;

    let stopped = registry
        .mark_runtime_stopped_if_owned(session.id, owner.pid, &owner.process_start)
        .map_err(AppError::from)
        .map_err(|error| CommandFailure::new(error, changed))?;
    if !stopped {
        return Err(CommandFailure::new(
            AppError::RuntimeSessionChanged {
                session_id: session.id,
            },
            changed,
        ));
    }
    Ok(changed || stopped)
}

fn cleanup_claimed_runtime(
    session: &StoredRuntimeSession,
    changed: bool,
) -> Result<(), CommandFailure> {
    if session.process.is_none() && session.adapter_startup.is_none() && session.adapter.is_none() {
        return Ok(());
    }

    if let Some(process) = session.process.as_ref() {
        let ownership = process_group_ownership(
            process.pid,
            process.process_group_id,
            &process.process_start,
        )
        .map_err(AppError::from)
        .map_err(|error| CommandFailure::new(error, changed))?;
        if ownership == ProcessOwnership::Mismatch {
            return Err(CommandFailure::new(
                AppError::RuntimeOwnershipMismatch {
                    session_id: session.id,
                    pid: process.pid,
                },
                changed,
            ));
        }
    }

    if session.adapter.is_some() {
        match supabase_adapter(session) {
            Ok(_) => {}
            Err(failure) => {
                return Err(CommandFailure::new(
                    failure.error,
                    changed || failure.changed,
                ));
            }
        }
    }

    cleanup_runtime_components(session, changed)?;
    Ok(())
}

pub fn run_release() -> Result<CommandSuccess<ReleaseData>, CommandFailure> {
    let location = current_location()?;
    let state_paths = StatePaths::discover()
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let Some(registry) = Registry::open_observational(&state_paths)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?
    else {
        return Ok(CommandSuccess {
            changed: false,
            data: ReleaseData::empty(),
        });
    };
    let Some(stored) = registry
        .find_project_instance(&location)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?
    else {
        return Ok(CommandSuccess {
            changed: false,
            data: ReleaseData::empty(),
        });
    };

    drop(registry);
    let mut registry = Registry::open_mutating(&state_paths)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let released = registry
        .release_allocations(stored.project_instance_id)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let released_services = released
        .into_iter()
        .map(|allocation| ReleasedService {
            service_key: allocation.service_key,
            protocol: allocation.protocol,
            port: allocation.port,
        })
        .collect::<Vec<_>>();

    Ok(CommandSuccess {
        changed: !released_services.is_empty(),
        data: ReleaseData {
            project_id: Some(stored.project_id),
            project_instance_id: Some(stored.project_instance_id),
            released_services,
        },
    })
}

pub fn run_reallocate() -> Result<CommandSuccess<ReallocateData>, CommandFailure> {
    let location = current_location()?;
    let detected = detect_current_project(&location)?;
    let state_paths = StatePaths::discover()
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let mut registry = Registry::open_mutating(&state_paths)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let identity = registry
        .ensure_project_instance(&location)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?;
    let reallocated = registry
        .reallocate_dynamic_tcp_allocations(
            identity.project_instance_id,
            &detected_service_keys(&detected),
        )
        .map_err(|error| CommandFailure::new(AppError::from(error), identity.changed))?;
    let previous_services = reallocated
        .previous_allocations
        .into_iter()
        .map(allocation_service)
        .collect();
    let services = reallocated
        .allocations
        .into_iter()
        .map(allocation_service)
        .collect();

    Ok(CommandSuccess {
        changed: identity.changed || reallocated.changed,
        data: ReallocateData {
            project_id: identity.project_id,
            project_instance_id: identity.project_instance_id,
            previous_services,
            services,
        },
    })
}

fn allocation_service(allocation: StoredAllocation) -> AllocationService {
    AllocationService {
        url: service_url(&allocation.service_key, allocation.port),
        service_key: allocation.service_key,
        protocol: allocation.protocol,
        port: allocation.port,
    }
}

pub fn run_exec(command: &[OsString]) -> Result<(), CommandFailure> {
    let Some(program) = command.first() else {
        return Err(AppError::MissingExecCommand.into());
    };
    let ensured = run_env()?;
    let changed = ensured.changed;

    let source = ProcessCommand::new(program)
        .args(&command[1..])
        .envs(ensured.data.environment)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .exec();

    Err(CommandFailure::new(
        AppError::CommandExec {
            program: program.clone(),
            source,
        },
        changed,
    ))
}

fn detect_current_project(location: &GitLocation) -> Result<DetectedProject, CommandFailure> {
    detect_project(location.worktree_root())
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?
        .ok_or_else(|| AppError::NoSupportedServices.into())
}

fn load_stored_instance(
    state_paths: &StatePaths,
    location: &GitLocation,
) -> Result<Option<StoredProjectInstance>, CommandFailure> {
    let Some(registry) = Registry::open_observational(state_paths)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)?
    else {
        return Ok(None);
    };
    registry
        .find_project_instance(location)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)
}

fn runtime_readiness(
    session: Option<&StoredRuntimeSession>,
    service_key: &str,
    protocol: &str,
    port: u16,
) -> Result<String, CommandFailure> {
    let Some(session) = session else {
        return Ok("not_started".to_owned());
    };
    match session.status.as_str() {
        "stopped" => Ok("stopped".to_owned()),
        "failed" => Ok("stale".to_owned()),
        "stopping" => Ok("stopping".to_owned()),
        "starting" => {
            if session
                .process
                .as_ref()
                .is_some_and(|process| process.service_key == service_key)
            {
                let process = session.process.as_ref().expect("checked above");
                let ownership = process_group_ownership(
                    process.pid,
                    process.process_group_id,
                    &process.process_start,
                )
                .map_err(AppError::from)
                .map_err(CommandFailure::from)?;
                Ok(match ownership {
                    ProcessOwnership::Owned | ProcessOwnership::LeaderExited => "starting",
                    ProcessOwnership::Gone | ProcessOwnership::Mismatch => "stale",
                }
                .to_owned())
            } else if session
                .adapter
                .as_ref()
                .is_some_and(|adapter| adapter_has_service(adapter, service_key, protocol, port))
            {
                Ok(if runtime_owner_is_alive(session)? {
                    "starting"
                } else {
                    "stale"
                }
                .to_owned())
            } else {
                Ok("not_started".to_owned())
            }
        }
        "ready" => {
            if let Some(process) = session
                .process
                .as_ref()
                .filter(|process| process.service_key == service_key)
            {
                let ownership = process_group_ownership(
                    process.pid,
                    process.process_group_id,
                    &process.process_start,
                )
                .map_err(AppError::from)
                .map_err(CommandFailure::from)?;
                return Ok(if matches!(
                    ownership,
                    ProcessOwnership::Owned | ProcessOwnership::LeaderExited
                ) && tcp_port_is_ready(port)
                {
                    "ready"
                } else {
                    "stale"
                }
                .to_owned());
            }
            if let Some(adapter) = session
                .adapter
                .as_ref()
                .filter(|adapter| adapter_has_service(adapter, service_key, protocol, port))
            {
                return Ok(
                    if adapter.adapter_key == ADAPTER_KEY && tcp_port_is_ready(port) {
                        "ready"
                    } else {
                        "stale"
                    }
                    .to_owned(),
                );
            }
            Ok("not_started".to_owned())
        }
        status => Err(AppError::InvalidRuntimeStatus(status.to_owned()).into()),
    }
}

fn runtime_has_service(
    session: &StoredRuntimeSession,
    service_key: &str,
    protocol: &str,
    port: u16,
) -> bool {
    session
        .process
        .as_ref()
        .is_some_and(|process| process.service_key == service_key && protocol == "tcp")
        || session.adapter.as_ref().is_some_and(|adapter| {
            supabase_service_is_persistent(service_key)
                && adapter_has_service(adapter, service_key, protocol, port)
        })
}

fn runtime_matches_detection(
    session: &StoredRuntimeSession,
    detected: &DetectedProject,
) -> Result<bool, CommandFailure> {
    let desired_web = detected.launch.is_some();
    let actual_web = session
        .process
        .as_ref()
        .is_some_and(|process| process.service_key == "web");
    if desired_web != actual_web {
        return Ok(false);
    }

    let desired_supabase = detected
        .services
        .iter()
        .filter(|service| service.service_key.starts_with("supabase."))
        .map(|service| (service.service_key.clone(), "tcp".to_owned()))
        .collect::<BTreeSet<_>>();
    let Some(adapter) = session.adapter.as_ref() else {
        return Ok(desired_supabase.is_empty());
    };
    supabase_adapter(session)?;
    let actual_supabase = adapter
        .services
        .iter()
        .map(|service| (service.service_key.clone(), service.protocol.clone()))
        .collect::<BTreeSet<_>>();
    Ok(desired_supabase == actual_supabase)
}

fn recorded_process_is_ready(
    process: &StoredRuntimeProcess,
    session_id: Uuid,
    port: u16,
) -> Result<bool, AppError> {
    match process_group_ownership(
        process.pid,
        process.process_group_id,
        &process.process_start,
    )? {
        ProcessOwnership::Owned | ProcessOwnership::LeaderExited => Ok(tcp_port_is_ready(port)),
        ProcessOwnership::Gone => Ok(false),
        ProcessOwnership::Mismatch => Err(AppError::RuntimeOwnershipMismatch {
            session_id,
            pid: process.pid,
        }),
    }
}

fn runtime_session_is_ready(
    stored: &StoredProjectInstance,
    session: &StoredRuntimeSession,
) -> Result<bool, CommandFailure> {
    let mut has_component = false;
    if let Some(process) = session.process.as_ref() {
        has_component = true;
        let Some(allocation) = stored.allocations.iter().find(|allocation| {
            allocation.service_key == process.service_key && allocation.protocol == "tcp"
        }) else {
            return Ok(false);
        };
        if !recorded_process_is_ready(process, session.id, allocation.port)
            .map_err(CommandFailure::from)?
        {
            return Ok(false);
        }
    }
    if session.adapter.is_some() {
        has_component = true;
        supabase_adapter(session)?;
        if !supabase_ports_ready(session) {
            return Ok(false);
        }
    }
    Ok(has_component)
}

fn run_data_from_stored(
    stored: &StoredProjectInstance,
    session: &StoredRuntimeSession,
) -> Result<RunData, CommandFailure> {
    let mut services = Vec::new();
    if let Some(process) = session.process.as_ref() {
        services.extend(
            stored
                .allocations
                .iter()
                .filter(|allocation| allocation.service_key == process.service_key)
                .map(|allocation| RunService {
                    url: service_url(&allocation.service_key, allocation.port),
                    service_key: allocation.service_key.clone(),
                    protocol: allocation.protocol.clone(),
                    port: allocation.port,
                    readiness: "ready",
                    log_path: process.log_path.clone(),
                }),
        );
    }
    if let Some(adapter) = session.adapter.as_ref() {
        supabase_adapter(session)?;
        services.extend(
            adapter
                .services
                .iter()
                .filter(|service| supabase_service_is_persistent(&service.service_key))
                .map(|service| RunService {
                    service_key: service.service_key.clone(),
                    protocol: service.protocol.clone(),
                    port: service.port,
                    url: service_url(&service.service_key, service.port),
                    readiness: "ready",
                    log_path: adapter.log_path.clone(),
                }),
        );
    }
    services.sort_by(|left, right| left.service_key.cmp(&right.service_key));
    if services.is_empty() {
        return Err(AppError::MissingRuntimeProcess {
            session_id: session.id,
        }
        .into());
    }
    Ok(RunData {
        project_id: stored.project_id,
        project_instance_id: stored.project_instance_id,
        runtime_session_id: session.id,
        services,
    })
}

fn run_data_from_environment(
    environment: EnvData,
    session_id: Uuid,
    process: Option<&StoredRuntimeProcess>,
    adapter: Option<&StoredRuntimeAdapter>,
) -> RunData {
    let mut services = environment
        .services
        .into_iter()
        .filter_map(|service| {
            let log_path =
                if process.is_some_and(|process| process.service_key == service.service_key) {
                    process.map(|process| process.log_path.clone())
                } else if adapter.is_some_and(|adapter| {
                    supabase_service_is_persistent(&service.service_key)
                        && adapter_has_service(
                            adapter,
                            &service.service_key,
                            service.protocol,
                            service.port,
                        )
                }) {
                    adapter.map(|adapter| adapter.log_path.clone())
                } else {
                    None
                }?;
            Some(RunService {
                service_key: service.service_key,
                protocol: service.protocol.to_owned(),
                port: service.port,
                url: service.url,
                readiness: "ready",
                log_path,
            })
        })
        .collect::<Vec<_>>();
    services.sort_by(|left, right| left.service_key.cmp(&right.service_key));
    RunData {
        project_id: environment.project_id,
        project_instance_id: environment.project_instance_id,
        runtime_session_id: session_id,
        services,
    }
}

fn supabase_adapter(
    session: &StoredRuntimeSession,
) -> Result<&StoredRuntimeAdapter, CommandFailure> {
    let adapter = session
        .adapter
        .as_ref()
        .ok_or(AppError::MissingRuntimeAdapter {
            session_id: session.id,
        })?;
    if adapter.adapter_key != ADAPTER_KEY {
        return Err(AppError::UnsupportedRuntimeAdapter {
            session_id: session.id,
            adapter_key: adapter.adapter_key.clone(),
        }
        .into());
    }
    Ok(adapter)
}

fn supabase_ports_ready(session: &StoredRuntimeSession) -> bool {
    let Some(adapter) = session.adapter.as_ref() else {
        return false;
    };
    supabase_adapter_ports_ready(adapter)
}

fn supabase_adapter_ports_ready(adapter: &StoredRuntimeAdapter) -> bool {
    let mut found = false;
    for service in adapter
        .services
        .iter()
        .filter(|service| supabase_service_is_persistent(&service.service_key))
    {
        found = true;
        if service.protocol != "tcp" || !tcp_port_is_ready(service.port) {
            return false;
        }
    }
    found
}

fn adapter_has_service(
    adapter: &StoredRuntimeAdapter,
    service_key: &str,
    protocol: &str,
    port: u16,
) -> bool {
    adapter.services.iter().any(|service| {
        service.service_key == service_key && service.protocol == protocol && service.port == port
    })
}

fn probe_supabase_services(services: &[StoredRuntimeService]) -> Result<(), RuntimeError> {
    for service in services {
        probe_tcp_port(service.port)?;
    }
    Ok(())
}

fn supabase_service_is_persistent(service_key: &str) -> bool {
    service_key.starts_with("supabase.")
        && !matches!(
            service_key,
            "supabase.db.shadow" | "supabase.edge_inspector" | "supabase.analytics.vector"
        )
}

fn service_url(service_key: &str, port: u16) -> String {
    let scheme = match service_key {
        "supabase.db" | "supabase.db.shadow" | "supabase.pooler" => "postgresql",
        "supabase.mail.smtp" => "smtp",
        "supabase.mail.pop3" => "pop3",
        "supabase.analytics.vector" => "tcp",
        _ => "http",
    };
    format!("{scheme}://127.0.0.1:{port}")
}

fn terminate_recorded_process_group(
    process: &StoredRuntimeProcess,
    session_id: Uuid,
    changed: bool,
) -> Result<(), CommandFailure> {
    let ownership = process_group_ownership(
        process.pid,
        process.process_group_id,
        &process.process_start,
    )
    .map_err(AppError::from)
    .map_err(|error| CommandFailure::new(error, changed))?;
    match ownership {
        ProcessOwnership::Owned | ProcessOwnership::LeaderExited => {
            terminate_process_group(process.process_group_id)
                .map_err(AppError::from)
                .map_err(|error| CommandFailure::new(error, true))
        }
        ProcessOwnership::Gone => Ok(()),
        ProcessOwnership::Mismatch => Err(CommandFailure::new(
            AppError::RuntimeOwnershipMismatch {
                session_id,
                pid: process.pid,
            },
            changed,
        )),
    }
}

fn current_location() -> Result<GitLocation, CommandFailure> {
    let cwd = env::current_dir()
        .map_err(AppError::CurrentDirectory)
        .map_err(CommandFailure::from)?;
    GitLocation::discover(cwd)
        .map_err(AppError::from)
        .map_err(CommandFailure::from)
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, File, OpenOptions},
        io::Write,
        net::{Ipv4Addr, SocketAddrV4, TcpListener},
    };

    use crate::{registry::StoredRuntimeService, runtime::RuntimeError};
    use tempfile::tempdir;

    use super::{probe_supabase_services, tail_file_snapshot};

    #[test]
    fn final_supabase_probe_rejects_an_occupied_port() {
        let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
            .expect("bind occupied test port");
        let port = listener.local_addr().expect("listener address").port();
        let services = [StoredRuntimeService {
            service_key: "supabase.api".to_owned(),
            protocol: "tcp".to_owned(),
            port,
        }];

        let error = probe_supabase_services(&services).expect_err("reject occupied port");
        assert!(matches!(error, RuntimeError::PortUnavailable { port: busy, .. } if busy == port));
    }

    #[test]
    fn log_snapshot_ignores_bytes_appended_after_length_capture() {
        let temp = tempdir().expect("create temp directory");
        let path = temp.path().join("runtime.log");
        fs::write(&path, b"first\nsecond\n").expect("write initial log");
        let file = File::open(&path).expect("open log snapshot");
        let snapshot_len = file.metadata().expect("read snapshot metadata").len();
        OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open active log writer")
            .write_all(b"future\n")
            .expect("append future log bytes");

        let output = tail_file_snapshot(file, snapshot_len, 20).expect("read log snapshot");
        assert_eq!(output, b"first\nsecond\n");
    }
}
