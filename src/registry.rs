use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    path::Path,
    time::Duration,
};

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    identity::GitLocation,
    state::{StatePaths, ensure_private_directory},
};

const MIGRATIONS: &[(i64, &str)] = &[
    (1, include_str!("../migrations/0001_initial.sql")),
    (2, include_str!("../migrations/0002_runtime.sql")),
    (3, include_str!("../migrations/0003_runtime_adapters.sql")),
    (
        4,
        include_str!("../migrations/0004_runtime_owner_identity.sql"),
    ),
];
pub const DEFAULT_PORT_START: u16 = 20_000;
pub const DEFAULT_PORT_END: u16 = 29_999;

pub struct Registry {
    connection: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsuredIdentity {
    pub project_id: Uuid,
    pub project_instance_id: Uuid,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsuredAllocation {
    pub service_key: String,
    pub protocol: &'static str,
    pub port: u16,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReallocatedAllocationSet {
    pub previous_allocations: Vec<StoredAllocation>,
    pub allocations: Vec<StoredAllocation>,
    pub changed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredProjectInstance {
    pub project_id: Uuid,
    pub project_instance_id: Uuid,
    pub allocations: Vec<StoredAllocation>,
    pub active_runtime: Option<StoredRuntimeSession>,
    pub latest_runtime: Option<StoredRuntimeSession>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAllocation {
    pub service_key: String,
    pub protocol: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPortAllocation {
    pub project_id: Uuid,
    pub project_instance_id: Uuid,
    pub service_key: String,
    pub protocol: String,
    pub port: u16,
    pub worktree_root: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRuntimeSession {
    pub id: Uuid,
    pub project_instance_id: Uuid,
    pub status: String,
    pub launcher_pid: u32,
    pub launcher_process_start: Option<String>,
    pub process: Option<StoredRuntimeProcess>,
    pub adapter_startup: Option<StoredRuntimeProcess>,
    pub adapter: Option<StoredRuntimeAdapter>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeOwnerRef<'a> {
    pub pid: u32,
    pub process_start: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRuntimeProcess {
    pub service_key: String,
    pub pid: u32,
    pub process_group_id: u32,
    pub process_start: String,
    pub executable: String,
    pub log_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRuntimeAdapter {
    pub adapter_key: String,
    pub working_directory: String,
    pub runtime_project_id: String,
    pub log_path: String,
    pub services: Vec<StoredRuntimeService>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRuntimeService {
    pub service_key: String,
    pub protocol: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeLogKind {
    Process,
    Adapter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRuntimeLog {
    pub session_id: Uuid,
    pub kind: RuntimeLogKind,
    pub log_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeClaim {
    pub session: StoredRuntimeSession,
    pub changed: bool,
}

impl Registry {
    pub fn open_mutating(paths: &StatePaths) -> Result<Self, RegistryError> {
        ensure_private_directory(paths.root())?;

        let mut connection = Connection::open(paths.registry())?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        apply_migrations(&mut connection)?;

        Ok(Self { connection })
    }

    pub fn open_observational(paths: &StatePaths) -> Result<Option<Self>, RegistryError> {
        if !paths.registry().try_exists()? {
            return Ok(None);
        }

        let connection =
            Connection::open_with_flags(paths.registry(), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        connection.busy_timeout(Duration::from_secs(5))?;

        let initialized = connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM sqlite_schema
                WHERE type = 'table' AND name = 'schema_migrations'
            )",
            [],
            |row| row.get::<_, bool>(0),
        )?;
        if !initialized {
            return Ok(None);
        }

        Ok(Some(Self { connection }))
    }

    pub fn find_allocation_by_port(
        &self,
        protocol: &str,
        port: u16,
    ) -> Result<Option<StoredPortAllocation>, RegistryError> {
        let stored = self
            .connection
            .query_row(
                "SELECT projects.id,
                        project_instances.id,
                        allocations.service_key,
                        allocations.protocol,
                        allocations.port,
                        project_instances.worktree_root
                 FROM allocations
                 JOIN project_instances
                   ON project_instances.id = allocations.project_instance_id
                 JOIN projects
                   ON projects.id = project_instances.project_id
                 WHERE allocations.protocol = ?1
                   AND allocations.port = ?2",
                params![protocol, port],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?;
        stored
            .map(
                |(project_id, project_instance_id, service_key, protocol, port, worktree_root)| {
                    Ok(StoredPortAllocation {
                        project_id: Uuid::parse_str(&project_id)?,
                        project_instance_id: Uuid::parse_str(&project_instance_id)?,
                        service_key,
                        protocol,
                        port: stored_port(port)?,
                        worktree_root,
                    })
                },
            )
            .transpose()
    }

    pub fn find_project_instance(
        &self,
        location: &GitLocation,
    ) -> Result<Option<StoredProjectInstance>, RegistryError> {
        let common_dir = path_text(location.git_common_dir())?;
        let worktree_git_dir = path_text(location.worktree_git_dir())?;
        let worktree_root = path_text(location.worktree_root())?;
        let transaction = self.connection.unchecked_transaction()?;
        let identity = transaction
            .query_row(
                "SELECT projects.id, project_instances.id, project_instances.worktree_root
                 FROM projects
                 JOIN project_instances
                   ON project_instances.project_id = projects.id
                 WHERE projects.git_common_dir = ?1
                   AND project_instances.worktree_git_dir = ?2",
                params![common_dir, worktree_git_dir],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((project_id, project_instance_id, stored_root)) = identity else {
            transaction.commit()?;
            return Ok(None);
        };
        if stored_root != worktree_root {
            return Err(RegistryError::IdentityConflict);
        }

        let rows = {
            let mut statement = transaction.prepare(
                "SELECT service_key, protocol, port
                 FROM allocations
                 WHERE project_instance_id = ?1
                 ORDER BY service_key, protocol",
            )?;
            statement
                .query_map([&project_instance_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut allocations = Vec::with_capacity(rows.len());
        for (service_key, protocol, port) in rows {
            allocations.push(StoredAllocation {
                service_key,
                protocol,
                port: u16::try_from(port).map_err(|_| RegistryError::InvalidStoredPort(port))?,
            });
        }

        let project_instance_uuid = Uuid::parse_str(&project_instance_id)?;
        let runtime_schema_available = schema_version(&transaction)? >= 2;
        let active_runtime = if runtime_schema_available {
            find_active_runtime(&transaction, project_instance_uuid)?
        } else {
            None
        };
        let latest_runtime = if runtime_schema_available {
            find_latest_runtime(&transaction, project_instance_uuid)?
        } else {
            None
        };

        let stored = StoredProjectInstance {
            project_id: Uuid::parse_str(&project_id)?,
            project_instance_id: project_instance_uuid,
            allocations,
            active_runtime,
            latest_runtime,
        };
        transaction.commit()?;
        Ok(Some(stored))
    }

    pub fn find_active_runtime(
        &self,
        project_instance_id: Uuid,
    ) -> Result<Option<StoredRuntimeSession>, RegistryError> {
        if !self.runtime_schema_available()? {
            return Ok(None);
        }
        find_active_runtime(&self.connection, project_instance_id)
    }

    pub fn find_latest_runtime_log(
        &self,
        project_instance_id: Uuid,
        service_key: &str,
    ) -> Result<Option<StoredRuntimeLog>, RegistryError> {
        if !self.runtime_schema_available()? {
            return Ok(None);
        }

        let project_instance_id = project_instance_id.to_string();
        if schema_version(&self.connection)? < 3 {
            let stored = self
                .connection
                .query_row(
                    "SELECT runtime_sessions.id, runtime_processes.log_path
                     FROM runtime_sessions
                     JOIN runtime_processes
                       ON runtime_processes.session_id = runtime_sessions.id
                     WHERE runtime_sessions.project_instance_id = ?1
                       AND runtime_processes.service_key = ?2
                     ORDER BY runtime_sessions.rowid DESC
                     LIMIT 1",
                    params![project_instance_id, service_key],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            return stored
                .map(|(session_id, log_path)| {
                    Ok(StoredRuntimeLog {
                        session_id: Uuid::parse_str(&session_id)?,
                        kind: RuntimeLogKind::Process,
                        log_path,
                    })
                })
                .transpose();
        }

        let stored = self
            .connection
            .query_row(
                "SELECT session_id, kind, log_path
                 FROM (
                     SELECT runtime_sessions.rowid AS session_rowid,
                            runtime_sessions.id AS session_id,
                            0 AS kind,
                            runtime_processes.log_path AS log_path
                     FROM runtime_sessions
                     JOIN runtime_processes
                       ON runtime_processes.session_id = runtime_sessions.id
                     WHERE runtime_sessions.project_instance_id = ?1
                       AND runtime_processes.service_key = ?2

                     UNION ALL

                     SELECT runtime_sessions.rowid AS session_rowid,
                            runtime_sessions.id AS session_id,
                            1 AS kind,
                            runtime_adapters.log_path AS log_path
                     FROM runtime_sessions
                     JOIN runtime_adapters
                       ON runtime_adapters.session_id = runtime_sessions.id
                     JOIN runtime_adapter_services
                       ON runtime_adapter_services.session_id = runtime_sessions.id
                     WHERE runtime_sessions.project_instance_id = ?1
                       AND runtime_adapter_services.service_key = ?2
                 )
                 ORDER BY session_rowid DESC
                 LIMIT 1",
                params![project_instance_id, service_key],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        stored
            .map(|(session_id, kind, log_path)| {
                let kind = match kind {
                    0 => RuntimeLogKind::Process,
                    1 => RuntimeLogKind::Adapter,
                    _ => unreachable!("runtime log kind is selected from SQL literals"),
                };
                Ok(StoredRuntimeLog {
                    session_id: Uuid::parse_str(&session_id)?,
                    kind,
                    log_path,
                })
            })
            .transpose()
    }

    pub fn terminal_runtime_sessions_to_prune(
        &self,
        project_instance_id: Uuid,
        retained_sessions: u32,
    ) -> Result<Vec<Uuid>, RegistryError> {
        if !self.runtime_schema_available()? {
            return Ok(Vec::new());
        }
        let mut statement = self.connection.prepare(
            "SELECT id
             FROM runtime_sessions
             WHERE project_instance_id = ?1
               AND status IN ('stopped', 'failed')
             ORDER BY rowid DESC
             LIMIT -1 OFFSET ?2",
        )?;
        let rows = statement
            .query_map(
                params![
                    project_instance_id.to_string(),
                    i64::from(retained_sessions)
                ],
                |row| row.get::<_, String>(0),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|session_id| Uuid::parse_str(&session_id).map_err(RegistryError::from))
            .collect()
    }

    pub fn delete_terminal_runtime_sessions(
        &mut self,
        project_instance_id: Uuid,
        session_ids: &[Uuid],
    ) -> Result<usize, RegistryError> {
        if session_ids.is_empty() {
            return Ok(0);
        }
        let project_instance_id = project_instance_id.to_string();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut deleted = 0;
        for session_id in session_ids {
            let session_id = session_id.to_string();
            let eligible = transaction.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM runtime_sessions
                    WHERE id = ?1
                      AND project_instance_id = ?2
                      AND status IN ('stopped', 'failed')
                )",
                params![session_id, project_instance_id],
                |row| row.get::<_, bool>(0),
            )?;
            if !eligible {
                continue;
            }
            transaction.execute(
                "DELETE FROM runtime_adapter_services WHERE session_id = ?1",
                [&session_id],
            )?;
            transaction.execute(
                "DELETE FROM runtime_adapters WHERE session_id = ?1",
                [&session_id],
            )?;
            transaction.execute(
                "DELETE FROM runtime_processes WHERE session_id = ?1",
                [&session_id],
            )?;
            deleted += transaction.execute(
                "DELETE FROM runtime_sessions
                 WHERE id = ?1
                   AND project_instance_id = ?2
                   AND status IN ('stopped', 'failed')",
                params![session_id, project_instance_id],
            )?;
        }
        transaction.commit()?;
        Ok(deleted)
    }

    pub fn claim_runtime_session(
        &mut self,
        project_instance_id: Uuid,
        launcher_pid: u32,
        launcher_process_start: &str,
        service_key: &str,
        protocol: &str,
        port: u16,
    ) -> Result<RuntimeClaim, RegistryError> {
        let project_instance_id_text = project_instance_id.to_string();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let allocation_matches = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM allocations
                WHERE project_instance_id = ?1
                  AND service_key = ?2
                  AND protocol = ?3
                  AND port = ?4
            )",
            params![project_instance_id_text, service_key, protocol, port],
            |row| row.get::<_, bool>(0),
        )?;
        if !allocation_matches {
            return Err(RegistryError::RuntimeAllocationChanged {
                project_instance_id: project_instance_id_text,
                service_key: service_key.to_owned(),
                protocol: protocol.to_owned(),
                port,
            });
        }
        let existing = active_runtime_id(&transaction, &project_instance_id_text)?;
        let (session_id, changed) = match existing {
            Some(session_id) => (session_id, false),
            None => {
                let session_id = Uuid::new_v4().to_string();
                transaction.execute(
                    "INSERT INTO runtime_sessions
                        (id, project_instance_id, status, launcher_pid, launcher_process_start)
                     VALUES (?1, ?2, 'starting', ?3, ?4)",
                    params![
                        session_id,
                        project_instance_id_text,
                        launcher_pid,
                        launcher_process_start
                    ],
                )?;
                (session_id, true)
            }
        };
        transaction.commit()?;

        let session = find_runtime_session(&self.connection, &session_id)?
            .ok_or_else(|| RegistryError::UnknownRuntimeSession(session_id.clone()))?;
        Ok(RuntimeClaim { session, changed })
    }

    pub fn replace_runtime_session_if_current(
        &mut self,
        predecessor_session_id: Uuid,
        project_instance_id: Uuid,
        owner: RuntimeOwnerRef<'_>,
        service_key: &str,
        protocol: &str,
        port: u16,
    ) -> Result<Option<RuntimeClaim>, RegistryError> {
        let predecessor_session_id = predecessor_session_id.to_string();
        let project_instance_id_text = project_instance_id.to_string();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let allocation_matches = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1
                FROM allocations
                WHERE project_instance_id = ?1
                  AND service_key = ?2
                  AND protocol = ?3
                  AND port = ?4
            )",
            params![project_instance_id_text, service_key, protocol, port],
            |row| row.get::<_, bool>(0),
        )?;
        if !allocation_matches {
            return Err(RegistryError::RuntimeAllocationChanged {
                project_instance_id: project_instance_id_text,
                service_key: service_key.to_owned(),
                protocol: protocol.to_owned(),
                port,
            });
        }
        if active_runtime_id(&transaction, &project_instance_id_text)?.as_deref()
            != Some(predecessor_session_id.as_str())
        {
            transaction.commit()?;
            return Ok(None);
        }
        let (predecessor_status, predecessor_owner_pid, predecessor_owner_start) = transaction
            .query_row(
                "SELECT status, launcher_pid, launcher_process_start
             FROM runtime_sessions WHERE id = ?1",
                [&predecessor_session_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )?;
        if predecessor_status != "stopping" {
            return Err(RegistryError::InvalidRuntimeStatus(predecessor_status));
        }
        if predecessor_owner_pid != i64::from(owner.pid)
            || predecessor_owner_start.as_deref() != Some(owner.process_start)
        {
            transaction.commit()?;
            return Ok(None);
        }

        let successor_session_id = Uuid::new_v4().to_string();
        let stopped = transaction.execute(
            "UPDATE runtime_sessions
             SET status = 'stopped', ended_at = CURRENT_TIMESTAMP
             WHERE id = ?1
               AND status = 'stopping'
               AND launcher_pid = ?2
               AND launcher_process_start = ?3",
            params![predecessor_session_id, owner.pid, owner.process_start],
        )?;
        if stopped == 0 {
            transaction.commit()?;
            return Ok(None);
        }
        transaction.execute(
            "INSERT INTO runtime_sessions
                (id, project_instance_id, status, launcher_pid, launcher_process_start)
             VALUES (?1, ?2, 'starting', ?3, ?4)",
            params![
                successor_session_id,
                project_instance_id_text,
                owner.pid,
                owner.process_start
            ],
        )?;
        transaction.commit()?;

        let session = find_runtime_session(&self.connection, &successor_session_id)?
            .ok_or_else(|| RegistryError::UnknownRuntimeSession(successor_session_id.clone()))?;
        Ok(Some(RuntimeClaim {
            session,
            changed: true,
        }))
    }

    pub fn record_runtime_process(
        &mut self,
        session_id: Uuid,
        process: &StoredRuntimeProcess,
    ) -> Result<(), RegistryError> {
        let session_id = session_id.to_string();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let status = transaction
            .query_row(
                "SELECT status FROM runtime_sessions WHERE id = ?1",
                [&session_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        match status.as_deref() {
            Some("starting") => {}
            Some(status) => {
                return Err(RegistryError::RuntimeSessionNotStarting {
                    session_id,
                    status: status.to_owned(),
                });
            }
            None => return Err(RegistryError::UnknownRuntimeSession(session_id)),
        }

        transaction.execute(
            "INSERT INTO runtime_processes
                (session_id, service_key, pid, process_group_id, process_start,
                 executable, log_path)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                session_id,
                process.service_key,
                process.pid,
                process.process_group_id,
                process.process_start,
                process.executable,
                process.log_path,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn clear_runtime_process(
        &mut self,
        session_id: Uuid,
        service_key: &str,
    ) -> Result<bool, RegistryError> {
        let changed = self.connection.execute(
            "DELETE FROM runtime_processes
             WHERE session_id = ?1 AND service_key = ?2",
            params![session_id.to_string(), service_key],
        )?;
        Ok(changed != 0)
    }

    pub fn record_runtime_adapter(
        &mut self,
        session_id: Uuid,
        adapter: &StoredRuntimeAdapter,
    ) -> Result<(), RegistryError> {
        let session_id = session_id.to_string();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let status = transaction
            .query_row(
                "SELECT status FROM runtime_sessions WHERE id = ?1",
                [&session_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        match status.as_deref() {
            Some("starting") => {}
            Some(status) => {
                return Err(RegistryError::RuntimeSessionNotStarting {
                    session_id,
                    status: status.to_owned(),
                });
            }
            None => return Err(RegistryError::UnknownRuntimeSession(session_id)),
        }

        transaction.execute(
            "INSERT INTO runtime_adapters
                (session_id, adapter_key, working_directory, runtime_project_id, log_path)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                session_id,
                adapter.adapter_key,
                adapter.working_directory,
                adapter.runtime_project_id,
                adapter.log_path,
            ],
        )?;
        for service in &adapter.services {
            transaction.execute(
                "INSERT INTO runtime_adapter_services
                    (session_id, service_key, protocol, port)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    session_id,
                    service.service_key,
                    service.protocol,
                    service.port,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn mark_runtime_ready(&mut self, session_id: Uuid) -> Result<bool, RegistryError> {
        let changed = self.connection.execute(
            "UPDATE runtime_sessions
             SET status = 'ready', ready_at = CURRENT_TIMESTAMP
             WHERE id = ?1 AND status = 'starting'",
            [session_id.to_string()],
        )?;
        Ok(changed != 0)
    }

    pub fn mark_runtime_failed(&mut self, session_id: Uuid) -> Result<bool, RegistryError> {
        let changed = self.connection.execute(
            "UPDATE runtime_sessions
             SET status = 'failed', ended_at = CURRENT_TIMESTAMP
             WHERE id = ?1 AND status IN ('starting', 'ready', 'stopping')",
            [session_id.to_string()],
        )?;
        Ok(changed != 0)
    }

    pub fn mark_runtime_start_failed(&mut self, session_id: Uuid) -> Result<bool, RegistryError> {
        let changed = self.connection.execute(
            "UPDATE runtime_sessions
             SET status = 'failed', ended_at = CURRENT_TIMESTAMP
             WHERE id = ?1 AND status = 'starting'",
            [session_id.to_string()],
        )?;
        Ok(changed != 0)
    }

    pub fn claim_runtime_stop(
        &mut self,
        project_instance_id: Uuid,
        transition_owner_pid: u32,
        transition_owner_process_start: &str,
    ) -> Result<Option<RuntimeClaim>, RegistryError> {
        self.claim_runtime_stop_inner(
            project_instance_id,
            None,
            false,
            transition_owner_pid,
            transition_owner_process_start,
        )
    }

    pub fn claim_runtime_stop_if_current(
        &mut self,
        project_instance_id: Uuid,
        session_id: Uuid,
        transition_owner_pid: u32,
        transition_owner_process_start: &str,
    ) -> Result<Option<RuntimeClaim>, RegistryError> {
        self.claim_runtime_stop_inner(
            project_instance_id,
            Some(session_id),
            false,
            transition_owner_pid,
            transition_owner_process_start,
        )
    }

    pub fn claim_abandoned_runtime_stop_if_current(
        &mut self,
        project_instance_id: Uuid,
        session_id: Uuid,
        transition_owner_pid: u32,
        transition_owner_process_start: &str,
    ) -> Result<Option<RuntimeClaim>, RegistryError> {
        self.claim_runtime_stop_inner(
            project_instance_id,
            Some(session_id),
            true,
            transition_owner_pid,
            transition_owner_process_start,
        )
    }

    fn claim_runtime_stop_inner(
        &mut self,
        project_instance_id: Uuid,
        expected_session_id: Option<Uuid>,
        allow_abandoned_adapter_start: bool,
        transition_owner_pid: u32,
        transition_owner_process_start: &str,
    ) -> Result<Option<RuntimeClaim>, RegistryError> {
        let project_instance_id_text = project_instance_id.to_string();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(session_id) = active_runtime_id(&transaction, &project_instance_id_text)? else {
            transaction.commit()?;
            return Ok(None);
        };
        if expected_session_id.is_some_and(|expected| expected.to_string() != session_id) {
            transaction.commit()?;
            return Ok(None);
        }
        let status = transaction.query_row(
            "SELECT status FROM runtime_sessions WHERE id = ?1",
            [&session_id],
            |row| row.get::<_, String>(0),
        )?;
        let changed = match status.as_str() {
            "ready" => {
                transaction.execute(
                    "UPDATE runtime_sessions
                     SET status = 'stopping',
                         launcher_pid = ?2,
                         launcher_process_start = ?3
                     WHERE id = ?1",
                    params![
                        session_id,
                        transition_owner_pid,
                        transition_owner_process_start
                    ],
                )?;
                true
            }
            "stopping" => false,
            "starting" => {
                let process_exists = transaction.query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM runtime_processes
                        WHERE session_id = ?1 AND service_key != 'supabase.startup'
                    )",
                    [&session_id],
                    |row| row.get::<_, bool>(0),
                )?;
                if !process_exists && !allow_abandoned_adapter_start {
                    return Err(RegistryError::RuntimeStillStarting(session_id));
                }
                transaction.execute(
                    "UPDATE runtime_sessions
                     SET status = 'stopping',
                         launcher_pid = ?2,
                         launcher_process_start = ?3
                     WHERE id = ?1",
                    params![
                        session_id,
                        transition_owner_pid,
                        transition_owner_process_start
                    ],
                )?;
                true
            }
            _ => return Err(RegistryError::InvalidRuntimeStatus(status)),
        };
        transaction.commit()?;
        let session = find_runtime_session(&self.connection, &session_id)?
            .ok_or_else(|| RegistryError::UnknownRuntimeSession(session_id.clone()))?;
        Ok(Some(RuntimeClaim { session, changed }))
    }

    pub fn take_over_runtime_stop_if_current(
        &mut self,
        project_instance_id: Uuid,
        session_id: Uuid,
        previous_owner_pid: u32,
        previous_owner_process_start: Option<&str>,
        transition_owner_pid: u32,
        transition_owner_process_start: &str,
    ) -> Result<Option<RuntimeClaim>, RegistryError> {
        let project_instance_id = project_instance_id.to_string();
        let session_id = session_id.to_string();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if active_runtime_id(&transaction, &project_instance_id)?.as_deref()
            != Some(session_id.as_str())
        {
            transaction.commit()?;
            return Ok(None);
        }
        let changed = transaction.execute(
            "UPDATE runtime_sessions
             SET launcher_pid = ?5,
                 launcher_process_start = ?6
             WHERE id = ?1
               AND project_instance_id = ?2
               AND status = 'stopping'
               AND launcher_pid = ?3
               AND launcher_process_start IS ?4",
            params![
                session_id,
                project_instance_id,
                previous_owner_pid,
                previous_owner_process_start,
                transition_owner_pid,
                transition_owner_process_start
            ],
        )?;
        if changed == 0 {
            transaction.commit()?;
            return Ok(None);
        }
        transaction.commit()?;
        let session = find_runtime_session(&self.connection, &session_id)?
            .ok_or_else(|| RegistryError::UnknownRuntimeSession(session_id.clone()))?;
        Ok(Some(RuntimeClaim {
            session,
            changed: true,
        }))
    }

    pub fn mark_runtime_stopped_if_owned(
        &mut self,
        session_id: Uuid,
        transition_owner_pid: u32,
        transition_owner_process_start: &str,
    ) -> Result<bool, RegistryError> {
        let changed = self.connection.execute(
            "UPDATE runtime_sessions
             SET status = 'stopped', ended_at = CURRENT_TIMESTAMP
             WHERE id = ?1
               AND status = 'stopping'
               AND launcher_pid = ?2
               AND launcher_process_start = ?3",
            params![
                session_id.to_string(),
                transition_owner_pid,
                transition_owner_process_start
            ],
        )?;
        Ok(changed != 0)
    }

    fn runtime_schema_available(&self) -> Result<bool, RegistryError> {
        let version = self.connection.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        Ok(version >= 2)
    }

    pub fn release_allocations(
        &mut self,
        project_instance_id: Uuid,
    ) -> Result<Vec<StoredAllocation>, RegistryError> {
        let project_instance_id = project_instance_id.to_string();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let instance_exists = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM project_instances WHERE id = ?1
            )",
            [&project_instance_id],
            |row| row.get::<_, bool>(0),
        )?;
        if !instance_exists {
            return Err(RegistryError::UnknownProjectInstance(project_instance_id));
        }

        ensure_runtime_inactive(&transaction, &project_instance_id)?;

        let allocations = {
            let mut statement = transaction.prepare(
                "SELECT service_key, protocol, port
                 FROM allocations
                 WHERE project_instance_id = ?1
                 ORDER BY service_key, protocol",
            )?;
            let rows = statement
                .query_map([&project_instance_id], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            let mut allocations = Vec::with_capacity(rows.len());
            for (service_key, protocol, port) in rows {
                allocations.push(StoredAllocation {
                    service_key,
                    protocol,
                    port: u16::try_from(port)
                        .map_err(|_| RegistryError::InvalidStoredPort(port))?,
                });
            }
            allocations
        };

        transaction.execute(
            "DELETE FROM allocations WHERE project_instance_id = ?1",
            [&project_instance_id],
        )?;
        transaction.commit()?;

        Ok(allocations)
    }

    pub fn reallocate_dynamic_tcp_allocations(
        &mut self,
        project_instance_id: Uuid,
        service_keys: &[String],
    ) -> Result<ReallocatedAllocationSet, RegistryError> {
        self.reallocate_dynamic_tcp_allocations_from(
            project_instance_id,
            service_keys,
            DEFAULT_PORT_START..=DEFAULT_PORT_END,
        )
    }

    fn reallocate_dynamic_tcp_allocations_from(
        &mut self,
        project_instance_id: Uuid,
        service_keys: &[String],
        candidates: impl IntoIterator<Item = u16>,
    ) -> Result<ReallocatedAllocationSet, RegistryError> {
        self.reallocate_dynamic_tcp_allocations_from_with_snapshot_hook(
            project_instance_id,
            service_keys,
            candidates,
            || {},
        )
    }

    fn reallocate_dynamic_tcp_allocations_from_with_snapshot_hook(
        &mut self,
        project_instance_id: Uuid,
        service_keys: &[String],
        candidates: impl IntoIterator<Item = u16>,
        after_initial_snapshot: impl FnOnce(),
    ) -> Result<ReallocatedAllocationSet, RegistryError> {
        let service_keys = normalized_service_keys(service_keys)?;
        let candidates = candidates
            .into_iter()
            .filter(|port| *port != 0)
            .collect::<Vec<_>>();
        let project_instance_id = project_instance_id.to_string();
        let mut after_initial_snapshot = Some(after_initial_snapshot);

        loop {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure_project_instance_exists(&transaction, &project_instance_id)?;
            ensure_runtime_inactive(&transaction, &project_instance_id)?;
            let previous_allocations = stored_tcp_allocations(&transaction, &project_instance_id)?;
            transaction.commit()?;
            if let Some(after_initial_snapshot) = after_initial_snapshot.take() {
                after_initial_snapshot();
            }

            let previous = allocation_map(&previous_allocations);
            let previous_ports = previous.values().copied().collect::<BTreeSet<_>>();
            let mut candidate_ports = candidates.iter().copied();
            let mut prepared = Vec::with_capacity(service_keys.len());
            for service_key in &service_keys {
                let reservation = loop {
                    let Some(port) = candidate_ports.next() else {
                        return Err(RegistryError::NoPortsAvailable);
                    };
                    if previous_ports.contains(&port)
                        || tcp_port_is_managed(&self.connection, port)?
                    {
                        continue;
                    }
                    if let Some(reservation) =
                        classify_candidate_reservation(port, reserve_tcp_port(port))?
                    {
                        break (service_key.clone(), port, reservation);
                    }
                };
                prepared.push(reservation);
            }

            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure_project_instance_exists(&transaction, &project_instance_id)?;
            ensure_runtime_inactive(&transaction, &project_instance_id)?;
            let current_allocations = stored_tcp_allocations(&transaction, &project_instance_id)?;
            let current = allocation_map(&current_allocations);
            if current != previous {
                if is_complete_reallocation(&previous, &current, &service_keys) {
                    drop(prepared);
                    transaction.commit()?;
                    return Ok(ReallocatedAllocationSet {
                        previous_allocations: current_allocations.clone(),
                        allocations: current_allocations,
                        changed: false,
                    });
                }
                transaction.rollback()?;
                drop(prepared);
                continue;
            }

            let candidate_conflict =
                prepared.iter().try_fold(false, |conflict, (_, port, _)| {
                    Ok::<_, RegistryError>(conflict || tcp_port_is_managed(&transaction, *port)?)
                })?;
            if candidate_conflict {
                transaction.rollback()?;
                drop(prepared);
                continue;
            }

            transaction.execute(
                "DELETE FROM allocations
                 WHERE project_instance_id = ?1 AND protocol = 'tcp'",
                [&project_instance_id],
            )?;
            for (service_key, port, _) in &prepared {
                transaction.execute(
                    "INSERT INTO allocations
                        (project_instance_id, service_key, protocol, port)
                     VALUES (?1, ?2, 'tcp', ?3)",
                    params![project_instance_id, service_key, port],
                )?;
            }
            let allocations = prepared
                .iter()
                .map(|(service_key, port, _)| StoredAllocation {
                    service_key: service_key.clone(),
                    protocol: "tcp".to_owned(),
                    port: *port,
                })
                .collect::<Vec<_>>();

            transaction.commit()?;
            drop(prepared);
            return Ok(ReallocatedAllocationSet {
                previous_allocations,
                allocations,
                changed: true,
            });
        }
    }

    pub fn ensure_project_instance(
        &mut self,
        location: &GitLocation,
    ) -> Result<EnsuredIdentity, RegistryError> {
        let common_dir = path_text(location.git_common_dir())?;
        let worktree_git_dir = path_text(location.worktree_git_dir())?;
        let worktree_root = path_text(location.worktree_root())?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut changed = false;

        let project_id = transaction
            .query_row(
                "SELECT id FROM projects WHERE git_common_dir = ?1",
                [common_dir],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let project_id = match project_id {
            Some(id) => id,
            None => {
                changed = true;
                let id = Uuid::new_v4().to_string();
                transaction.execute(
                    "INSERT INTO projects (id, git_common_dir) VALUES (?1, ?2)",
                    params![id, common_dir],
                )?;
                id
            }
        };

        let instance = transaction
            .query_row(
                "SELECT id, project_id, worktree_root
                 FROM project_instances
                 WHERE worktree_git_dir = ?1",
                [worktree_git_dir],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let instance_id = match instance {
            Some((id, stored_project_id, stored_root)) => {
                if stored_project_id != project_id || stored_root != worktree_root {
                    return Err(RegistryError::IdentityConflict);
                }
                id
            }
            None => {
                changed = true;
                let id = Uuid::new_v4().to_string();
                transaction.execute(
                    "INSERT INTO project_instances
                        (id, project_id, worktree_git_dir, worktree_root)
                     VALUES (?1, ?2, ?3, ?4)",
                    params![id, project_id, worktree_git_dir, worktree_root],
                )?;
                id
            }
        };

        transaction.commit()?;

        Ok(EnsuredIdentity {
            project_id: Uuid::parse_str(&project_id)?,
            project_instance_id: Uuid::parse_str(&instance_id)?,
            changed,
        })
    }

    pub fn ensure_dynamic_tcp_allocation(
        &mut self,
        project_instance_id: Uuid,
        service_key: &str,
    ) -> Result<EnsuredAllocation, RegistryError> {
        self.ensure_dynamic_tcp_allocation_from(
            project_instance_id,
            service_key,
            DEFAULT_PORT_START..=DEFAULT_PORT_END,
        )
    }

    pub fn ensure_dynamic_tcp_allocations(
        &mut self,
        project_instance_id: Uuid,
        service_keys: &[String],
    ) -> Result<Vec<EnsuredAllocation>, RegistryError> {
        self.ensure_dynamic_tcp_allocations_allowing(
            project_instance_id,
            service_keys,
            &BTreeSet::new(),
        )
    }

    pub(crate) fn ensure_dynamic_tcp_allocations_allowing(
        &mut self,
        project_instance_id: Uuid,
        service_keys: &[String],
        allowed_occupied: &BTreeSet<(String, u16)>,
    ) -> Result<Vec<EnsuredAllocation>, RegistryError> {
        self.ensure_dynamic_tcp_allocations_from(
            project_instance_id,
            service_keys,
            DEFAULT_PORT_START..=DEFAULT_PORT_END,
            allowed_occupied,
        )
    }

    fn ensure_dynamic_tcp_allocation_from(
        &mut self,
        project_instance_id: Uuid,
        service_key: &str,
        candidates: impl IntoIterator<Item = u16>,
    ) -> Result<EnsuredAllocation, RegistryError> {
        let mut allocations = self.ensure_dynamic_tcp_allocations_from(
            project_instance_id,
            &[service_key.to_owned()],
            candidates,
            &BTreeSet::new(),
        )?;
        allocations.pop().ok_or(RegistryError::NoPortsAvailable)
    }

    fn ensure_dynamic_tcp_allocations_from(
        &mut self,
        project_instance_id: Uuid,
        service_keys: &[String],
        candidates: impl IntoIterator<Item = u16>,
        allowed_occupied: &BTreeSet<(String, u16)>,
    ) -> Result<Vec<EnsuredAllocation>, RegistryError> {
        let service_keys = normalized_service_keys(service_keys)?;
        let candidates = candidates
            .into_iter()
            .filter(|port| *port != 0)
            .collect::<Vec<_>>();
        let project_instance_id = project_instance_id.to_string();

        loop {
            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure_project_instance_exists(&transaction, &project_instance_id)?;

            let mut established = BTreeMap::new();
            let mut missing = Vec::new();
            let mut established_reservations = Vec::new();
            for service_key in &service_keys {
                if let Some(port) =
                    allocation_port(&transaction, &project_instance_id, service_key)?
                {
                    if !allowed_occupied.contains(&(service_key.clone(), port)) {
                        established_reservations
                            .push(reserve_established_tcp_port(service_key, port)?);
                    }
                    established.insert(service_key.clone(), port);
                } else {
                    missing.push(service_key.clone());
                }
            }

            // Releasing established probes before commit prevents the next serialized
            // Duckflap caller from mistaking these short-lived reservations for listeners.
            drop(established_reservations);
            transaction.commit()?;

            if missing.is_empty() {
                return Ok(established
                    .into_iter()
                    .map(|(service_key, port)| EnsuredAllocation {
                        service_key,
                        protocol: "tcp",
                        port,
                        changed: false,
                    })
                    .collect());
            }

            let mut candidate_ports = candidates.iter().copied();
            let mut prepared = Vec::with_capacity(missing.len());
            for service_key in &missing {
                let reservation = loop {
                    let Some(port) = candidate_ports.next() else {
                        return Err(RegistryError::NoPortsAvailable);
                    };
                    if tcp_port_is_managed(&self.connection, port)? {
                        continue;
                    }
                    if let Some(reservation) =
                        classify_candidate_reservation(port, reserve_tcp_port(port))?
                    {
                        break (service_key.clone(), port, reservation);
                    }
                };
                prepared.push(reservation);
            }

            let transaction = self
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure_project_instance_exists(&transaction, &project_instance_id)?;

            let mut current_allocations = BTreeMap::new();
            let mut state_changed = false;
            for service_key in &service_keys {
                let current = allocation_port(&transaction, &project_instance_id, service_key)?;
                if let Some(port) = current {
                    current_allocations.insert(service_key.clone(), port);
                }
                if current != established.get(service_key).copied() {
                    state_changed = true;
                }
            }
            if state_changed
                && current_allocations.len() == service_keys.len()
                && established
                    .iter()
                    .all(|(service_key, port)| current_allocations.get(service_key) == Some(port))
            {
                // Another complete batch won after the initial read. Accept its committed
                // set without racing its short-lived post-commit socket reservations.
                drop(prepared);
                transaction.commit()?;
                return Ok(current_allocations
                    .into_iter()
                    .map(|(service_key, port)| EnsuredAllocation {
                        service_key,
                        protocol: "tcp",
                        port,
                        changed: false,
                    })
                    .collect());
            }
            if !state_changed {
                for (_, port, _) in &prepared {
                    if tcp_port_is_managed(&transaction, *port)? {
                        state_changed = true;
                        break;
                    }
                }
            }
            if state_changed {
                transaction.rollback()?;
                drop(prepared);
                continue;
            }

            for (service_key, port, _) in &prepared {
                transaction.execute(
                    "INSERT INTO allocations
                        (project_instance_id, service_key, protocol, port)
                     VALUES (?1, ?2, 'tcp', ?3)",
                    params![project_instance_id, service_key, port],
                )?;
            }

            let mut allocations = established
                .into_iter()
                .map(|(service_key, port)| EnsuredAllocation {
                    service_key,
                    protocol: "tcp",
                    port,
                    changed: false,
                })
                .chain(
                    prepared
                        .iter()
                        .map(|(service_key, port, _)| EnsuredAllocation {
                            service_key: service_key.clone(),
                            protocol: "tcp",
                            port: *port,
                            changed: true,
                        }),
                )
                .collect::<Vec<_>>();
            allocations.sort_by(|left, right| left.service_key.cmp(&right.service_key));

            transaction.commit()?;
            drop(prepared);
            return Ok(allocations);
        }
    }
}

fn normalized_service_keys(service_keys: &[String]) -> Result<Vec<String>, RegistryError> {
    let mut normalized = service_keys.to_vec();
    normalized.sort();
    for service_key in &normalized {
        if service_key.is_empty() {
            return Err(RegistryError::InvalidServiceKey);
        }
    }
    if let Some(duplicate) = normalized
        .windows(2)
        .find(|pair| pair[0] == pair[1])
        .map(|pair| pair[0].clone())
    {
        return Err(RegistryError::DuplicateServiceKey(duplicate));
    }
    Ok(normalized)
}

fn ensure_project_instance_exists(
    connection: &Connection,
    project_instance_id: &str,
) -> Result<(), RegistryError> {
    let exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM project_instances WHERE id = ?1)",
        [project_instance_id],
        |row| row.get::<_, bool>(0),
    )?;
    if exists {
        Ok(())
    } else {
        Err(RegistryError::UnknownProjectInstance(
            project_instance_id.to_owned(),
        ))
    }
}

fn allocation_port(
    connection: &Connection,
    project_instance_id: &str,
    service_key: &str,
) -> Result<Option<u16>, RegistryError> {
    connection
        .query_row(
            "SELECT port
             FROM allocations
             WHERE project_instance_id = ?1
               AND service_key = ?2
               AND protocol = 'tcp'",
            params![project_instance_id, service_key],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(|port| u16::try_from(port).map_err(|_| RegistryError::InvalidStoredPort(port)))
        .transpose()
}

fn stored_tcp_allocations(
    connection: &Connection,
    project_instance_id: &str,
) -> Result<Vec<StoredAllocation>, RegistryError> {
    let mut statement = connection.prepare(
        "SELECT service_key, port
         FROM allocations
         WHERE project_instance_id = ?1 AND protocol = 'tcp'
         ORDER BY service_key",
    )?;
    statement
        .query_map([project_instance_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .map(|row| {
            let (service_key, port) = row?;
            Ok(StoredAllocation {
                service_key,
                protocol: "tcp".to_owned(),
                port: stored_port(port)?,
            })
        })
        .collect()
}

fn allocation_map(allocations: &[StoredAllocation]) -> BTreeMap<String, u16> {
    allocations
        .iter()
        .map(|allocation| (allocation.service_key.clone(), allocation.port))
        .collect()
}

fn is_complete_reallocation(
    previous: &BTreeMap<String, u16>,
    current: &BTreeMap<String, u16>,
    service_keys: &[String],
) -> bool {
    let previous_ports = previous.values().copied().collect::<BTreeSet<_>>();
    current.len() == service_keys.len()
        && service_keys
            .iter()
            .all(|service_key| current.contains_key(service_key))
        && current
            .values()
            .all(|current_port| !previous_ports.contains(current_port))
}

fn tcp_port_is_managed(connection: &Connection, port: u16) -> Result<bool, RegistryError> {
    connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM allocations
                WHERE protocol = 'tcp' AND port = ?1
            )",
            [port],
            |row| row.get::<_, bool>(0),
        )
        .map_err(RegistryError::from)
}

fn active_runtime_id(
    connection: &Connection,
    project_instance_id: &str,
) -> Result<Option<String>, RegistryError> {
    connection
        .query_row(
            "SELECT id
             FROM runtime_sessions
             WHERE project_instance_id = ?1
               AND status IN ('starting', 'ready', 'stopping')
             ORDER BY rowid DESC
             LIMIT 1",
            [project_instance_id],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(RegistryError::from)
}

fn ensure_runtime_inactive(
    connection: &Connection,
    project_instance_id: &str,
) -> Result<(), RegistryError> {
    if let Some(session_id) = active_runtime_id(connection, project_instance_id)? {
        Err(RegistryError::RuntimeActive {
            project_instance_id: project_instance_id.to_owned(),
            session_id,
        })
    } else {
        Ok(())
    }
}

fn find_active_runtime(
    connection: &Connection,
    project_instance_id: Uuid,
) -> Result<Option<StoredRuntimeSession>, RegistryError> {
    let Some(session_id) = active_runtime_id(connection, &project_instance_id.to_string())? else {
        return Ok(None);
    };
    find_runtime_session(connection, &session_id)
}

fn find_latest_runtime(
    connection: &Connection,
    project_instance_id: Uuid,
) -> Result<Option<StoredRuntimeSession>, RegistryError> {
    let session_id = connection
        .query_row(
            "SELECT id
             FROM runtime_sessions
             WHERE project_instance_id = ?1
             ORDER BY rowid DESC
             LIMIT 1",
            [project_instance_id.to_string()],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    let Some(session_id) = session_id else {
        return Ok(None);
    };
    find_runtime_session(connection, &session_id)
}

fn find_runtime_session(
    connection: &Connection,
    session_id: &str,
) -> Result<Option<StoredRuntimeSession>, RegistryError> {
    let owner_identity_available = schema_version(connection)? >= 4;
    let session_query = if owner_identity_available {
        "SELECT id, project_instance_id, status, launcher_pid, launcher_process_start
         FROM runtime_sessions
         WHERE id = ?1"
    } else {
        "SELECT id, project_instance_id, status, launcher_pid, NULL
         FROM runtime_sessions
         WHERE id = ?1"
    };
    let session = connection
        .query_row(session_query, [session_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })
        .optional()?;
    let Some((id, project_instance_id, status, launcher_pid, launcher_process_start)) = session
    else {
        return Ok(None);
    };
    let process = find_runtime_process(connection, &id, "web")?;
    let adapter_startup = find_runtime_process(connection, &id, "supabase.startup")?;
    let adapter = if schema_version(connection)? >= 3 {
        let adapter = connection
            .query_row(
                "SELECT adapter_key, working_directory, runtime_project_id, log_path
             FROM runtime_adapters
             WHERE session_id = ?1
             ",
                [&id],
                |row| {
                    Ok(StoredRuntimeAdapter {
                        adapter_key: row.get(0)?,
                        working_directory: row.get(1)?,
                        runtime_project_id: row.get(2)?,
                        log_path: row.get(3)?,
                        services: Vec::new(),
                    })
                },
            )
            .optional()?;
        adapter
            .map(|mut adapter| {
                let mut statement = connection.prepare(
                    "SELECT service_key, protocol, port
                     FROM runtime_adapter_services
                     WHERE session_id = ?1
                     ORDER BY service_key, protocol",
                )?;
                adapter.services = statement
                    .query_map([&id], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })?
                    .map(|row| {
                        let (service_key, protocol, port) = row?;
                        Ok(StoredRuntimeService {
                            service_key,
                            protocol,
                            port: stored_port(port)?,
                        })
                    })
                    .collect::<Result<Vec<_>, RegistryError>>()?;
                Ok::<StoredRuntimeAdapter, RegistryError>(adapter)
            })
            .transpose()?
    } else {
        None
    };

    Ok(Some(StoredRuntimeSession {
        id: Uuid::parse_str(&id)?,
        project_instance_id: Uuid::parse_str(&project_instance_id)?,
        status,
        launcher_pid: stored_pid(launcher_pid)?,
        launcher_process_start,
        process,
        adapter_startup,
        adapter,
    }))
}

fn find_runtime_process(
    connection: &Connection,
    session_id: &str,
    service_key: &str,
) -> Result<Option<StoredRuntimeProcess>, RegistryError> {
    let process = connection
        .query_row(
            "SELECT service_key, pid, process_group_id, process_start, executable, log_path
             FROM runtime_processes
             WHERE session_id = ?1 AND service_key = ?2",
            params![session_id, service_key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                ))
            },
        )
        .optional()?;
    process
        .map(
            |(service_key, pid, process_group_id, process_start, executable, log_path)| {
                Ok(StoredRuntimeProcess {
                    service_key,
                    pid: stored_pid(pid)?,
                    process_group_id: stored_pid(process_group_id)?,
                    process_start,
                    executable,
                    log_path,
                })
            },
        )
        .transpose()
}

fn stored_pid(pid: i64) -> Result<u32, RegistryError> {
    u32::try_from(pid).map_err(|_| RegistryError::InvalidStoredProcessId(pid))
}

fn stored_port(port: i64) -> Result<u16, RegistryError> {
    u16::try_from(port).map_err(|_| RegistryError::InvalidStoredPort(port))
}

fn schema_version(connection: &Connection) -> Result<i64, RegistryError> {
    connection
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
            [],
            |row| row.get(0),
        )
        .map_err(RegistryError::from)
}

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("failed to access Duckflap state: {0}")]
    Io(#[from] std::io::Error),

    #[error("registry operation failed: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("registry contains an invalid UUID: {0}")]
    InvalidUuid(#[from] uuid::Error),

    #[error("path is not valid UTF-8: {0:?}")]
    NonUtf8Path(std::path::PathBuf),

    #[error("registry schema version {found} is newer than supported version {supported}")]
    DatabaseTooNew { found: i64, supported: i64 },

    #[error("the stored project instance does not match the discovered Git location")]
    IdentityConflict,

    #[error("service key must not be empty")]
    InvalidServiceKey,

    #[error("service key appears more than once in an allocation batch: {0}")]
    DuplicateServiceKey(String),

    #[error("project instance {0} does not exist")]
    UnknownProjectInstance(String),

    #[error("registry contains invalid TCP port {0}")]
    InvalidStoredPort(i64),

    #[error("registry contains invalid process ID {0}")]
    InvalidStoredProcessId(i64),

    #[error("runtime session {0} does not exist")]
    UnknownRuntimeSession(String),

    #[error(
        "the {protocol} allocation for service {service_key} on port {port} changed before runtime startup for project instance {project_instance_id}"
    )]
    RuntimeAllocationChanged {
        project_instance_id: String,
        service_key: String,
        protocol: String,
        port: u16,
    },

    #[error("runtime session {session_id} is {status}, not starting")]
    RuntimeSessionNotStarting { session_id: String, status: String },

    #[error("runtime session {0} is still starting")]
    RuntimeStillStarting(String),

    #[error(
        "project instance {project_instance_id} has active runtime session {session_id}; stop it before changing allocations"
    )]
    RuntimeActive {
        project_instance_id: String,
        session_id: String,
    },

    #[error("registry contains invalid runtime status {0}")]
    InvalidRuntimeStatus(String),

    #[error("established TCP port {port} for service {service_key} is occupied: {source}")]
    EstablishedPortOccupied {
        service_key: String,
        port: u16,
        source: std::io::Error,
    },

    #[error("failed to probe TCP port {port}: {source}")]
    PortProbeFailed { port: u16, source: std::io::Error },

    #[error("no TCP ports are available in the candidate range")]
    NoPortsAvailable,
}

fn apply_migrations(connection: &mut Connection) -> Result<(), RegistryError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY NOT NULL,
            applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );",
    )?;

    let current = transaction.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    let supported = MIGRATIONS.last().map_or(0, |(version, _)| *version);
    if current > supported {
        return Err(RegistryError::DatabaseTooNew {
            found: current,
            supported,
        });
    }

    for (version, sql) in MIGRATIONS.iter().filter(|(version, _)| *version > current) {
        transaction.execute_batch(sql)?;
        transaction.execute(
            "INSERT INTO schema_migrations (version) VALUES (?1)",
            [version],
        )?;
    }

    transaction.commit()?;
    Ok(())
}

fn path_text(path: &Path) -> Result<&str, RegistryError> {
    path.to_str()
        .ok_or_else(|| RegistryError::NonUtf8Path(path.to_path_buf()))
}

fn reserve_tcp_port(port: u16) -> std::io::Result<TcpListener> {
    let loopback = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))?;
    drop(loopback);

    TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
}

fn reserve_established_tcp_port(
    service_key: &str,
    port: u16,
) -> Result<TcpListener, RegistryError> {
    let reservation = match reserve_tcp_port(port) {
        Err(source) if source.kind() == std::io::ErrorKind::AddrInUse => {
            std::thread::sleep(Duration::from_millis(10));
            reserve_tcp_port(port)
        }
        reservation => reservation,
    };
    reservation.map_err(|source| {
        if source.kind() == std::io::ErrorKind::AddrInUse {
            RegistryError::EstablishedPortOccupied {
                service_key: service_key.to_owned(),
                port,
                source,
            }
        } else {
            RegistryError::PortProbeFailed { port, source }
        }
    })
}

fn classify_candidate_reservation<T>(
    port: u16,
    reservation: std::io::Result<T>,
) -> Result<Option<T>, RegistryError> {
    match reservation {
        Ok(reservation) => Ok(Some(reservation)),
        Err(source) if source.kind() == std::io::ErrorKind::AddrInUse => Ok(None),
        Err(source) => Err(RegistryError::PortProbeFailed { port, source }),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        fs,
        net::{Ipv4Addr, SocketAddrV4, TcpListener},
        path::Path,
        process::Command,
        sync::{
            Arc, Barrier,
            atomic::{AtomicU16, Ordering},
        },
        thread,
    };

    use rusqlite::{Connection, params};
    use tempfile::tempdir;
    use uuid::Uuid;

    use crate::{identity::GitLocation, state::StatePaths};

    use super::{
        EnsuredAllocation, Registry, RegistryError, RuntimeOwnerRef, StoredAllocation,
        StoredRuntimeAdapter, StoredRuntimeProcess, StoredRuntimeService,
        classify_candidate_reservation, find_runtime_session,
    };

    static NEXT_TEST_PORT: AtomicU16 = AtomicU16::new(10_000);

    #[test]
    fn candidate_probe_only_skips_address_conflicts() {
        let occupied = classify_candidate_reservation::<()>(
            20_000,
            Err(std::io::Error::from(std::io::ErrorKind::AddrInUse)),
        )
        .expect("classify occupied port");
        assert!(occupied.is_none());

        let error = classify_candidate_reservation::<()>(
            20_000,
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        )
        .expect_err("preserve unexpected probe error");
        assert!(matches!(
            error,
            RegistryError::PortProbeFailed { port: 20_000, .. }
        ));
    }

    #[test]
    fn migrations_create_foundation_and_runtime_tables() {
        let temp = tempdir().expect("create temp dir");
        let paths = StatePaths::from_root(temp.path().join("state"));
        drop(Registry::open_mutating(&paths).expect("open registry"));
        let connection = Connection::open(paths.registry()).expect("reopen registry");
        let mut statement = connection
            .prepare(
                "SELECT name FROM sqlite_schema
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
                 ORDER BY name",
            )
            .expect("prepare table query");
        let tables = statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query tables")
            .collect::<Result<BTreeSet<_>, _>>()
            .expect("read tables");

        assert_eq!(
            tables,
            BTreeSet::from([
                "allocations".to_owned(),
                "project_instances".to_owned(),
                "projects".to_owned(),
                "runtime_adapters".to_owned(),
                "runtime_adapter_services".to_owned(),
                "runtime_processes".to_owned(),
                "runtime_sessions".to_owned(),
                "schema_migrations".to_owned(),
            ])
        );
        assert_eq!(
            connection
                .query_row("SELECT MAX(version) FROM schema_migrations", [], |row| row
                    .get::<_, i64>(
                    0
                ),)
                .expect("read latest migration"),
            4
        );
        let mut columns = connection
            .prepare("PRAGMA table_info(runtime_sessions)")
            .expect("prepare runtime column query");
        let columns = columns
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query runtime columns")
            .collect::<Result<BTreeSet<_>, _>>()
            .expect("read runtime columns");
        assert!(columns.contains("launcher_process_start"));
    }

    #[test]
    fn observational_open_accepts_a_pre_runtime_registry() {
        let temp = tempdir().expect("create temp dir");
        let paths = StatePaths::from_root(temp.path().join("state"));
        fs::create_dir_all(paths.root()).expect("create state directory");
        let connection = Connection::open(paths.registry()).expect("create old registry");
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY NOT NULL,
                    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                 );",
            )
            .expect("create migration table");
        connection
            .execute_batch(include_str!("../migrations/0001_initial.sql"))
            .expect("apply allocation migration");
        connection
            .execute("INSERT INTO schema_migrations (version) VALUES (1)", [])
            .expect("record allocation migration");
        drop(connection);

        let registry = Registry::open_observational(&paths)
            .expect("open old registry")
            .expect("registry exists");
        assert!(
            !registry
                .runtime_schema_available()
                .expect("read schema version")
        );
    }

    #[test]
    fn runtime_session_reader_accepts_a_pre_owner_identity_schema() {
        let connection = Connection::open_in_memory().expect("open legacy registry");
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY NOT NULL,
                    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                 );",
            )
            .expect("create migration table");
        connection
            .execute_batch(include_str!("../migrations/0001_initial.sql"))
            .expect("apply allocation migration");
        connection
            .execute_batch(include_str!("../migrations/0002_runtime.sql"))
            .expect("apply runtime migration");
        connection
            .execute_batch(include_str!("../migrations/0003_runtime_adapters.sql"))
            .expect("apply adapter migration");
        connection
            .execute_batch(
                "INSERT INTO schema_migrations (version) VALUES (1), (2), (3);
                 INSERT INTO projects (id, git_common_dir)
                 VALUES ('00000000-0000-4000-8000-000000000001', '/legacy/.git');
                 INSERT INTO project_instances
                    (id, project_id, worktree_git_dir, worktree_root)
                 VALUES (
                    '00000000-0000-4000-8000-000000000002',
                    '00000000-0000-4000-8000-000000000001',
                    '/legacy/.git',
                    '/legacy'
                 );
                 INSERT INTO runtime_sessions
                    (id, project_instance_id, status, launcher_pid)
                 VALUES (
                    '00000000-0000-4000-8000-000000000003',
                    '00000000-0000-4000-8000-000000000002',
                    'starting',
                    1234
                 );",
            )
            .expect("seed legacy runtime");

        let session = find_runtime_session(&connection, "00000000-0000-4000-8000-000000000003")
            .expect("read legacy runtime")
            .expect("legacy runtime exists");
        assert_eq!(session.launcher_pid, 1234);
        assert!(session.launcher_process_start.is_none());
    }

    #[test]
    fn observational_open_treats_an_uninitialized_database_as_empty() {
        let temp = tempdir().expect("create temp dir");
        let paths = StatePaths::from_root(temp.path().join("state"));
        fs::create_dir_all(paths.root()).expect("create state directory");
        drop(Connection::open(paths.registry()).expect("create empty database"));

        assert!(
            Registry::open_observational(&paths)
                .expect("observe empty database")
                .is_none()
        );
    }

    #[test]
    fn ensuring_the_same_location_reuses_opaque_ids() {
        let temp = tempdir().expect("create temp dir");
        let repo = temp.path().join("repo");
        let location = initialize_repo(&repo);
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");

        let first = registry
            .ensure_project_instance(&location)
            .expect("ensure first identity");
        let second = registry
            .ensure_project_instance(&location)
            .expect("ensure second identity");

        assert!(first.changed);
        assert!(!second.changed);
        assert_eq!(first.project_id, second.project_id);
        assert_eq!(first.project_instance_id, second.project_instance_id);
    }

    #[test]
    fn first_allocation_is_stable() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let first = create_test_allocation(&mut registry, identity.project_instance_id, "web");
        let port = first.port;
        let second = registry
            .ensure_dynamic_tcp_allocation_from(
                identity.project_instance_id,
                "web",
                std::iter::empty(),
            )
            .expect("reuse allocation");

        assert!(first.changed);
        assert!(!second.changed);
        assert_eq!(first.port, port);
        assert_eq!(second.port, port);
    }

    #[test]
    fn batch_allocation_is_stable_and_deterministic() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let service_keys = vec![
            "supabase.studio".to_owned(),
            "web".to_owned(),
            "supabase.db".to_owned(),
        ];

        let first = registry
            .ensure_dynamic_tcp_allocations_from(
                identity.project_instance_id,
                &service_keys,
                free_ports(8),
                &BTreeSet::new(),
            )
            .expect("create allocation batch");
        let second = registry
            .ensure_dynamic_tcp_allocations_from(
                identity.project_instance_id,
                &service_keys,
                std::iter::empty(),
                &BTreeSet::new(),
            )
            .expect("reuse allocation batch");

        assert_eq!(
            first
                .iter()
                .map(|allocation| allocation.service_key.as_str())
                .collect::<Vec<_>>(),
            ["supabase.db", "supabase.studio", "web"]
        );
        assert_eq!(
            first
                .iter()
                .map(|allocation| allocation.port)
                .collect::<Vec<_>>(),
            second
                .iter()
                .map(|allocation| allocation.port)
                .collect::<Vec<_>>()
        );
        assert!(first.iter().all(|allocation| allocation.changed));
        assert!(second.iter().all(|allocation| !allocation.changed));
    }

    #[test]
    fn exhausted_batch_inserts_no_allocations() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let service_keys = vec!["one".to_owned(), "two".to_owned(), "three".to_owned()];

        let error = registry
            .ensure_dynamic_tcp_allocations_from(
                identity.project_instance_id,
                &service_keys,
                free_ports(2),
                &BTreeSet::new(),
            )
            .expect_err("reject incomplete allocation batch");
        assert!(
            matches!(error, RegistryError::NoPortsAvailable),
            "unexpected batch error: {error:?}"
        );

        let stored = registry
            .find_project_instance(&location)
            .expect("read project instance")
            .expect("stored project instance");
        assert!(stored.allocations.is_empty());
    }

    #[test]
    fn failed_batch_preserves_established_allocations_without_partial_inserts() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let established_port =
            create_test_allocation(&mut registry, identity.project_instance_id, "web").port;
        let service_keys = vec!["web".to_owned(), "db".to_owned(), "studio".to_owned()];

        let error = registry
            .ensure_dynamic_tcp_allocations_from(
                identity.project_instance_id,
                &service_keys,
                [free_port()],
                &BTreeSet::new(),
            )
            .expect_err("reject incomplete extension batch");
        assert!(
            matches!(error, RegistryError::NoPortsAvailable),
            "unexpected batch error: {error:?}"
        );

        let stored = registry
            .find_project_instance(&location)
            .expect("read project instance")
            .expect("stored project instance");
        assert_eq!(
            stored.allocations,
            [StoredAllocation {
                service_key: "web".to_owned(),
                protocol: "tcp".to_owned(),
                port: established_port,
            }]
        );
    }

    #[test]
    fn release_removes_allocations_but_preserves_identity() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let port = create_test_allocation(&mut registry, identity.project_instance_id, "web").port;

        let released = registry
            .release_allocations(identity.project_instance_id)
            .expect("release allocation");
        let repeated = registry
            .release_allocations(identity.project_instance_id)
            .expect("repeat release");
        let stored = registry
            .find_project_instance(&location)
            .expect("find preserved identity")
            .expect("identity remains");

        assert_eq!(
            released,
            vec![StoredAllocation {
                service_key: "web".to_owned(),
                protocol: "tcp".to_owned(),
                port,
            }]
        );
        assert!(repeated.is_empty());
        assert_eq!(stored.project_id, identity.project_id);
        assert_eq!(stored.project_instance_id, identity.project_instance_id);
        assert!(stored.allocations.is_empty());
    }

    #[test]
    fn release_rejects_an_active_runtime_without_removing_allocations() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let port = create_test_allocation(&mut registry, identity.project_instance_id, "web").port;
        let session = registry
            .claim_runtime_session(
                identity.project_instance_id,
                1234,
                "owner-1234",
                "web",
                "tcp",
                port,
            )
            .expect("claim runtime session");

        let error = registry
            .release_allocations(identity.project_instance_id)
            .expect_err("reject release while runtime is active");
        assert!(matches!(
            error,
            RegistryError::RuntimeActive {
                project_instance_id,
                session_id,
            } if project_instance_id == identity.project_instance_id.to_string()
                && session_id == session.session.id.to_string()
        ));
        let stored = registry
            .find_project_instance(&location)
            .expect("read project instance")
            .expect("project instance remains");
        assert_eq!(stored.allocations.len(), 1);
        assert_eq!(stored.allocations[0].port, port);

        assert!(
            registry
                .mark_runtime_start_failed(session.session.id)
                .expect("finish runtime session")
        );
        let released = registry
            .release_allocations(identity.project_instance_id)
            .expect("release after runtime finishes");
        assert_eq!(released.len(), 1);
    }

    #[test]
    fn reallocation_replaces_the_complete_detected_set_atomically() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let initial_keys = vec!["historical".to_owned(), "web".to_owned()];
        let initial = registry
            .ensure_dynamic_tcp_allocations_from(
                identity.project_instance_id,
                &initial_keys,
                free_ports(8),
                &BTreeSet::new(),
            )
            .expect("create initial allocations");
        let initial_ports = initial
            .iter()
            .map(|allocation| allocation.port)
            .collect::<BTreeSet<_>>();
        let desired_keys = vec!["db".to_owned(), "web".to_owned()];

        let reallocated = registry
            .reallocate_dynamic_tcp_allocations_from(
                identity.project_instance_id,
                &desired_keys,
                free_ports(8),
            )
            .expect("reallocate complete set");
        let stored = registry
            .find_project_instance(&location)
            .expect("read project instance")
            .expect("stored project instance");

        assert!(reallocated.changed);
        assert_eq!(
            reallocated
                .previous_allocations
                .iter()
                .map(|allocation| allocation.service_key.as_str())
                .collect::<Vec<_>>(),
            ["historical", "web"]
        );
        assert_eq!(
            reallocated
                .allocations
                .iter()
                .map(|allocation| allocation.service_key.as_str())
                .collect::<Vec<_>>(),
            ["db", "web"]
        );
        assert!(
            reallocated
                .allocations
                .iter()
                .all(|allocation| !initial_ports.contains(&allocation.port))
        );
        assert_eq!(stored.allocations, reallocated.allocations);
    }

    #[test]
    fn failed_reallocation_preserves_the_complete_previous_set() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let initial_keys = vec!["db".to_owned(), "web".to_owned()];
        registry
            .ensure_dynamic_tcp_allocations_from(
                identity.project_instance_id,
                &initial_keys,
                free_ports(8),
                &BTreeSet::new(),
            )
            .expect("create initial allocations");
        let before = registry
            .find_project_instance(&location)
            .expect("read project instance")
            .expect("stored project instance")
            .allocations;

        let error = registry
            .reallocate_dynamic_tcp_allocations_from(
                identity.project_instance_id,
                &initial_keys,
                free_ports(1),
            )
            .expect_err("exhaust replacement candidates");
        let after = registry
            .find_project_instance(&location)
            .expect("read project instance after failure")
            .expect("stored project instance")
            .allocations;

        assert!(matches!(error, RegistryError::NoPortsAvailable));
        assert_eq!(after, before);
    }

    #[test]
    fn reallocation_moves_away_from_an_occupied_established_port() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let old_port =
            create_test_allocation(&mut registry, identity.project_instance_id, "web").port;
        let foreign_listener = bind_test_port(Ipv4Addr::UNSPECIFIED, old_port);

        let reallocated = registry
            .reallocate_dynamic_tcp_allocations_from(
                identity.project_instance_id,
                &["web".to_owned()],
                free_ports(4),
            )
            .expect("move away from occupied established port");

        assert!(reallocated.changed);
        assert_eq!(reallocated.previous_allocations[0].port, old_port);
        assert_ne!(reallocated.allocations[0].port, old_port);
        assert_eq!(
            foreign_listener
                .local_addr()
                .expect("foreign listener address")
                .port(),
            old_port
        );
    }

    #[test]
    fn reallocation_rejects_an_active_runtime_without_changing_allocations() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let port = create_test_allocation(&mut registry, identity.project_instance_id, "web").port;
        let session = registry
            .claim_runtime_session(
                identity.project_instance_id,
                1234,
                "owner-1234",
                "web",
                "tcp",
                port,
            )
            .expect("claim runtime session");

        let error = registry
            .reallocate_dynamic_tcp_allocations_from(
                identity.project_instance_id,
                &["web".to_owned()],
                free_ports(4),
            )
            .expect_err("reject reallocation while runtime is active");
        let stored = registry
            .find_project_instance(&location)
            .expect("read project instance")
            .expect("stored project instance");

        assert!(matches!(error, RegistryError::RuntimeActive { .. }));
        assert_eq!(stored.allocations[0].port, port);
        assert!(
            registry
                .mark_runtime_start_failed(session.session.id)
                .expect("finish runtime session")
        );
    }

    #[test]
    fn simultaneous_reallocations_converge_on_one_replacement_set() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut setup_registry = Registry::open_mutating(&paths).expect("open setup registry");
        let identity = setup_registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let service_keys = vec!["db".to_owned(), "studio".to_owned(), "web".to_owned()];
        setup_registry
            .ensure_dynamic_tcp_allocations_from(
                identity.project_instance_id,
                &service_keys,
                free_ports(8),
                &BTreeSet::new(),
            )
            .expect("create initial allocations");
        drop(setup_registry);

        let mut first_registry = Registry::open_mutating(&paths).expect("open first connection");
        let mut second_registry = Registry::open_mutating(&paths).expect("open second connection");
        let candidates = free_ports(12);
        let barrier = Arc::new(Barrier::new(3));
        let first_barrier = Arc::clone(&barrier);
        let first_keys = service_keys.clone();
        let first_candidates = candidates.clone();
        let first = thread::spawn(move || {
            first_registry.reallocate_dynamic_tcp_allocations_from_with_snapshot_hook(
                identity.project_instance_id,
                &first_keys,
                first_candidates,
                || {
                    first_barrier.wait();
                },
            )
        });
        let second_barrier = Arc::clone(&barrier);
        let second = thread::spawn(move || {
            second_registry.reallocate_dynamic_tcp_allocations_from_with_snapshot_hook(
                identity.project_instance_id,
                &service_keys,
                candidates,
                || {
                    second_barrier.wait();
                },
            )
        });

        barrier.wait();
        let first = first
            .join()
            .expect("join first reallocator")
            .expect("first reallocation");
        let second = second
            .join()
            .expect("join second reallocator")
            .expect("second reallocation");

        assert_eq!(first.allocations, second.allocations);
        assert_ne!(first.changed, second.changed);
    }

    #[test]
    fn runtime_claim_rejects_an_allocation_released_after_environment_materialization() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let port = create_test_allocation(&mut registry, identity.project_instance_id, "web").port;
        registry
            .release_allocations(identity.project_instance_id)
            .expect("release allocation before runtime claim");

        let error = registry
            .claim_runtime_session(
                identity.project_instance_id,
                1234,
                "owner-1234",
                "web",
                "tcp",
                port,
            )
            .expect_err("reject stale runtime environment");
        assert!(matches!(
            error,
            RegistryError::RuntimeAllocationChanged {
                project_instance_id,
                service_key,
                protocol,
                port: changed_port,
            } if project_instance_id == identity.project_instance_id.to_string()
                && service_key == "web"
                && protocol == "tcp"
                && changed_port == port
        ));
        assert!(
            registry
                .find_active_runtime(identity.project_instance_id)
                .expect("read active runtime")
                .is_none()
        );
    }

    #[test]
    fn runtime_session_claim_and_stop_are_idempotent() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let port = create_test_allocation(&mut registry, identity.project_instance_id, "web").port;

        let first = registry
            .claim_runtime_session(
                identity.project_instance_id,
                1234,
                "owner-1234",
                "web",
                "tcp",
                port,
            )
            .expect("claim runtime");
        let repeated = registry
            .claim_runtime_session(
                identity.project_instance_id,
                5678,
                "owner-5678",
                "web",
                "tcp",
                port,
            )
            .expect("repeat runtime claim");
        assert!(first.changed);
        assert!(!repeated.changed);
        assert_eq!(repeated.session.id, first.session.id);
        assert_eq!(repeated.session.launcher_pid, 1234);
        assert_eq!(
            repeated.session.launcher_process_start.as_deref(),
            Some("owner-1234")
        );

        registry
            .record_runtime_process(
                first.session.id,
                &StoredRuntimeProcess {
                    service_key: "web".to_owned(),
                    pid: 2001,
                    process_group_id: 2001,
                    process_start: "Tue Aug 11 10:00:00 2026".to_owned(),
                    executable: "/repo/node_modules/.bin/next".to_owned(),
                    log_path: "/state/sessions/session/web.log".to_owned(),
                },
            )
            .expect("record runtime process");
        assert!(
            registry
                .mark_runtime_ready(first.session.id)
                .expect("mark runtime ready")
        );

        let stop = registry
            .claim_runtime_stop(identity.project_instance_id, 3001, "owner-3001")
            .expect("claim stop")
            .expect("active runtime");
        let repeated_stop = registry
            .claim_runtime_stop(identity.project_instance_id, 3002, "owner-3002")
            .expect("repeat stop claim")
            .expect("stopping runtime");
        assert!(stop.changed);
        assert!(!repeated_stop.changed);
        assert_eq!(stop.session.launcher_pid, 3001);
        assert_eq!(repeated_stop.session.launcher_pid, 3001);
        assert_eq!(
            repeated_stop.session.launcher_process_start.as_deref(),
            Some("owner-3001")
        );
        assert!(
            !registry
                .mark_runtime_stopped_if_owned(first.session.id, 3002, "owner-3002")
                .expect("reject non-owner completion")
        );
        assert!(
            !registry
                .mark_runtime_stopped_if_owned(first.session.id, 3001, "reused-owner-3001")
                .expect("reject reused owner PID completion")
        );
        assert!(
            registry
                .mark_runtime_stopped_if_owned(first.session.id, 3001, "owner-3001")
                .expect("mark runtime stopped")
        );
        assert!(
            registry
                .find_active_runtime(identity.project_instance_id)
                .expect("read active runtime")
                .is_none()
        );
        let stored = registry
            .find_project_instance(&location)
            .expect("read project instance")
            .expect("stored project instance");
        assert_eq!(
            stored.latest_runtime.map(|session| session.status),
            Some("stopped".to_owned())
        );
    }

    #[test]
    fn terminal_history_candidates_and_deletion_are_scoped_and_deterministic() {
        let temp = tempdir().expect("create temp dir");
        let first_location = initialize_repo(&temp.path().join("first-repo"));
        let second_location = initialize_repo(&temp.path().join("second-repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let first = registry
            .ensure_project_instance(&first_location)
            .expect("ensure first identity");
        let second = registry
            .ensure_project_instance(&second_location)
            .expect("ensure second identity");

        let first_sessions = (0..5)
            .map(|index| {
                let session_id = Uuid::new_v4();
                registry
                    .connection
                    .execute(
                        "INSERT INTO runtime_sessions
                            (id, project_instance_id, status, launcher_pid,
                             launcher_process_start, ended_at)
                         VALUES (?1, ?2, 'failed', ?3, ?4, CURRENT_TIMESTAMP)",
                        params![
                            session_id.to_string(),
                            first.project_instance_id.to_string(),
                            10_000 + index,
                            format!("first-owner-{index}")
                        ],
                    )
                    .expect("insert first terminal session");
                registry
                    .connection
                    .execute(
                        "INSERT INTO runtime_processes
                            (session_id, service_key, pid, process_group_id, process_start,
                             executable, log_path)
                         VALUES (?1, 'web', ?2, ?2, ?3, '/bin/false', ?4)",
                        params![
                            session_id.to_string(),
                            20_000 + index,
                            format!("process-{index}"),
                            format!("/state/sessions/{session_id}/web.log")
                        ],
                    )
                    .expect("insert first runtime process");
                session_id
            })
            .collect::<Vec<_>>();
        let other_session = Uuid::new_v4();
        registry
            .connection
            .execute(
                "INSERT INTO runtime_sessions
                    (id, project_instance_id, status, launcher_pid,
                     launcher_process_start, ended_at)
                 VALUES (?1, ?2, 'failed', 30000, 'other-owner', CURRENT_TIMESTAMP)",
                params![
                    other_session.to_string(),
                    second.project_instance_id.to_string()
                ],
            )
            .expect("insert other terminal session");
        let active_session = Uuid::new_v4();
        registry
            .connection
            .execute(
                "INSERT INTO runtime_sessions
                    (id, project_instance_id, status, launcher_pid, launcher_process_start)
                 VALUES (?1, ?2, 'starting', 40000, 'active-owner')",
                params![
                    active_session.to_string(),
                    first.project_instance_id.to_string()
                ],
            )
            .expect("insert active session");
        registry
            .connection
            .execute(
                "INSERT INTO runtime_adapters
                    (session_id, adapter_key, working_directory, runtime_project_id, log_path)
                 VALUES (?1, 'supabase', '/state/runtime', 'retained-test', ?2)",
                params![
                    first_sessions[0].to_string(),
                    format!("/state/sessions/{}/supabase.log", first_sessions[0])
                ],
            )
            .expect("insert terminal runtime adapter");
        registry
            .connection
            .execute(
                "INSERT INTO runtime_adapter_services
                    (session_id, service_key, protocol, port)
                 VALUES (?1, 'supabase.api', 'tcp', 54321)",
                [first_sessions[0].to_string()],
            )
            .expect("insert terminal adapter service");

        let candidates = registry
            .terminal_runtime_sessions_to_prune(first.project_instance_id, 3)
            .expect("select terminal history candidates");
        assert_eq!(candidates, vec![first_sessions[1], first_sessions[0]]);

        let mut requested = candidates.clone();
        requested.push(active_session);
        requested.push(other_session);
        let deleted = registry
            .delete_terminal_runtime_sessions(first.project_instance_id, &requested)
            .expect("delete exact terminal history candidates");
        assert_eq!(deleted, 2);

        let remaining_first_terminal = registry
            .connection
            .query_row(
                "SELECT COUNT(*) FROM runtime_sessions
                 WHERE project_instance_id = ?1 AND status IN ('stopped', 'failed')",
                [first.project_instance_id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .expect("count retained first sessions");
        assert_eq!(remaining_first_terminal, 3);
        assert!(
            registry
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM runtime_sessions WHERE id = ?1)",
                    [active_session.to_string()],
                    |row| row.get::<_, bool>(0),
                )
                .expect("check active session")
        );
        assert!(
            registry
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM runtime_sessions WHERE id = ?1)",
                    [other_session.to_string()],
                    |row| row.get::<_, bool>(0),
                )
                .expect("check other session")
        );
        for deleted_session in &first_sessions[..2] {
            let process_exists = registry
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM runtime_processes WHERE session_id = ?1)",
                    [deleted_session.to_string()],
                    |row| row.get::<_, bool>(0),
                )
                .expect("check deleted process");
            assert!(!process_exists);
        }
        assert_eq!(
            registry
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM runtime_adapters WHERE session_id = ?1",
                    [first_sessions[0].to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count deleted adapters"),
            0
        );
        assert_eq!(
            registry
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM runtime_adapter_services WHERE session_id = ?1",
                    [first_sessions[0].to_string()],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count deleted adapter services"),
            0
        );
    }

    #[test]
    fn runtime_replacement_atomically_stops_the_predecessor_and_claims_the_successor() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let port = create_test_allocation(&mut registry, identity.project_instance_id, "web").port;
        let predecessor = registry
            .claim_runtime_session(
                identity.project_instance_id,
                1234,
                "owner-1234",
                "web",
                "tcp",
                port,
            )
            .expect("claim predecessor");
        assert!(
            registry
                .mark_runtime_ready(predecessor.session.id)
                .expect("mark predecessor ready")
        );
        let stop = registry
            .claim_runtime_stop_if_current(
                identity.project_instance_id,
                predecessor.session.id,
                5678,
                "owner-5678",
            )
            .expect("claim predecessor stop")
            .expect("current predecessor");
        assert!(stop.changed);

        assert!(
            registry
                .replace_runtime_session_if_current(
                    predecessor.session.id,
                    identity.project_instance_id,
                    RuntimeOwnerRef {
                        pid: 5678,
                        process_start: "reused-owner-5678",
                    },
                    "web",
                    "tcp",
                    port,
                )
                .expect("reject non-owner replacement")
                .is_none()
        );
        assert!(
            registry
                .take_over_runtime_stop_if_current(
                    identity.project_instance_id,
                    predecessor.session.id,
                    5678,
                    Some("reused-owner-5678"),
                    9999,
                    "owner-9999",
                )
                .expect("reject takeover with stale owner identity")
                .is_none()
        );
        let takeover = registry
            .take_over_runtime_stop_if_current(
                identity.project_instance_id,
                predecessor.session.id,
                5678,
                Some("owner-5678"),
                9999,
                "owner-9999",
            )
            .expect("take over predecessor")
            .expect("current predecessor");
        assert!(takeover.changed);
        assert_eq!(takeover.session.launcher_pid, 9999);
        assert_eq!(
            takeover.session.launcher_process_start.as_deref(),
            Some("owner-9999")
        );

        let successor = registry
            .replace_runtime_session_if_current(
                predecessor.session.id,
                identity.project_instance_id,
                RuntimeOwnerRef {
                    pid: 9999,
                    process_start: "owner-9999",
                },
                "web",
                "tcp",
                port,
            )
            .expect("replace runtime")
            .expect("current predecessor replacement");
        assert!(successor.changed);
        assert_ne!(successor.session.id, predecessor.session.id);
        assert_eq!(successor.session.status, "starting");
        assert_eq!(successor.session.launcher_pid, 9999);
        assert_eq!(
            successor.session.launcher_process_start.as_deref(),
            Some("owner-9999")
        );

        let predecessor_status = registry
            .connection
            .query_row(
                "SELECT status FROM runtime_sessions WHERE id = ?1",
                [predecessor.session.id.to_string()],
                |row| row.get::<_, String>(0),
            )
            .expect("read predecessor status");
        assert_eq!(predecessor_status, "stopped");
        let stored = registry
            .find_project_instance(&location)
            .expect("read project instance")
            .expect("stored project instance");
        assert_eq!(
            stored.active_runtime.as_ref().map(|session| session.id),
            Some(successor.session.id)
        );
        assert_eq!(
            stored.latest_runtime.as_ref().map(|session| session.id),
            Some(successor.session.id)
        );
        assert!(
            registry
                .replace_runtime_session_if_current(
                    predecessor.session.id,
                    identity.project_instance_id,
                    RuntimeOwnerRef {
                        pid: 9999,
                        process_start: "owner-9999",
                    },
                    "web",
                    "tcp",
                    port,
                )
                .expect("repeat stale replacement")
                .is_none()
        );
    }

    #[test]
    fn adapter_only_start_requires_an_explicit_abandoned_stop_claim() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let port =
            create_test_allocation(&mut registry, identity.project_instance_id, "supabase.api")
                .port;
        let start = registry
            .claim_runtime_session(
                identity.project_instance_id,
                1234,
                "owner-1234",
                "supabase.api",
                "tcp",
                port,
            )
            .expect("claim runtime");
        registry
            .record_runtime_adapter(
                start.session.id,
                &StoredRuntimeAdapter {
                    adapter_key: "supabase".to_owned(),
                    working_directory: "/state/runtime".to_owned(),
                    runtime_project_id: "duckflap-test".to_owned(),
                    log_path: "/state/session/supabase.log".to_owned(),
                    services: vec![StoredRuntimeService {
                        service_key: "supabase.api".to_owned(),
                        protocol: "tcp".to_owned(),
                        port,
                    }],
                },
            )
            .expect("record runtime adapter");
        registry
            .record_runtime_process(
                start.session.id,
                &StoredRuntimeProcess {
                    service_key: "supabase.startup".to_owned(),
                    pid: 3001,
                    process_group_id: 3001,
                    process_start: "Tue Aug 11 10:00:01 2026".to_owned(),
                    executable: "/usr/local/bin/supabase".to_owned(),
                    log_path: "/state/session/supabase.log".to_owned(),
                },
            )
            .expect("record transient adapter startup");

        let error = registry
            .claim_runtime_stop_if_current(
                identity.project_instance_id,
                start.session.id,
                4001,
                "owner-4001",
            )
            .expect_err("reject normal stop claim during adapter start");
        assert!(matches!(error, RegistryError::RuntimeStillStarting(_)));
        assert_eq!(
            registry
                .find_active_runtime(identity.project_instance_id)
                .expect("read active runtime")
                .expect("active runtime")
                .status,
            "starting"
        );

        let abandoned = registry
            .claim_abandoned_runtime_stop_if_current(
                identity.project_instance_id,
                start.session.id,
                4002,
                "owner-4002",
            )
            .expect("claim abandoned start")
            .expect("active runtime");
        assert!(abandoned.changed);
        assert_eq!(abandoned.session.status, "stopping");
        assert_eq!(
            abandoned
                .session
                .adapter_startup
                .as_ref()
                .map(|process| process.service_key.as_str()),
            Some("supabase.startup")
        );
    }

    #[test]
    fn busy_candidate_is_skipped() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let busy_port = free_port();
        let _busy = bind_test_port(Ipv4Addr::LOCALHOST, busy_port);
        let mut candidates = vec![busy_port];
        candidates.extend(free_ports(8));

        let allocation = registry
            .ensure_dynamic_tcp_allocation_from(identity.project_instance_id, "web", candidates)
            .expect("create allocation");

        assert_ne!(allocation.port, busy_port);
    }

    #[test]
    fn managed_port_cannot_be_owned_by_two_instances() {
        let temp = tempdir().expect("create temp dir");
        let first_location = initialize_repo(&temp.path().join("first"));
        let second_location = initialize_repo(&temp.path().join("second"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let first_identity = registry
            .ensure_project_instance(&first_location)
            .expect("ensure first identity");
        let second_identity = registry
            .ensure_project_instance(&second_location)
            .expect("ensure second identity");
        let port =
            create_test_allocation(&mut registry, first_identity.project_instance_id, "web").port;
        let error = registry
            .ensure_dynamic_tcp_allocation_from(second_identity.project_instance_id, "web", [port])
            .expect_err("reject duplicate ownership");

        assert!(matches!(error, RegistryError::NoPortsAvailable));
    }

    #[test]
    fn simultaneous_connections_allocate_distinct_ports() {
        let temp = tempdir().expect("create temp dir");
        let first_location = initialize_repo(&temp.path().join("first"));
        let second_location = initialize_repo(&temp.path().join("second"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut setup_registry = Registry::open_mutating(&paths).expect("open setup registry");
        let first_identity = setup_registry
            .ensure_project_instance(&first_location)
            .expect("ensure first identity");
        let second_identity = setup_registry
            .ensure_project_instance(&second_location)
            .expect("ensure second identity");
        drop(setup_registry);

        let mut first_registry = Registry::open_mutating(&paths).expect("open first connection");
        let mut second_registry = Registry::open_mutating(&paths).expect("open second connection");
        let candidates = free_ports(4);
        let barrier = Arc::new(Barrier::new(3));
        let first_barrier = Arc::clone(&barrier);
        let first_candidates = candidates.clone();
        let first = thread::spawn(move || {
            first_barrier.wait();
            first_registry.ensure_dynamic_tcp_allocation_from(
                first_identity.project_instance_id,
                "web",
                first_candidates,
            )
        });
        let second_barrier = Arc::clone(&barrier);
        let second = thread::spawn(move || {
            second_barrier.wait();
            second_registry.ensure_dynamic_tcp_allocation_from(
                second_identity.project_instance_id,
                "web",
                candidates,
            )
        });

        barrier.wait();
        let first = first
            .join()
            .expect("join first allocator")
            .expect("first allocation");
        let second = second
            .join()
            .expect("join second allocator")
            .expect("second allocation");

        assert_ne!(first.port, second.port);
        assert!(first.changed);
        assert!(second.changed);
    }

    #[test]
    fn simultaneous_batch_callers_converge_on_one_allocation_set() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut setup_registry = Registry::open_mutating(&paths).expect("open setup registry");
        let identity = setup_registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        drop(setup_registry);

        let mut first_registry = Registry::open_mutating(&paths).expect("open first connection");
        let mut second_registry = Registry::open_mutating(&paths).expect("open second connection");
        let service_keys = vec!["web".to_owned(), "db".to_owned(), "studio".to_owned()];
        let candidates = free_ports(8);
        let barrier = Arc::new(Barrier::new(3));
        let first_barrier = Arc::clone(&barrier);
        let first_service_keys = service_keys.clone();
        let first_candidates = candidates.clone();
        let first = thread::spawn(move || {
            first_barrier.wait();
            first_registry.ensure_dynamic_tcp_allocations_from(
                identity.project_instance_id,
                &first_service_keys,
                first_candidates,
                &BTreeSet::new(),
            )
        });
        let second_barrier = Arc::clone(&barrier);
        let second = thread::spawn(move || {
            second_barrier.wait();
            second_registry.ensure_dynamic_tcp_allocations_from(
                identity.project_instance_id,
                &service_keys,
                candidates,
                &BTreeSet::new(),
            )
        });

        barrier.wait();
        let first = first
            .join()
            .expect("join first allocator")
            .expect("first allocation batch");
        let second = second
            .join()
            .expect("join second allocator")
            .expect("second allocation batch");

        assert_eq!(
            first
                .iter()
                .map(|allocation| (&allocation.service_key, allocation.port))
                .collect::<Vec<_>>(),
            second
                .iter()
                .map(|allocation| (&allocation.service_key, allocation.port))
                .collect::<Vec<_>>()
        );
        let changed_counts = [
            first.iter().filter(|allocation| allocation.changed).count(),
            second
                .iter()
                .filter(|allocation| allocation.changed)
                .count(),
        ];
        assert!(changed_counts.contains(&0));
        assert!(changed_counts.contains(&3));
    }

    #[test]
    fn simultaneous_instances_receive_disjoint_allocation_sets() {
        let temp = tempdir().expect("create temp dir");
        let first_location = initialize_repo(&temp.path().join("first"));
        let second_location = initialize_repo(&temp.path().join("second"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut setup_registry = Registry::open_mutating(&paths).expect("open setup registry");
        let first_identity = setup_registry
            .ensure_project_instance(&first_location)
            .expect("ensure first identity");
        let second_identity = setup_registry
            .ensure_project_instance(&second_location)
            .expect("ensure second identity");
        drop(setup_registry);

        let mut first_registry = Registry::open_mutating(&paths).expect("open first connection");
        let mut second_registry = Registry::open_mutating(&paths).expect("open second connection");
        let service_keys = vec!["web".to_owned(), "db".to_owned(), "studio".to_owned()];
        let candidates = free_ports(8);
        let barrier = Arc::new(Barrier::new(3));
        let first_barrier = Arc::clone(&barrier);
        let first_service_keys = service_keys.clone();
        let first_candidates = candidates.clone();
        let first = thread::spawn(move || {
            first_barrier.wait();
            first_registry.ensure_dynamic_tcp_allocations_from(
                first_identity.project_instance_id,
                &first_service_keys,
                first_candidates,
                &BTreeSet::new(),
            )
        });
        let second_barrier = Arc::clone(&barrier);
        let second = thread::spawn(move || {
            second_barrier.wait();
            second_registry.ensure_dynamic_tcp_allocations_from(
                second_identity.project_instance_id,
                &service_keys,
                candidates,
                &BTreeSet::new(),
            )
        });

        barrier.wait();
        let first = first
            .join()
            .expect("join first allocator")
            .expect("first allocation batch");
        let second = second
            .join()
            .expect("join second allocator")
            .expect("second allocation batch");
        let first_ports = first
            .iter()
            .map(|allocation| allocation.port)
            .collect::<BTreeSet<_>>();
        let second_ports = second
            .iter()
            .map(|allocation| allocation.port)
            .collect::<BTreeSet<_>>();

        assert!(first_ports.is_disjoint(&second_ports));
        assert!(first.iter().all(|allocation| allocation.changed));
        assert!(second.iter().all(|allocation| allocation.changed));
    }

    #[test]
    fn simultaneous_connections_reuse_an_established_allocation() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut setup_registry = Registry::open_mutating(&paths).expect("open setup registry");
        let identity = setup_registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let port =
            create_test_allocation(&mut setup_registry, identity.project_instance_id, "web").port;
        drop(setup_registry);

        const CONNECTION_COUNT: usize = 4;
        let barrier = Arc::new(Barrier::new(CONNECTION_COUNT + 1));
        let mut callers = Vec::with_capacity(CONNECTION_COUNT);
        for _ in 0..CONNECTION_COUNT {
            let mut registry =
                Registry::open_mutating(&paths).expect("open independent connection");
            let barrier = Arc::clone(&barrier);
            let project_instance_id = identity.project_instance_id;
            callers.push(thread::spawn(move || {
                barrier.wait();
                registry.ensure_dynamic_tcp_allocation_from(
                    project_instance_id,
                    "web",
                    std::iter::empty::<u16>(),
                )
            }));
        }

        barrier.wait();
        for caller in callers {
            let allocation = caller
                .join()
                .expect("join allocation caller")
                .expect("reuse established allocation");
            assert_eq!(allocation.port, port);
            assert!(!allocation.changed);
        }
    }

    #[test]
    fn occupied_established_port_is_preserved() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");
        let port = create_test_allocation(&mut registry, identity.project_instance_id, "web").port;
        let listener = bind_test_port(Ipv4Addr::UNSPECIFIED, port);

        let error = registry
            .ensure_dynamic_tcp_allocation_from(
                identity.project_instance_id,
                "web",
                std::iter::empty(),
            )
            .expect_err("reject occupied established port");
        assert!(matches!(
            error,
            RegistryError::EstablishedPortOccupied {
                port: occupied,
                ..
            } if occupied == port
        ));

        drop(listener);
        let preserved = registry
            .ensure_dynamic_tcp_allocation_from(
                identity.project_instance_id,
                "web",
                std::iter::empty(),
            )
            .expect("reuse preserved allocation");
        assert_eq!(preserved.port, port);
        assert!(!preserved.changed);
    }

    #[test]
    fn empty_candidate_range_is_exhausted() {
        let temp = tempdir().expect("create temp dir");
        let location = initialize_repo(&temp.path().join("repo"));
        let paths = StatePaths::from_root(temp.path().join("state"));
        let mut registry = Registry::open_mutating(&paths).expect("open registry");
        let identity = registry
            .ensure_project_instance(&location)
            .expect("ensure identity");

        let error = registry
            .ensure_dynamic_tcp_allocation_from(
                identity.project_instance_id,
                "web",
                std::iter::empty(),
            )
            .expect_err("report exhaustion");

        assert!(matches!(error, RegistryError::NoPortsAvailable));
    }

    fn initialize_repo(path: &Path) -> GitLocation {
        fs::create_dir(path).expect("create repo dir");
        let status = Command::new("git")
            .args(["init", "--quiet"])
            .arg(path)
            .status()
            .expect("run git init");
        assert!(status.success());
        GitLocation::discover(path).expect("discover Git location")
    }

    fn create_test_allocation(
        registry: &mut Registry,
        project_instance_id: uuid::Uuid,
        service_key: &str,
    ) -> EnsuredAllocation {
        registry
            .ensure_dynamic_tcp_allocation_from(project_instance_id, service_key, free_ports(8))
            .expect("create allocation")
    }

    fn bind_test_port(address: Ipv4Addr, port: u16) -> TcpListener {
        for _ in 0..20 {
            match TcpListener::bind(SocketAddrV4::new(address, port)) {
                Ok(listener) => return listener,
                Err(source) if source.kind() == std::io::ErrorKind::AddrInUse => {
                    thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(source) => panic!("bind test port {port}: {source}"),
            }
        }
        panic!("test port {port} remained occupied during handoff")
    }

    fn free_port() -> u16 {
        loop {
            let port = NEXT_TEST_PORT.fetch_add(1, Ordering::Relaxed);
            if let Ok(listener) = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
            {
                drop(listener);
                return port;
            }
        }
    }

    fn free_ports(count: usize) -> Vec<u16> {
        (0..count).map(|_| free_port()).collect()
    }
}
