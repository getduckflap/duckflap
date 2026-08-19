use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
};

use thiserror::Error;
use toml::{Table, Value};
use uuid::Uuid;

use crate::{
    runtime::{GatedRuntime, RuntimeError, spawn_gated_with_stdio},
    state::{StatePaths, ensure_private_directory, make_file_private},
};

pub const ADAPTER_KEY: &str = "supabase";
pub const STARTUP_PROCESS_KEY: &str = "supabase.startup";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedRuntime {
    pub working_directory: PathBuf,
    pub project_id: String,
}

pub fn materialize(
    source_root: &Path,
    state_paths: &StatePaths,
    project_instance_id: Uuid,
    operation_id: Uuid,
    ports: &BTreeMap<String, u16>,
) -> Result<MaterializedRuntime, SupabaseError> {
    let source_supabase = source_root.join("supabase");
    let runtimes = state_paths.runtimes();
    let target = runtimes.join(project_instance_id.to_string());
    let staging = runtimes.join(format!(".{project_instance_id}.{operation_id}.staging"));

    ensure_private_directory(&runtimes).map_err(|source| SupabaseError::PrepareDirectory {
        path: runtimes.clone(),
        source,
    })?;
    remove_directory_if_present(&staging)?;
    fs::create_dir(&staging).map_err(|source| SupabaseError::PrepareDirectory {
        path: staging.clone(),
        source,
    })?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).map_err(|source| {
        SupabaseError::PrepareDirectory {
            path: staging.clone(),
            source,
        }
    })?;

    let result = (|| {
        copy_supabase_project(&source_supabase, &staging.join("supabase"))?;
        let source_env = source_root.join(".env");
        if source_env
            .try_exists()
            .map_err(|source| SupabaseError::Copy {
                from: source_env.clone(),
                to: staging.join(".env"),
                source,
            })?
        {
            copy_entry(&source_env, &staging.join(".env"))?;
        }

        let project_id = runtime_project_id(project_instance_id);
        rewrite_config(&staging.join("supabase/config.toml"), &project_id, ports)?;
        remove_directory_if_present(&target)?;
        fs::rename(&staging, &target).map_err(|source| SupabaseError::InstallDirectory {
            from: staging.clone(),
            to: target.clone(),
            source,
        })?;

        Ok(MaterializedRuntime {
            working_directory: target,
            project_id,
        })
    })();

    if result.is_err() {
        let _ = remove_directory_if_present(&staging);
    }
    result
}

fn copy_supabase_project(source: &Path, destination: &Path) -> Result<(), SupabaseError> {
    reject_symlink(source)?;
    fs::create_dir(destination).map_err(|source_error| SupabaseError::Copy {
        from: source.to_path_buf(),
        to: destination.to_path_buf(),
        source: source_error,
    })?;
    for entry in fs::read_dir(source).map_err(|source_error| SupabaseError::Copy {
        from: source.to_path_buf(),
        to: destination.to_path_buf(),
        source: source_error,
    })? {
        let entry = entry.map_err(|source_error| SupabaseError::Copy {
            from: source.to_path_buf(),
            to: destination.to_path_buf(),
            source: source_error,
        })?;
        if entry.file_name() == ".temp" || entry.file_name() == ".branches" {
            continue;
        }
        copy_entry(&entry.path(), &destination.join(entry.file_name()))?;
    }
    Ok(())
}

pub fn prepare_start(
    working_directory: &Path,
    log_path: &Path,
) -> Result<GatedRuntime, SupabaseError> {
    let executable = find_supabase_executable()?;
    let (log, stderr) = open_log(log_path, LogMode::Truncate)?;
    let arguments = vec![
        OsString::from("start"),
        OsString::from("--workdir"),
        working_directory.as_os_str().to_owned(),
        OsString::from("--yes"),
    ];
    spawn_gated_with_stdio(
        &executable,
        &arguments,
        &BTreeMap::new(),
        working_directory,
        log_path,
        log,
        stderr,
    )
    .map_err(SupabaseError::PrepareStartHelper)
}

pub fn release_and_wait_for_start(
    pending: &mut GatedRuntime,
    log_path: &Path,
) -> Result<(), SupabaseError> {
    pending.release().map_err(SupabaseError::ReleaseStartGate)?;
    let status = match pending.child.wait() {
        Ok(status) => status,
        Err(source) => {
            let _ = crate::runtime::terminate_process_group(pending.process_group_id);
            let _ = pending.child.wait();
            return Err(SupabaseError::WaitForCli {
                action: "start",
                source,
            });
        }
    };
    let exec_error = pending
        .take_exec_error()
        .map_err(|error| SupabaseError::WaitForCli {
            action: "start",
            source: io::Error::other(error.to_string()),
        })?;
    if let Some(source) = exec_error {
        return Err(SupabaseError::LaunchCli {
            action: "start",
            source,
        });
    }
    if status.success() {
        Ok(())
    } else {
        Err(SupabaseError::CliFailed {
            action: "start",
            status,
            log_path: log_path.to_path_buf(),
        })
    }
}

pub fn stop(
    working_directory: &Path,
    project_id: &str,
    log_path: &Path,
) -> Result<(), SupabaseError> {
    run_cli(
        "stop",
        working_directory,
        Some(project_id),
        log_path,
        LogMode::Append,
    )
}

fn runtime_project_id(project_instance_id: Uuid) -> String {
    format!("duckflap{}", project_instance_id.simple())
}

fn rewrite_config(
    path: &Path,
    project_id: &str,
    ports: &BTreeMap<String, u16>,
) -> Result<(), SupabaseError> {
    let contents = fs::read_to_string(path).map_err(|source| SupabaseError::ReadConfig {
        path: path.to_path_buf(),
        source,
    })?;
    let mut config =
        toml::from_str::<Value>(&contents).map_err(|source| SupabaseError::ParseConfig {
            path: path.to_path_buf(),
            source,
        })?;
    let root = config
        .as_table_mut()
        .ok_or_else(|| SupabaseError::ConfigRootNotTable(path.to_path_buf()))?;
    root.insert(
        "project_id".to_owned(),
        Value::String(project_id.to_owned()),
    );

    let mail_section = if root.contains_key("local_smtp") {
        "local_smtp"
    } else {
        "inbucket"
    };
    for (service_key, port) in ports {
        let field = match service_key.as_str() {
            "supabase.api" => Some((&["api"][..], "port")),
            "supabase.db" => Some((&["db"][..], "port")),
            "supabase.db.shadow" => Some((&["db"][..], "shadow_port")),
            "supabase.pooler" => Some((&["db", "pooler"][..], "port")),
            "supabase.studio" => Some((&["studio"][..], "port")),
            "supabase.mail" => Some((&[mail_section][..], "port")),
            "supabase.mail.smtp" => Some((&[mail_section][..], "smtp_port")),
            "supabase.mail.pop3" => Some((&[mail_section][..], "pop3_port")),
            "supabase.edge_inspector" => Some((&["edge_runtime"][..], "inspector_port")),
            "supabase.analytics" => Some((&["analytics"][..], "port")),
            "supabase.analytics.vector" => Some((&["analytics"][..], "vector_port")),
            _ => None,
        };
        if let Some((sections, field)) = field {
            set_integer(root, sections, field, *port);
        }
    }

    let rendered =
        toml::to_string_pretty(&config).map_err(|source| SupabaseError::RenderConfig {
            path: path.to_path_buf(),
            source,
        })?;
    fs::write(path, rendered).map_err(|source| SupabaseError::WriteConfig {
        path: path.to_path_buf(),
        source,
    })
}

fn set_integer(root: &mut Table, sections: &[&str], field: &str, port: u16) {
    let mut table = root;
    for section in sections {
        let value = table
            .entry((*section).to_owned())
            .or_insert_with(|| Value::Table(Table::new()));
        if !value.is_table() {
            *value = Value::Table(Table::new());
        }
        table = value.as_table_mut().expect("table was just created");
    }
    table.insert(field.to_owned(), Value::Integer(i64::from(port)));
}

fn copy_entry(source: &Path, destination: &Path) -> Result<(), SupabaseError> {
    let metadata = fs::symlink_metadata(source).map_err(|source_error| SupabaseError::Copy {
        from: source.to_path_buf(),
        to: destination.to_path_buf(),
        source: source_error,
    })?;
    if metadata.file_type().is_symlink() {
        return Err(SupabaseError::UnsupportedSymlink(source.to_path_buf()));
    } else if metadata.is_dir() {
        fs::create_dir(destination).map_err(|source_error| SupabaseError::Copy {
            from: source.to_path_buf(),
            to: destination.to_path_buf(),
            source: source_error,
        })?;
        for entry in fs::read_dir(source).map_err(|source_error| SupabaseError::Copy {
            from: source.to_path_buf(),
            to: destination.to_path_buf(),
            source: source_error,
        })? {
            let entry = entry.map_err(|source_error| SupabaseError::Copy {
                from: source.to_path_buf(),
                to: destination.to_path_buf(),
                source: source_error,
            })?;
            copy_entry(&entry.path(), &destination.join(entry.file_name()))?;
        }
    } else {
        fs::copy(source, destination).map_err(|source_error| SupabaseError::Copy {
            from: source.to_path_buf(),
            to: destination.to_path_buf(),
            source: source_error,
        })?;
    }
    Ok(())
}

fn reject_symlink(path: &Path) -> Result<(), SupabaseError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| SupabaseError::Copy {
        from: path.to_path_buf(),
        to: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() {
        Err(SupabaseError::UnsupportedSymlink(path.to_path_buf()))
    } else {
        Ok(())
    }
}

fn remove_directory_if_present(path: &Path) -> Result<(), SupabaseError> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(SupabaseError::RemoveDirectory {
            path: path.to_path_buf(),
            source,
        }),
    }
}

enum LogMode {
    Truncate,
    Append,
}

fn find_supabase_executable() -> Result<PathBuf, SupabaseError> {
    let executable = env::var_os("PATH")
        .into_iter()
        .flat_map(|path| env::split_paths(&path).collect::<Vec<_>>())
        .map(|directory| directory.join("supabase"))
        .find(|candidate| {
            fs::metadata(candidate).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        });
    let executable = executable.ok_or_else(|| SupabaseError::LaunchCli {
        action: "start",
        source: io::Error::new(
            io::ErrorKind::NotFound,
            "Supabase CLI is not available on PATH",
        ),
    })?;
    fs::canonicalize(&executable).map_err(|source| SupabaseError::LaunchCli {
        action: "start",
        source,
    })
}

fn open_log(log_path: &Path, log_mode: LogMode) -> Result<(File, File), SupabaseError> {
    if let Some(parent) = log_path.parent() {
        ensure_private_directory(parent).map_err(|source| SupabaseError::PrepareDirectory {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let mut options = OpenOptions::new();
    options.create(true).write(true).mode(0o600);
    match log_mode {
        LogMode::Truncate => {
            options.truncate(true);
        }
        LogMode::Append => {
            options.append(true);
        }
    }
    let log = options
        .open(log_path)
        .map_err(|source| SupabaseError::OpenLog {
            path: log_path.to_path_buf(),
            source,
        })?;
    make_file_private(log_path).map_err(|source| SupabaseError::OpenLog {
        path: log_path.to_path_buf(),
        source,
    })?;
    let stderr = File::try_clone(&log).map_err(|source| SupabaseError::OpenLog {
        path: log_path.to_path_buf(),
        source,
    })?;
    Ok((log, stderr))
}

fn run_cli(
    action: &'static str,
    working_directory: &Path,
    project_id: Option<&str>,
    log_path: &Path,
    log_mode: LogMode,
) -> Result<(), SupabaseError> {
    let (log, stderr) = open_log(log_path, log_mode)?;

    let mut command = Command::new("supabase");
    command
        .arg(action)
        .arg("--workdir")
        .arg(working_directory)
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(stderr));
    if action == "start" {
        command.arg("--yes");
    }
    if let Some(project_id) = project_id {
        command.arg("--project-id").arg(project_id);
    }
    let mut child = command
        .spawn()
        .map_err(|source| SupabaseError::LaunchCli { action, source })?;
    let status = match child.wait() {
        Ok(status) => status,
        Err(source) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SupabaseError::WaitForCli { action, source });
        }
    };
    if status.success() {
        Ok(())
    } else {
        Err(SupabaseError::CliFailed {
            action,
            status,
            log_path: log_path.to_path_buf(),
        })
    }
}

#[derive(Debug, Error)]
pub enum SupabaseError {
    #[error("Supabase runtime path is not valid UTF-8: {0:?}")]
    NonUtf8Path(PathBuf),
    #[error("failed to prepare Supabase runtime directory {path:?}: {source}")]
    PrepareDirectory { path: PathBuf, source: io::Error },
    #[error("failed to remove old Supabase runtime directory {path:?}: {source}")]
    RemoveDirectory { path: PathBuf, source: io::Error },
    #[error("failed to copy Supabase runtime input from {from:?} to {to:?}: {source}")]
    Copy {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
    #[error("local Supabase runtime input {0:?} is a symlink, which is unsupported")]
    UnsupportedSymlink(PathBuf),
    #[error("failed to install Supabase runtime directory from {from:?} to {to:?}: {source}")]
    InstallDirectory {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },
    #[error("failed to read generated Supabase config {path:?}: {source}")]
    ReadConfig { path: PathBuf, source: io::Error },
    #[error("generated Supabase config {path:?} is invalid: {source}")]
    ParseConfig {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("generated Supabase config {0:?} must have a table root")]
    ConfigRootNotTable(PathBuf),
    #[error("failed to render generated Supabase config {path:?}: {source}")]
    RenderConfig {
        path: PathBuf,
        source: toml::ser::Error,
    },
    #[error("failed to write generated Supabase config {path:?}: {source}")]
    WriteConfig { path: PathBuf, source: io::Error },
    #[error("failed to open Supabase runtime log {path:?}: {source}")]
    OpenLog { path: PathBuf, source: io::Error },
    #[error("failed to launch Supabase CLI for {action}: {source}")]
    LaunchCli {
        action: &'static str,
        source: io::Error,
    },
    #[error("failed to prepare the gated Supabase start helper: {0}")]
    PrepareStartHelper(RuntimeError),
    #[error("failed to release the gated Supabase start helper: {0}")]
    ReleaseStartGate(RuntimeError),
    #[error("failed to wait for Supabase CLI {action}: {source}")]
    WaitForCli {
        action: &'static str,
        source: io::Error,
    },
    #[error("Supabase CLI {action} failed ({status}); see {log_path:?}")]
    CliFailed {
        action: &'static str,
        status: ExitStatus,
        log_path: PathBuf,
    },
}

impl SupabaseError {
    pub fn start_may_have_created_resources(&self) -> bool {
        matches!(
            self,
            Self::WaitForCli {
                action: "start",
                ..
            } | Self::CliFailed {
                action: "start",
                ..
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };

    use tempfile::tempdir;
    use toml::Value;
    use uuid::Uuid;

    use crate::state::StatePaths;

    use super::materialize;

    #[test]
    fn materializes_complete_private_project_with_every_allocated_port() {
        let temp = tempdir().expect("create temp directory");
        let source = temp.path().join("source");
        let supabase = source.join("supabase");
        fs::create_dir_all(supabase.join("migrations")).expect("create Supabase source");
        fs::create_dir(supabase.join(".temp")).expect("create CLI temp state");
        fs::write(supabase.join(".temp/project-ref"), "linked-ref")
            .expect("write ignored CLI state");
        fs::write(
            supabase.join("config.toml"),
            r#"
                project_id = "source"

                [api]
                port = "env(API_PORT)"

                [db]
                port = 54322
                shadow_port = 54320

                [db.pooler]
                enabled = true
                port = 54329

                [studio]
                port = 54323

                [local_smtp]
                port = 54324
                smtp_port = 54325
                pop3_port = 54326

                [edge_runtime]
                inspector_port = 8083

                [analytics]
                port = 54327
                vector_port = 54328
            "#,
        )
        .expect("write source config");
        fs::write(supabase.join("migrations/0001_test.sql"), "select 1;\n")
            .expect("write migration");
        fs::write(source.join(".env"), "API_PORT=54321\n").expect("write root environment");

        let ports = BTreeMap::from([
            ("supabase.api".to_owned(), 20_000),
            ("supabase.db".to_owned(), 20_001),
            ("supabase.db.shadow".to_owned(), 20_002),
            ("supabase.pooler".to_owned(), 20_003),
            ("supabase.studio".to_owned(), 20_004),
            ("supabase.mail".to_owned(), 20_005),
            ("supabase.mail.smtp".to_owned(), 20_006),
            ("supabase.mail.pop3".to_owned(), 20_007),
            ("supabase.edge_inspector".to_owned(), 20_008),
            ("supabase.analytics".to_owned(), 20_009),
            ("supabase.analytics.vector".to_owned(), 20_010),
        ]);
        let instance_id =
            Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("project instance UUID");
        let state = StatePaths::from_root(temp.path().join("state"));
        let runtime = materialize(&source, &state, instance_id, Uuid::new_v4(), &ports)
            .expect("materialize Supabase runtime");

        assert_eq!(
            runtime.project_id,
            "duckflapaaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa"
        );
        assert_eq!(
            fs::metadata(&runtime.working_directory)
                .expect("runtime metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::read_to_string(runtime.working_directory.join(".env")).expect("copied environment"),
            "API_PORT=54321\n"
        );
        assert_eq!(
            fs::read_to_string(
                runtime
                    .working_directory
                    .join("supabase/migrations/0001_test.sql")
            )
            .expect("copied migration"),
            "select 1;\n"
        );
        assert!(!runtime.working_directory.join("supabase/.temp").exists());

        let config_text =
            fs::read_to_string(runtime.working_directory.join("supabase/config.toml"))
                .expect("read generated config");
        let config = toml::from_str::<Value>(&config_text).expect("parse generated config");
        assert_eq!(
            config["project_id"].as_str(),
            Some(runtime.project_id.as_str())
        );
        for (path, expected) in [
            (&["api", "port"][..], 20_000),
            (&["db", "port"][..], 20_001),
            (&["db", "shadow_port"][..], 20_002),
            (&["db", "pooler", "port"][..], 20_003),
            (&["studio", "port"][..], 20_004),
            (&["local_smtp", "port"][..], 20_005),
            (&["local_smtp", "smtp_port"][..], 20_006),
            (&["local_smtp", "pop3_port"][..], 20_007),
            (&["edge_runtime", "inspector_port"][..], 20_008),
            (&["analytics", "port"][..], 20_009),
            (&["analytics", "vector_port"][..], 20_010),
        ] {
            let value = path.iter().fold(&config, |value, key| &value[*key]);
            assert_eq!(
                value.as_integer(),
                Some(expected),
                "wrong value at {path:?}"
            );
        }
    }

    #[test]
    fn rejects_a_symlinked_config_without_touching_its_target() {
        let temp = tempdir().expect("create temp directory");
        let source = temp.path().join("source");
        let supabase = source.join("supabase");
        fs::create_dir_all(&supabase).expect("create Supabase source");
        let external = temp.path().join("shared-config.toml");
        let original = "project_id = \"shared\"\n";
        fs::write(&external, original).expect("write shared config");
        symlink(&external, supabase.join("config.toml")).expect("link shared config");

        let state = StatePaths::from_root(temp.path().join("state"));
        let instance_id = Uuid::new_v4();
        let error = materialize(
            &source,
            &state,
            instance_id,
            Uuid::new_v4(),
            &BTreeMap::from([("supabase.api".to_owned(), 20_000)]),
        )
        .expect_err("reject symlinked config");

        assert!(
            matches!(error, super::SupabaseError::UnsupportedSymlink(path) if path == supabase.join("config.toml"))
        );
        assert_eq!(
            fs::read_to_string(&external).expect("read shared config"),
            original
        );
        assert!(!state.runtimes().join(instance_id.to_string()).exists());
    }
}
