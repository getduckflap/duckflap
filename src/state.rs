use std::{
    env, fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use thiserror::Error;

pub const STATE_DIR_ENV: &str = "DUCKFLAP_STATE_DIR";
pub const REGISTRY_FILE: &str = "registry.sqlite3";
pub const SESSIONS_DIR: &str = "sessions";
pub const RUNTIMES_DIR: &str = "runtimes";

pub fn ensure_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

pub fn make_file_private(path: &Path) -> io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatePaths {
    root: PathBuf,
    registry: PathBuf,
}

impl StatePaths {
    pub fn discover() -> Result<Self, StateError> {
        let root = resolve_state_dir_for(
            env::var_os(STATE_DIR_ENV).map(PathBuf::from),
            env::var_os("XDG_STATE_HOME").map(PathBuf::from),
            env::var_os("HOME").map(PathBuf::from),
            current_platform()?,
        )?;

        Ok(Self::from_root(root))
    }

    pub fn from_root(root: PathBuf) -> Self {
        let registry = root.join(REGISTRY_FILE);
        Self { root, registry }
    }

    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    pub fn registry(&self) -> &std::path::Path {
        &self.registry
    }

    pub fn sessions(&self) -> PathBuf {
        self.root.join(SESSIONS_DIR)
    }

    pub fn runtimes(&self) -> PathBuf {
        self.root.join(RUNTIMES_DIR)
    }
}

#[derive(Debug, Error)]
pub enum StateError {
    #[error("{variable} must be an absolute path, got {path:?}")]
    RelativePath {
        variable: &'static str,
        path: PathBuf,
    },

    #[error("HOME is not set")]
    MissingHome,

    #[error("Duckflap does not support this operating system yet")]
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum Platform {
    MacOs,
    Linux,
}

#[cfg(target_os = "macos")]
fn current_platform() -> Result<Platform, StateError> {
    Ok(Platform::MacOs)
}

#[cfg(target_os = "linux")]
fn current_platform() -> Result<Platform, StateError> {
    Ok(Platform::Linux)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn current_platform() -> Result<Platform, StateError> {
    Err(StateError::UnsupportedPlatform)
}

fn resolve_state_dir_for(
    override_dir: Option<PathBuf>,
    xdg_state_home: Option<PathBuf>,
    home: Option<PathBuf>,
    platform: Platform,
) -> Result<PathBuf, StateError> {
    if let Some(path) = override_dir {
        return require_absolute(STATE_DIR_ENV, path);
    }

    match platform {
        Platform::MacOs => {
            let home = home.ok_or(StateError::MissingHome)?;
            Ok(require_absolute("HOME", home)?.join("Library/Application Support/duckflap"))
        }
        Platform::Linux => match xdg_state_home {
            Some(path) => Ok(require_absolute("XDG_STATE_HOME", path)?.join("duckflap")),
            None => {
                let home = home.ok_or(StateError::MissingHome)?;
                Ok(require_absolute("HOME", home)?.join(".local/state/duckflap"))
            }
        },
    }
}

fn require_absolute(variable: &'static str, path: PathBuf) -> Result<PathBuf, StateError> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(StateError::RelativePath { variable, path })
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{Platform, REGISTRY_FILE, StatePaths, resolve_state_dir_for};

    #[test]
    fn explicit_override_wins() {
        let root = resolve_state_dir_for(
            Some(PathBuf::from("/tmp/duckflap-test")),
            Some(PathBuf::from("/tmp/xdg")),
            Some(PathBuf::from("/home/test")),
            Platform::Linux,
        )
        .expect("resolve state dir");

        assert_eq!(root, PathBuf::from("/tmp/duckflap-test"));
        assert_eq!(
            StatePaths::from_root(root).registry(),
            PathBuf::from("/tmp/duckflap-test").join(REGISTRY_FILE)
        );
    }

    #[test]
    fn linux_uses_xdg_state_home() {
        let root = resolve_state_dir_for(
            None,
            Some(PathBuf::from("/var/state")),
            None,
            Platform::Linux,
        )
        .expect("resolve state dir");

        assert_eq!(root, PathBuf::from("/var/state/duckflap"));
    }

    #[test]
    fn macos_uses_application_support() {
        let root = resolve_state_dir_for(
            None,
            None,
            Some(PathBuf::from("/Users/test")),
            Platform::MacOs,
        )
        .expect("resolve state dir");

        assert_eq!(
            root,
            PathBuf::from("/Users/test/Library/Application Support/duckflap")
        );
    }
}
