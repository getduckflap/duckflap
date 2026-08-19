use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    string::FromUtf8Error,
};

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitLocation {
    worktree_root: PathBuf,
    git_common_dir: PathBuf,
    worktree_git_dir: PathBuf,
}

impl GitLocation {
    pub fn discover(cwd: impl AsRef<Path>) -> Result<Self, IdentityError> {
        let cwd = cwd.as_ref();

        Ok(Self {
            worktree_root: git_path(cwd, "--show-toplevel")?,
            git_common_dir: git_path(cwd, "--git-common-dir")?,
            worktree_git_dir: git_path(cwd, "--git-dir")?,
        })
    }

    pub fn worktree_root(&self) -> &Path {
        &self.worktree_root
    }

    pub fn git_common_dir(&self) -> &Path {
        &self.git_common_dir
    }

    pub fn worktree_git_dir(&self) -> &Path {
        &self.worktree_git_dir
    }
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("failed to run git: {0}")]
    GitUnavailable(#[from] io::Error),

    #[error("{cwd:?} is not a Git worktree: {message}")]
    NotWorktree { cwd: PathBuf, message: String },

    #[error("git returned a non-UTF-8 path: {0}")]
    NonUtf8Path(#[from] FromUtf8Error),

    #[error("git returned an empty path for {flag}")]
    EmptyPath { flag: &'static str },

    #[error("failed to canonicalise Git path {path:?}: {source}")]
    Canonicalize { path: PathBuf, source: io::Error },
}

fn git_path(cwd: &Path, flag: &'static str) -> Result<PathBuf, IdentityError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(cwd)
        .args(["rev-parse", "--path-format=absolute", flag])
        .output()?;

    if !output.status.success() {
        return Err(IdentityError::NotWorktree {
            cwd: cwd.to_path_buf(),
            message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }

    let mut bytes = output.stdout;
    while matches!(bytes.last(), Some(b'\n' | b'\r')) {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(IdentityError::EmptyPath { flag });
    }

    let path = PathBuf::from(String::from_utf8(bytes)?);
    fs::canonicalize(&path).map_err(|source| IdentityError::Canonicalize { path, source })
}

#[cfg(test)]
mod tests {
    use std::{fs, process::Command};

    use tempfile::tempdir;

    use super::GitLocation;

    #[test]
    fn discovers_an_initialized_repository() {
        let temp = tempdir().expect("create temp dir");
        let repo = temp.path().join("repo");
        fs::create_dir(&repo).expect("create repo dir");
        let status = Command::new("git")
            .args(["init", "--quiet"])
            .arg(&repo)
            .status()
            .expect("run git init");
        assert!(status.success());

        let location = GitLocation::discover(&repo).expect("discover Git location");

        assert_eq!(
            location.worktree_root(),
            fs::canonicalize(&repo).expect("canonical repo")
        );
        assert_eq!(location.git_common_dir(), location.worktree_git_dir());
    }

    #[test]
    fn linked_worktrees_share_a_project_but_not_an_instance_locator() {
        let temp = tempdir().expect("create temp dir");
        let repo = temp.path().join("repo");
        let linked = temp.path().join("linked");
        fs::create_dir(&repo).expect("create repo dir");
        assert!(
            Command::new("git")
                .args(["init", "--quiet"])
                .arg(&repo)
                .status()
                .expect("run git init")
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args([
                    "-c",
                    "user.name=Duckflap Tests",
                    "-c",
                    "user.email=tests@duckflap.invalid",
                    "commit",
                    "--quiet",
                    "--allow-empty",
                    "-m",
                    "initial",
                ])
                .status()
                .expect("create initial commit")
                .success()
        );
        assert!(
            Command::new("git")
                .arg("-C")
                .arg(&repo)
                .args(["worktree", "add", "--quiet", "--detach"])
                .arg(&linked)
                .arg("HEAD")
                .status()
                .expect("create linked worktree")
                .success()
        );

        let primary = GitLocation::discover(&repo).expect("discover primary worktree");
        let secondary = GitLocation::discover(&linked).expect("discover linked worktree");

        assert_eq!(primary.git_common_dir(), secondary.git_common_dir());
        assert_ne!(primary.worktree_git_dir(), secondary.worktree_git_dir());
        assert_ne!(primary.worktree_root(), secondary.worktree_root());
    }
}
