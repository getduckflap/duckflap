use std::{
    collections::BTreeMap,
    io,
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    path::Path,
    process::Command,
    time::Duration,
};

use thiserror::Error;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(100);

#[cfg(target_os = "macos")]
const TRUSTED_LSOF_PATHS: &[&str] = &["/usr/sbin/lsof"];
#[cfg(target_os = "linux")]
const TRUSTED_LSOF_PATHS: &[&str] = &["/usr/bin/lsof", "/usr/sbin/lsof"];
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const TRUSTED_LSOF_PATHS: &[&str] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpPortState {
    Free,
    Occupied,
    Listening,
}

impl TcpPortState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Free => "free",
            Self::Occupied => "occupied",
            Self::Listening => "listening",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEvidence {
    pub available: bool,
    pub processes: Vec<InspectedProcess>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InspectedProcess {
    pub pid: u32,
    pub command: Option<String>,
}

#[derive(Debug, Error)]
pub enum InspectionError {
    #[error("failed to inspect IPv4 TCP port {port}: {source}")]
    Probe { port: u16, source: io::Error },
}

pub fn inspect_ipv4_tcp(port: u16) -> Result<(TcpPortState, ProcessEvidence), InspectionError> {
    let loopback_available = bind_available(Ipv4Addr::LOCALHOST, port)?;
    let unspecified_available = bind_available(Ipv4Addr::UNSPECIFIED, port)?;
    let loopback_reachable = if loopback_available && unspecified_available {
        false
    } else {
        TcpStream::connect_timeout(
            &SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into(),
            CONNECT_TIMEOUT,
        )
        .is_ok()
    };
    let state = classify_ipv4_tcp(
        loopback_available,
        unspecified_available,
        loopback_reachable,
    );
    let evidence = if state == TcpPortState::Free {
        ProcessEvidence {
            available: true,
            processes: Vec::new(),
        }
    } else {
        inspect_processes(port)
    };
    Ok((state, evidence))
}

fn classify_ipv4_tcp(
    loopback_available: bool,
    unspecified_available: bool,
    loopback_reachable: bool,
) -> TcpPortState {
    if loopback_reachable {
        TcpPortState::Listening
    } else if loopback_available && unspecified_available {
        TcpPortState::Free
    } else {
        TcpPortState::Occupied
    }
}

fn bind_available(address: Ipv4Addr, port: u16) -> Result<bool, InspectionError> {
    match TcpListener::bind(SocketAddrV4::new(address, port)) {
        Ok(listener) => {
            drop(listener);
            Ok(true)
        }
        Err(source) if source.kind() == io::ErrorKind::AddrInUse => Ok(false),
        Err(source) => Err(InspectionError::Probe { port, source }),
    }
}

fn inspect_processes(port: u16) -> ProcessEvidence {
    let Some(executable) = trusted_lsof_path() else {
        return ProcessEvidence {
            available: false,
            processes: Vec::new(),
        };
    };

    let output = match Command::new(executable).args(lsof_arguments(port)).output() {
        Ok(output) => output,
        Err(_) => {
            return ProcessEvidence {
                available: false,
                processes: Vec::new(),
            };
        }
    };
    if !output.status.success() {
        return ProcessEvidence {
            available: false,
            processes: Vec::new(),
        };
    }
    ProcessEvidence {
        available: true,
        processes: parse_lsof_fields(&String::from_utf8_lossy(&output.stdout)),
    }
}

fn trusted_lsof_path() -> Option<&'static Path> {
    TRUSTED_LSOF_PATHS
        .iter()
        .copied()
        .map(Path::new)
        .find(|path| path.is_file())
}

fn lsof_arguments(port: u16) -> [String; 4] {
    [
        "-nP".to_owned(),
        format!("-i4TCP:{port}"),
        "-sTCP:LISTEN".to_owned(),
        "-Fpc".to_owned(),
    ]
}

fn parse_lsof_fields(output: &str) -> Vec<InspectedProcess> {
    let mut processes = BTreeMap::<u32, Option<String>>::new();
    let mut current_pid = None;
    for line in output.lines() {
        match line.as_bytes().first() {
            Some(b'p') => {
                current_pid = line[1..].parse::<u32>().ok();
                if let Some(pid) = current_pid {
                    processes.entry(pid).or_default();
                }
            }
            Some(b'c') => {
                if let Some(pid) = current_pid {
                    processes.insert(pid, Some(line[1..].to_owned()));
                }
            }
            _ => {}
        }
    }
    processes
        .into_iter()
        .map(|(pid, command)| InspectedProcess { pid, command })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        InspectedProcess, TRUSTED_LSOF_PATHS, TcpPortState, classify_ipv4_tcp, lsof_arguments,
        parse_lsof_fields,
    };

    #[test]
    fn classifies_ports_by_loopback_reachability() {
        assert_eq!(classify_ipv4_tcp(true, true, false), TcpPortState::Free);
        assert_eq!(
            classify_ipv4_tcp(false, false, true),
            TcpPortState::Listening
        );
        assert_eq!(
            classify_ipv4_tcp(true, false, false),
            TcpPortState::Occupied
        );
        assert_eq!(
            classify_ipv4_tcp(false, true, false),
            TcpPortState::Occupied
        );
    }

    #[test]
    fn process_inspection_uses_trusted_paths_and_ipv4_only() {
        assert!(
            TRUSTED_LSOF_PATHS
                .iter()
                .all(|path| Path::new(path).is_absolute())
        );
        assert_eq!(
            lsof_arguments(20_000),
            ["-nP", "-i4TCP:20000", "-sTCP:LISTEN", "-Fpc"]
        );
    }

    #[test]
    fn parses_and_sorts_lsof_process_fields() {
        assert_eq!(
            parse_lsof_fields("p42\ncnode\np7\ncpostgres\np42\ncnext-server\n"),
            vec![
                InspectedProcess {
                    pid: 7,
                    command: Some("postgres".to_owned()),
                },
                InspectedProcess {
                    pid: 42,
                    command: Some("next-server".to_owned()),
                },
            ]
        );
    }
}
