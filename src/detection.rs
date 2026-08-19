use std::{collections::BTreeMap, env, fs, io, path::Path, path::PathBuf};

use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceRequirement {
    pub service_key: String,
    pub protocol: Protocol,
    pub port: PortRequirement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedProject {
    pub services: Vec<ServiceRequirement>,
    pub launch: Option<LaunchRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequirement {
    pub program: PathBuf,
    pub arguments: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortRequirement {
    Dynamic,
}

pub fn detect_project(worktree_root: &Path) -> Result<Option<DetectedProject>, DetectionError> {
    let next = detect_nextjs(worktree_root)?;
    let supabase_services = detect_supabase(worktree_root)?;

    if next.is_none() && supabase_services.is_none() {
        return Ok(None);
    }

    let mut services = next
        .as_ref()
        .map(|_| vec![dynamic_tcp_service("web")])
        .unwrap_or_default();
    services.extend(supabase_services.unwrap_or_default());

    Ok(Some(DetectedProject {
        services,
        launch: next,
    }))
}

fn detect_nextjs(worktree_root: &Path) -> Result<Option<LaunchRequirement>, DetectionError> {
    let manifest_path = worktree_root.join("package.json");
    let bytes = match fs::read(&manifest_path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(DetectionError::ReadManifest {
                path: manifest_path,
                source,
            });
        }
    };
    let manifest = serde_json::from_slice::<PackageJson>(&bytes).map_err(|source| {
        DetectionError::InvalidManifest {
            path: manifest_path,
            source,
        }
    })?;

    if !manifest.dependencies.contains_key("next")
        && !manifest.dev_dependencies.contains_key("next")
    {
        return Ok(None);
    }

    let Some(script) = manifest.scripts.get("dev") else {
        return Ok(None);
    };
    if script.trim().is_empty() {
        return Ok(None);
    }
    if has_unsupported_shell_syntax(script) {
        return Err(DetectionError::AmbiguousDevScript {
            script: script.to_owned(),
        });
    }

    let tokens = script.split_whitespace().collect::<Vec<_>>();
    if tokens.first() != Some(&"next") || tokens.get(1) != Some(&"dev") {
        return Err(DetectionError::AmbiguousDevScript {
            script: script.to_owned(),
        });
    }
    if tokens.iter().skip(2).any(|token| is_port_argument(token)) {
        return Err(DetectionError::ExplicitPort {
            script: script.to_owned(),
        });
    }
    if tokens
        .iter()
        .skip(2)
        .any(|token| is_hostname_argument(token))
    {
        return Err(DetectionError::ExplicitHostname {
            script: script.to_owned(),
        });
    }

    let mut arguments = vec![
        "dev".to_owned(),
        "--hostname".to_owned(),
        "127.0.0.1".to_owned(),
    ];
    arguments.extend(tokens.iter().skip(2).map(|token| (*token).to_owned()));

    Ok(Some(LaunchRequirement {
        program: worktree_root.join("node_modules/.bin/next"),
        arguments,
    }))
}

fn detect_supabase(
    worktree_root: &Path,
) -> Result<Option<Vec<ServiceRequirement>>, DetectionError> {
    let config_path = worktree_root.join("supabase/config.toml");
    let contents = match fs::read_to_string(&config_path) {
        Ok(contents) => contents,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(DetectionError::ReadSupabaseConfig {
                path: config_path,
                source,
            });
        }
    };
    let config = toml::from_str::<SupabaseConfig>(&contents).map_err(|source| {
        DetectionError::InvalidSupabaseConfig {
            path: config_path.clone(),
            source,
        }
    })?;

    if config.inbucket.is_some() && config.local_smtp.is_some() {
        return Err(DetectionError::AmbiguousSupabaseMailConfig { path: config_path });
    }

    let mut environment = SupabaseEnvironment::new(worktree_root, &config_path);
    let api_enabled = resolve_bool(
        config.api.enabled.as_ref(),
        true,
        "api.enabled",
        &mut environment,
    )?;
    resolve_port(config.api.port.as_ref(), "api.port", &mut environment)?;
    let api_tls_enabled = resolve_bool(
        config.api.tls.enabled.as_ref(),
        false,
        "api.tls.enabled",
        &mut environment,
    )?;
    if api_tls_enabled {
        return Err(DetectionError::UnsupportedSupabaseTls { path: config_path });
    }

    resolve_port(config.db.port.as_ref(), "db.port", &mut environment)?;
    resolve_port(
        config.db.shadow_port.as_ref(),
        "db.shadow_port",
        &mut environment,
    )?;
    let pooler_enabled = resolve_bool(
        config.db.pooler.enabled.as_ref(),
        false,
        "db.pooler.enabled",
        &mut environment,
    )?;
    resolve_port(
        config.db.pooler.port.as_ref(),
        "db.pooler.port",
        &mut environment,
    )?;
    let studio_enabled = resolve_bool(
        config.studio.enabled.as_ref(),
        true,
        "studio.enabled",
        &mut environment,
    )?;
    resolve_port(config.studio.port.as_ref(), "studio.port", &mut environment)?;

    let (mail, mail_prefix) = match (&config.inbucket, &config.local_smtp) {
        (Some(mail), None) => (Some(mail), "inbucket"),
        (None, Some(mail)) => (Some(mail), "local_smtp"),
        (None, None) => (None, "inbucket"),
        (Some(_), Some(_)) => unreachable!("ambiguous mail config was rejected"),
    };
    let mail_enabled = resolve_bool(
        mail.and_then(|mail| mail.enabled.as_ref()),
        true,
        &format!("{mail_prefix}.enabled"),
        &mut environment,
    )?;
    resolve_port(
        mail.and_then(|mail| mail.port.as_ref()),
        &format!("{mail_prefix}.port"),
        &mut environment,
    )?;
    let smtp_enabled = resolve_port(
        mail.and_then(|mail| mail.smtp_port.as_ref()),
        &format!("{mail_prefix}.smtp_port"),
        &mut environment,
    )?
    .is_some();
    let pop3_enabled = resolve_port(
        mail.and_then(|mail| mail.pop3_port.as_ref()),
        &format!("{mail_prefix}.pop3_port"),
        &mut environment,
    )?
    .is_some();

    let edge_runtime_enabled = resolve_bool(
        config.edge_runtime.enabled.as_ref(),
        true,
        "edge_runtime.enabled",
        &mut environment,
    )?;
    resolve_port(
        config.edge_runtime.inspector_port.as_ref(),
        "edge_runtime.inspector_port",
        &mut environment,
    )?;
    let analytics_enabled = resolve_bool(
        config.analytics.enabled.as_ref(),
        false,
        "analytics.enabled",
        &mut environment,
    )?;
    resolve_port(
        config.analytics.port.as_ref(),
        "analytics.port",
        &mut environment,
    )?;
    resolve_port(
        config.analytics.vector_port.as_ref(),
        "analytics.vector_port",
        &mut environment,
    )?;

    let mut services = Vec::new();
    if api_enabled {
        services.push(dynamic_tcp_service("supabase.api"));
    }
    services.push(dynamic_tcp_service("supabase.db"));
    services.push(dynamic_tcp_service("supabase.db.shadow"));
    if pooler_enabled {
        services.push(dynamic_tcp_service("supabase.pooler"));
    }
    if studio_enabled {
        services.push(dynamic_tcp_service("supabase.studio"));
    }

    if mail_enabled {
        services.push(dynamic_tcp_service("supabase.mail"));
        if smtp_enabled {
            services.push(dynamic_tcp_service("supabase.mail.smtp"));
        }
        if pop3_enabled {
            services.push(dynamic_tcp_service("supabase.mail.pop3"));
        }
    }
    if edge_runtime_enabled {
        services.push(dynamic_tcp_service("supabase.edge_inspector"));
    }
    if analytics_enabled {
        services.push(dynamic_tcp_service("supabase.analytics"));
        services.push(dynamic_tcp_service("supabase.analytics.vector"));
    }

    Ok(Some(services))
}

fn dynamic_tcp_service(service_key: &str) -> ServiceRequirement {
    ServiceRequirement {
        service_key: service_key.to_owned(),
        protocol: Protocol::Tcp,
        port: PortRequirement::Dynamic,
    }
}

#[derive(Debug, Error)]
pub enum DetectionError {
    #[error("failed to read package manifest {path:?}: {source}")]
    ReadManifest {
        path: std::path::PathBuf,
        source: io::Error,
    },

    #[error("package manifest {path:?} is invalid: {source}")]
    InvalidManifest {
        path: std::path::PathBuf,
        source: serde_json::Error,
    },

    #[error("failed to read local Supabase config {path:?}: {source}")]
    ReadSupabaseConfig {
        path: std::path::PathBuf,
        source: io::Error,
    },

    #[error("local Supabase config {path:?} is invalid: {source}")]
    InvalidSupabaseConfig {
        path: std::path::PathBuf,
        source: toml::de::Error,
    },

    #[error("failed to read Supabase environment file {path:?}: {source}")]
    ReadSupabaseEnvironment {
        path: std::path::PathBuf,
        source: io::Error,
    },

    #[error("Supabase environment file {path:?} is invalid")]
    InvalidSupabaseEnvironmentFile { path: std::path::PathBuf },

    #[error(
        "local Supabase config {path:?} field {field} must be a {expected} literal or exact env(NAME) reference"
    )]
    InvalidSupabaseField {
        path: std::path::PathBuf,
        field: String,
        expected: &'static str,
    },

    #[error(
        "local Supabase config {path:?} field {field} references missing environment variable {variable}"
    )]
    MissingSupabaseEnvironment {
        path: std::path::PathBuf,
        field: String,
        variable: String,
    },

    #[error(
        "environment variable {variable} used by local Supabase config {path:?} field {field} must contain a {expected}"
    )]
    InvalidSupabaseEnvironment {
        path: std::path::PathBuf,
        field: String,
        variable: String,
        expected: &'static str,
    },

    #[error(
        "local Supabase config {path:?} enables [api.tls], which Duckflap does not support yet"
    )]
    UnsupportedSupabaseTls { path: std::path::PathBuf },

    #[error(
        "local Supabase config {path:?} contains both [inbucket] and [local_smtp]; keep only the section supported by the installed Supabase CLI"
    )]
    AmbiguousSupabaseMailConfig { path: std::path::PathBuf },

    #[error("Next.js dev script is ambiguous and cannot be allocated automatically: {script}")]
    AmbiguousDevScript { script: String },

    #[error("Next.js dev script fixes its own port and cannot use a dynamic allocation: {script}")]
    ExplicitPort { script: String },

    #[error(
        "Next.js dev script fixes its own hostname and cannot use Duckflap's IPv4 loopback binding: {script}"
    )]
    ExplicitHostname { script: String },
}

#[derive(Debug, Deserialize)]
struct PackageJson {
    #[serde(default)]
    dependencies: BTreeMap<String, Value>,
    #[serde(default, rename = "devDependencies")]
    dev_dependencies: BTreeMap<String, Value>,
    #[serde(default)]
    scripts: BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
struct SupabaseConfig {
    #[serde(default)]
    api: ApiSection,
    #[serde(default)]
    db: DatabaseSection,
    #[serde(default)]
    studio: EnabledPortSection,
    inbucket: Option<MailSection>,
    local_smtp: Option<MailSection>,
    #[serde(default)]
    edge_runtime: EdgeRuntimeSection,
    #[serde(default)]
    analytics: AnalyticsSection,
}

#[derive(Debug, Default, Deserialize)]
struct ApiSection {
    enabled: Option<SupabaseBool>,
    port: Option<SupabasePort>,
    #[serde(default)]
    tls: TlsSection,
}

#[derive(Debug, Default, Deserialize)]
struct EnabledPortSection {
    enabled: Option<SupabaseBool>,
    port: Option<SupabasePort>,
}

#[derive(Debug, Default, Deserialize)]
struct DatabaseSection {
    port: Option<SupabasePort>,
    shadow_port: Option<SupabasePort>,
    #[serde(default)]
    pooler: EnabledPortSection,
}

#[derive(Debug, Default, Deserialize)]
struct MailSection {
    enabled: Option<SupabaseBool>,
    port: Option<SupabasePort>,
    smtp_port: Option<SupabasePort>,
    pop3_port: Option<SupabasePort>,
}

#[derive(Debug, Default, Deserialize)]
struct EdgeRuntimeSection {
    enabled: Option<SupabaseBool>,
    inspector_port: Option<SupabasePort>,
}

#[derive(Debug, Default, Deserialize)]
struct AnalyticsSection {
    enabled: Option<SupabaseBool>,
    port: Option<SupabasePort>,
    vector_port: Option<SupabasePort>,
}

#[derive(Debug, Default, Deserialize)]
struct TlsSection {
    enabled: Option<SupabaseBool>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SupabaseBool {
    Literal(bool),
    Environment(String),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SupabasePort {
    Literal(u16),
    Environment(String),
}

struct SupabaseEnvironment<'a> {
    worktree_root: &'a Path,
    config_path: &'a Path,
    file_values: Option<BTreeMap<String, String>>,
}

impl<'a> SupabaseEnvironment<'a> {
    fn new(worktree_root: &'a Path, config_path: &'a Path) -> Self {
        Self {
            worktree_root,
            config_path,
            file_values: None,
        }
    }

    fn resolve(&mut self, variable: &str, field: &str) -> Result<String, DetectionError> {
        match env::var(variable) {
            Ok(value) => return Ok(value),
            Err(env::VarError::NotUnicode(_)) => {
                return Err(DetectionError::InvalidSupabaseEnvironment {
                    path: self.config_path.to_path_buf(),
                    field: field.to_owned(),
                    variable: variable.to_owned(),
                    expected: "Unicode value",
                });
            }
            Err(env::VarError::NotPresent) => {}
        }

        if self.file_values.is_none() {
            self.file_values = Some(load_supabase_environment(self.worktree_root)?);
        }
        self.file_values
            .as_ref()
            .and_then(|values| values.get(variable))
            .cloned()
            .ok_or_else(|| DetectionError::MissingSupabaseEnvironment {
                path: self.config_path.to_path_buf(),
                field: field.to_owned(),
                variable: variable.to_owned(),
            })
    }
}

fn load_supabase_environment(
    worktree_root: &Path,
) -> Result<BTreeMap<String, String>, DetectionError> {
    let path = worktree_root.join(".env");
    let iterator = match dotenvy::from_path_iter(&path) {
        Ok(iterator) => iterator,
        Err(source) if source.not_found() => return Ok(BTreeMap::new()),
        Err(source) => return Err(supabase_environment_file_error(path, source)),
    };
    let mut values = BTreeMap::new();
    for item in iterator {
        let (key, value) =
            item.map_err(|source| supabase_environment_file_error(path.clone(), source))?;
        values.insert(key, value);
    }
    Ok(values)
}

fn supabase_environment_file_error(path: PathBuf, source: dotenvy::Error) -> DetectionError {
    match source {
        dotenvy::Error::Io(source) => DetectionError::ReadSupabaseEnvironment { path, source },
        _ => DetectionError::InvalidSupabaseEnvironmentFile { path },
    }
}

fn resolve_bool(
    value: Option<&SupabaseBool>,
    default: bool,
    field: &str,
    environment: &mut SupabaseEnvironment<'_>,
) -> Result<bool, DetectionError> {
    let Some(value) = value else {
        return Ok(default);
    };
    match value {
        SupabaseBool::Literal(value) => Ok(*value),
        SupabaseBool::Environment(reference) => {
            let variable = parse_env_reference(reference).ok_or_else(|| {
                DetectionError::InvalidSupabaseField {
                    path: environment.config_path.to_path_buf(),
                    field: field.to_owned(),
                    expected: "boolean",
                }
            })?;
            let resolved = environment.resolve(variable, field)?;
            match resolved.trim() {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(DetectionError::InvalidSupabaseEnvironment {
                    path: environment.config_path.to_path_buf(),
                    field: field.to_owned(),
                    variable: variable.to_owned(),
                    expected: "boolean",
                }),
            }
        }
    }
}

fn resolve_port(
    value: Option<&SupabasePort>,
    field: &str,
    environment: &mut SupabaseEnvironment<'_>,
) -> Result<Option<u16>, DetectionError> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        SupabasePort::Literal(port) => Ok(Some(*port)),
        SupabasePort::Environment(reference) => {
            let variable = parse_env_reference(reference).ok_or_else(|| {
                DetectionError::InvalidSupabaseField {
                    path: environment.config_path.to_path_buf(),
                    field: field.to_owned(),
                    expected: "TCP port",
                }
            })?;
            let resolved = environment.resolve(variable, field)?;
            resolved.trim().parse::<u16>().map(Some).map_err(|_| {
                DetectionError::InvalidSupabaseEnvironment {
                    path: environment.config_path.to_path_buf(),
                    field: field.to_owned(),
                    variable: variable.to_owned(),
                    expected: "TCP port",
                }
            })
        }
    }
}

fn parse_env_reference(reference: &str) -> Option<&str> {
    let variable = reference.strip_prefix("env(")?.strip_suffix(')')?;
    let mut bytes = variable.bytes();
    let first = bytes.next()?;
    if !first.is_ascii_uppercase() && first != b'_' {
        return None;
    }
    bytes
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        .then_some(variable)
}

fn has_unsupported_shell_syntax(script: &str) -> bool {
    script.bytes().any(|byte| {
        !byte.is_ascii_alphanumeric()
            && !matches!(
                byte,
                b' ' | b'\t' | b'-' | b'.' | b'_' | b'/' | b':' | b'=' | b',' | b'@' | b'+'
            )
    })
}

fn is_port_argument(token: &str) -> bool {
    token == "-p"
        || token == "--port"
        || token.starts_with("-p=")
        || token.starts_with("--port=")
        || token.strip_prefix("-p").is_some_and(|value| {
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn is_hostname_argument(token: &str) -> bool {
    token == "-H"
        || token == "--hostname"
        || token.starts_with("-H=")
        || token.starts_with("--hostname=")
        || token
            .strip_prefix("-H")
            .is_some_and(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{DetectionError, PortRequirement, Protocol, detect_project};

    #[test]
    fn detects_a_root_nextjs_dev_script() {
        let temp = tempdir().expect("create temp dir");
        write_manifest(
            temp.path(),
            r#"{
                "dependencies": { "next": "latest" },
                "scripts": { "dev": "next dev --turbopack" }
            }"#,
        );

        let detected = detect_project(temp.path())
            .expect("detect project")
            .expect("Next.js project");
        let services = &detected.services;

        assert_eq!(services.len(), 1);
        assert_eq!(services[0].service_key, "web");
        assert_eq!(services[0].protocol, Protocol::Tcp);
        assert_eq!(services[0].port, PortRequirement::Dynamic);
        let launch = detected.launch.expect("Next.js launch requirement");
        assert_eq!(launch.program, temp.path().join("node_modules/.bin/next"));
        assert_eq!(
            launch.arguments,
            ["dev", "--hostname", "127.0.0.1", "--turbopack"]
        );
    }

    #[test]
    fn detects_next_in_dev_dependencies() {
        let temp = tempdir().expect("create temp dir");
        write_manifest(
            temp.path(),
            r#"{
                "devDependencies": { "next": "latest" },
                "scripts": { "dev": "next dev" }
            }"#,
        );

        assert_eq!(
            detect_project(temp.path())
                .expect("detect project")
                .expect("Next.js project")
                .services
                .len(),
            1,
        );
    }

    #[test]
    fn missing_manifest_or_required_fields_detects_nothing() {
        let temp = tempdir().expect("create temp dir");
        assert!(
            detect_project(temp.path())
                .expect("missing manifest")
                .is_none()
        );

        write_manifest(
            temp.path(),
            r#"{
                "dependencies": { "react": "latest" },
                "scripts": { "dev": "next dev" }
            }"#,
        );
        assert!(
            detect_project(temp.path())
                .expect("missing dependency")
                .is_none()
        );

        write_manifest(temp.path(), r#"{ "dependencies": { "next": "latest" } }"#);
        assert!(
            detect_project(temp.path())
                .expect("missing script")
                .is_none()
        );
    }

    #[test]
    fn malformed_manifest_is_an_error() {
        let temp = tempdir().expect("create temp dir");
        write_manifest(temp.path(), "{");

        assert!(matches!(
            detect_project(temp.path()).expect_err("reject malformed manifest"),
            DetectionError::InvalidManifest { .. }
        ));
    }

    #[test]
    fn wrappers_and_compound_commands_are_ambiguous() {
        for script in [
            "cross-env NODE_ENV=development next dev",
            "next dev && generate-client",
            "next dev | logger",
            "next dev; generate-client",
            "next dev $(custom-args)",
            "next dev \"-p\" 3000",
            "next dev '--port' 3000",
            "next dev \\-p 3000",
            "next dev $NEXT_ARGS",
            "next dev -p$DEV_PORT",
            "next dev *",
            "next dev --turbo{,pack}",
        ] {
            let temp = tempdir().expect("create temp dir");
            write_next_manifest(temp.path(), script);

            assert!(matches!(
                detect_project(temp.path()).expect_err("reject ambiguous script"),
                DetectionError::AmbiguousDevScript { .. }
            ));
        }
    }

    #[test]
    fn explicit_port_arguments_are_rejected() {
        for script in [
            "next dev -p 3000",
            "next dev -p=3000",
            "next dev -p3000",
            "next dev --port 3000",
            "next dev --port=3000",
        ] {
            let temp = tempdir().expect("create temp dir");
            write_next_manifest(temp.path(), script);

            assert!(matches!(
                detect_project(temp.path()).expect_err("reject explicit port"),
                DetectionError::ExplicitPort { .. }
            ));
        }
    }

    #[test]
    fn explicit_hostname_arguments_are_rejected() {
        for script in [
            "next dev -H localhost",
            "next dev -H=localhost",
            "next dev -Hlocalhost",
            "next dev --hostname localhost",
            "next dev --hostname=localhost",
        ] {
            let temp = tempdir().expect("create temp dir");
            write_next_manifest(temp.path(), script);

            assert!(matches!(
                detect_project(temp.path()).expect_err("reject explicit hostname"),
                DetectionError::ExplicitHostname { .. }
            ));
        }
    }

    #[test]
    fn nested_applications_are_not_searched() {
        let temp = tempdir().expect("create temp dir");
        let nested = temp.path().join("apps/web");
        fs::create_dir_all(&nested).expect("create nested app");
        write_next_manifest(&nested, "next dev");

        assert!(
            detect_project(temp.path())
                .expect("detect root project")
                .is_none()
        );
    }

    #[test]
    fn detects_enabled_local_supabase_listeners() {
        let temp = tempdir().expect("create temp dir");
        write_supabase_config(
            temp.path(),
            r#"
                [api]
                enabled = false
                port = 54321

                [api.tls]
                enabled = false

                [db]
                port = 54322
                shadow_port = 54320

                [db.pooler]
                enabled = true
                port = 54329

                [studio]
                enabled = false

                [local_smtp]
                enabled = true
                port = 54324
                smtp_port = 54325
                pop3_port = 54326

                [edge_runtime]
                enabled = false

                [analytics]
                enabled = true
                port = 54327
                vector_port = 54328
            "#,
        );

        let detected = detect_project(temp.path())
            .expect("detect project")
            .expect("Supabase project");
        let keys = detected
            .services
            .iter()
            .map(|service| service.service_key.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            keys,
            [
                "supabase.db",
                "supabase.db.shadow",
                "supabase.pooler",
                "supabase.mail",
                "supabase.mail.smtp",
                "supabase.mail.pop3",
                "supabase.analytics",
                "supabase.analytics.vector",
            ]
        );
        assert!(detected.launch.is_none());
        assert!(detected.services.iter().all(|service| {
            service.protocol == Protocol::Tcp && service.port == PortRequirement::Dynamic
        }));
    }

    #[test]
    fn resolves_env_backed_supabase_listener_values_from_root_dotenv() {
        let temp = tempdir().expect("create temp dir");
        fs::write(
            temp.path().join(".env"),
            "DUCKFLAP_TEST_API_ENABLED=false\n\
             DUCKFLAP_TEST_API_PORT=54321\n\
             DUCKFLAP_TEST_TLS_ENABLED=false\n\
             DUCKFLAP_TEST_POOLER_ENABLED=true\n\
             DUCKFLAP_TEST_POOLER_PORT=54329\n\
             DUCKFLAP_TEST_STUDIO_ENABLED=false\n\
             DUCKFLAP_TEST_MAIL_ENABLED=true\n\
             DUCKFLAP_TEST_SMTP_PORT=54325\n\
             DUCKFLAP_TEST_EDGE_ENABLED=false\n\
             DUCKFLAP_TEST_ANALYTICS_ENABLED=true\n\
             DUCKFLAP_TEST_VECTOR_PORT=54328\n",
        )
        .expect("write root environment");
        write_supabase_config(
            temp.path(),
            r#"
                [api]
                enabled = "env(DUCKFLAP_TEST_API_ENABLED)"
                port = "env(DUCKFLAP_TEST_API_PORT)"

                [api.tls]
                enabled = "env(DUCKFLAP_TEST_TLS_ENABLED)"

                [db]
                port = 54322
                shadow_port = 54320

                [db.pooler]
                enabled = "env(DUCKFLAP_TEST_POOLER_ENABLED)"
                port = "env(DUCKFLAP_TEST_POOLER_PORT)"

                [studio]
                enabled = "env(DUCKFLAP_TEST_STUDIO_ENABLED)"

                [inbucket]
                enabled = "env(DUCKFLAP_TEST_MAIL_ENABLED)"
                smtp_port = "env(DUCKFLAP_TEST_SMTP_PORT)"

                [edge_runtime]
                enabled = "env(DUCKFLAP_TEST_EDGE_ENABLED)"

                [analytics]
                enabled = "env(DUCKFLAP_TEST_ANALYTICS_ENABLED)"
                vector_port = "env(DUCKFLAP_TEST_VECTOR_PORT)"
            "#,
        );

        let detected = detect_project(temp.path())
            .expect("detect env-backed Supabase project")
            .expect("Supabase project");
        let keys = detected
            .services
            .iter()
            .map(|service| service.service_key.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            keys,
            [
                "supabase.db",
                "supabase.db.shadow",
                "supabase.pooler",
                "supabase.mail",
                "supabase.mail.smtp",
                "supabase.analytics",
                "supabase.analytics.vector",
            ]
        );
    }

    #[test]
    fn later_dotenv_assignments_override_earlier_values() {
        let temp = tempdir().expect("create temp dir");
        fs::write(
            temp.path().join(".env"),
            "DUCKFLAP_TEST_DUPLICATE_API_ENABLED=true\n\
             DUCKFLAP_TEST_DUPLICATE_API_ENABLED=false\n\
             DUCKFLAP_TEST_DUPLICATE_TLS_ENABLED=true\n\
             DUCKFLAP_TEST_DUPLICATE_TLS_ENABLED=false\n",
        )
        .expect("write duplicate root environment");
        write_supabase_config(
            temp.path(),
            r#"
                [api]
                enabled = "env(DUCKFLAP_TEST_DUPLICATE_API_ENABLED)"

                [api.tls]
                enabled = "env(DUCKFLAP_TEST_DUPLICATE_TLS_ENABLED)"

                [studio]
                enabled = false

                [inbucket]
                enabled = false

                [edge_runtime]
                enabled = false
            "#,
        );

        let detected = detect_project(temp.path())
            .expect("detect using final duplicate values")
            .expect("Supabase project");
        let keys = detected
            .services
            .iter()
            .map(|service| service.service_key.as_str())
            .collect::<Vec<_>>();

        assert_eq!(keys, ["supabase.db", "supabase.db.shadow"]);
    }

    #[test]
    fn rejects_missing_or_invalid_supabase_environment_values() {
        let missing = tempdir().expect("create missing-value temp dir");
        write_supabase_config(
            missing.path(),
            "[api]\nenabled = \"env(DUCKFLAP_TEST_MISSING_ENABLED_019FF1C9)\"",
        );
        assert!(matches!(
            detect_project(missing.path()).expect_err("reject missing environment value"),
            DetectionError::MissingSupabaseEnvironment { .. }
        ));

        let invalid = tempdir().expect("create invalid-value temp dir");
        fs::write(
            invalid.path().join(".env"),
            "DUCKFLAP_TEST_INVALID_PORT=not-a-port\n",
        )
        .expect("write invalid root environment");
        write_supabase_config(
            invalid.path(),
            "[api]\nport = \"env(DUCKFLAP_TEST_INVALID_PORT)\"",
        );
        assert!(matches!(
            detect_project(invalid.path()).expect_err("reject invalid environment value"),
            DetectionError::InvalidSupabaseEnvironment { .. }
        ));

        let malformed_file = tempdir().expect("create malformed-file temp dir");
        fs::write(
            malformed_file.path().join(".env"),
            "DUCKFLAP_TEST_SECRET=\"unterminated\n",
        )
        .expect("write malformed root environment");
        write_supabase_config(
            malformed_file.path(),
            "[api]\nenabled = \"env(DUCKFLAP_TEST_SECRET)\"",
        );
        assert!(matches!(
            detect_project(malformed_file.path()).expect_err("reject malformed environment file"),
            DetectionError::InvalidSupabaseEnvironmentFile { .. }
        ));
    }

    #[test]
    fn rejects_literal_and_env_backed_supabase_api_tls() {
        let literal = tempdir().expect("create literal TLS temp dir");
        write_supabase_config(literal.path(), "[api.tls]\nenabled = true");
        assert!(matches!(
            detect_project(literal.path()).expect_err("reject literal TLS"),
            DetectionError::UnsupportedSupabaseTls { .. }
        ));

        let env_backed = tempdir().expect("create env-backed TLS temp dir");
        fs::write(
            env_backed.path().join(".env"),
            "DUCKFLAP_TEST_TLS_ENABLED_TRUE=true\n",
        )
        .expect("write TLS environment");
        write_supabase_config(
            env_backed.path(),
            "[api.tls]\nenabled = \"env(DUCKFLAP_TEST_TLS_ENABLED_TRUE)\"",
        );
        assert!(matches!(
            detect_project(env_backed.path()).expect_err("reject env-backed TLS"),
            DetectionError::UnsupportedSupabaseTls { .. }
        ));
    }

    #[test]
    fn merges_nextjs_and_default_supabase_listeners() {
        let temp = tempdir().expect("create temp dir");
        write_next_manifest(temp.path(), "next dev");
        write_supabase_config(temp.path(), "project_id = \"example\"");

        let detected = detect_project(temp.path())
            .expect("detect project")
            .expect("mixed project");
        let keys = detected
            .services
            .iter()
            .map(|service| service.service_key.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            keys,
            [
                "web",
                "supabase.api",
                "supabase.db",
                "supabase.db.shadow",
                "supabase.studio",
                "supabase.mail",
                "supabase.edge_inspector",
            ]
        );
        assert!(detected.launch.is_some());
    }

    #[test]
    fn rejects_invalid_or_ambiguous_supabase_config() {
        let malformed = tempdir().expect("create malformed temp dir");
        write_supabase_config(malformed.path(), "[api\nenabled = true");
        assert!(matches!(
            detect_project(malformed.path()).expect_err("reject malformed config"),
            DetectionError::InvalidSupabaseConfig { .. }
        ));

        let wrong_type = tempdir().expect("create wrong-type temp dir");
        write_supabase_config(wrong_type.path(), "[api]\nenabled = \"yes\"");
        assert!(matches!(
            detect_project(wrong_type.path()).expect_err("reject wrong known type"),
            DetectionError::InvalidSupabaseField { .. }
        ));

        let aliases = tempdir().expect("create aliases temp dir");
        write_supabase_config(
            aliases.path(),
            "[inbucket]\nenabled = true\n[local_smtp]\nenabled = true",
        );
        assert!(matches!(
            detect_project(aliases.path()).expect_err("reject ambiguous mail config"),
            DetectionError::AmbiguousSupabaseMailConfig { .. }
        ));
    }

    fn write_next_manifest(root: &std::path::Path, script: &str) {
        write_manifest(
            root,
            &format!(
                r#"{{
                    "dependencies": {{ "next": "latest" }},
                    "scripts": {{ "dev": {script:?} }}
                }}"#
            ),
        );
    }

    fn write_manifest(root: &std::path::Path, contents: &str) {
        fs::write(root.join("package.json"), contents).expect("write package manifest");
    }

    fn write_supabase_config(root: &std::path::Path, contents: &str) {
        let directory = root.join("supabase");
        fs::create_dir(&directory).expect("create Supabase directory");
        fs::write(directory.join("config.toml"), contents).expect("write Supabase config");
    }
}
