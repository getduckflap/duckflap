use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs,
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    os::unix::{fs::PermissionsExt, process::ExitStatusExt},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{Mutex, MutexGuard},
    thread,
    time::Duration,
};

use duckflap::{
    registry::Registry,
    runtime::{current_process_identity, terminate_process_group},
    state::StatePaths,
};
use rusqlite::{Connection, params};
use serde_json::Value;
use tempfile::tempdir;

static CLI_TEST_LOCK: Mutex<()> = Mutex::new(());
const FAKE_TCP_LISTENER: &str = r#"exec python3 -c 'import os
import socket
listener = socket.socket()
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", int(os.environ["PORT"])))
listener.listen()
while True:
    connection, _ = listener.accept()
    connection.close()'"#;

#[test]
fn env_json_is_stable_and_leaves_the_worktree_clean() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev --turbopack" }
        }"#,
    );

    let first = run_env(&repo, &state);
    assert!(first.status.success(), "{first:?}");
    assert!(first.stderr.is_empty(), "stderr was not empty: {first:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse first response");
    assert_eq!(first_json["schema_version"], 1);
    assert_eq!(first_json["command"], "env");
    assert_eq!(first_json["ok"], true);
    assert_eq!(first_json["changed"], true);
    assert_eq!(first_json["data"]["services"][0]["service_key"], "web");
    assert_eq!(first_json["data"]["services"][0]["protocol"], "tcp");
    let first_port = first_json["data"]["services"][0]["port"]
        .as_u64()
        .expect("numeric port");
    assert_eq!(
        first_json["data"]["environment"]["PORT"].as_str(),
        Some(first_port.to_string().as_str())
    );
    assert_eq!(
        first_json["data"]["environment"]["DUCKFLAP_WEB_URL"],
        format!("http://127.0.0.1:{first_port}")
    );

    let second = run_env(&repo, &state);
    assert!(second.status.success(), "{second:?}");
    assert!(second.stderr.is_empty(), "stderr was not empty: {second:?}");
    let second_json: Value = serde_json::from_slice(&second.stdout).expect("parse second response");
    assert_eq!(second_json["changed"], false);
    assert_eq!(
        second_json["data"]["project_id"],
        first_json["data"]["project_id"]
    );
    assert_eq!(
        second_json["data"]["project_instance_id"],
        first_json["data"]["project_instance_id"]
    );
    assert_eq!(second_json["data"]["services"][0]["port"], first_port);
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn env_shell_output_is_stable_evaluable_and_git_clean() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );

    let mut outputs = Vec::new();
    for shell in ["sh", "bash", "zsh"] {
        let output = run_env_shell(&repo, &state, shell);
        assert!(output.status.success(), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        outputs.push(String::from_utf8(output.stdout).expect("UTF-8 shell output"));
    }
    assert!(outputs.windows(2).all(|pair| pair[0] == pair[1]));
    let shell_environment = outputs.first().expect("shell environment");
    assert!(shell_environment.starts_with("export DUCKFLAP_WEB_PORT='"));
    assert!(!shell_environment.contains("schema_version"));

    let evaluated = Command::new("/bin/sh")
        .arg("-c")
        .arg("eval \"$1\"\nprintf '%s\\n' \"$PORT\" \"$DUCKFLAP_WEB_PORT\" \"$DUCKFLAP_WEB_URL\"")
        .arg("duckflap-env-test")
        .arg(shell_environment)
        .env("PORT", "9999")
        .output()
        .expect("evaluate shell environment");
    assert!(evaluated.status.success(), "{evaluated:?}");
    assert!(evaluated.stderr.is_empty(), "{evaluated:?}");
    let evaluated = String::from_utf8(evaluated.stdout).expect("UTF-8 evaluated environment");
    let values = evaluated.lines().collect::<Vec<_>>();
    assert_eq!(values.len(), 3);
    assert_eq!(values[0], values[1]);
    assert_ne!(values[0], "9999");
    assert_eq!(values[2], format!("http://127.0.0.1:{}", values[0]));
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn env_rejects_an_unknown_shell_before_creating_state() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );

    let output = run_env_shell(&repo, &state, "fish");
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(!output.stderr.is_empty(), "{output:?}");
    assert!(!state.exists(), "invalid shell created Duckflap state");
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn env_allocates_nextjs_and_local_supabase_without_touching_config() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    let config = r#"
        project_id = "mixed-project"

        [api]
        enabled = true
        port = 54321

        [db]
        port = 54322
        shadow_port = 54320

        [db.pooler]
        enabled = false

        [studio]
        enabled = true

        [local_smtp]
        enabled = true

        [edge_runtime]
        enabled = false

        [analytics]
        enabled = false
    "#;
    add_supabase_config(&repo, config);
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);
    let config_path = repo.join("supabase/config.toml");
    let config_before = fs::read(&config_path).expect("read config before env");

    let first = run_env(&repo, &state);
    assert!(first.status.success(), "{first:?}");
    assert!(first.stderr.is_empty(), "stderr was not empty: {first:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse env response");
    let services = first_json["data"]["services"]
        .as_array()
        .expect("service array");
    assert_eq!(services.len(), 6);

    let service = |key: &str| {
        services
            .iter()
            .find(|service| service["service_key"] == key)
            .unwrap_or_else(|| panic!("missing service {key}"))
    };
    assert!(
        service("web")["url"]
            .as_str()
            .expect("web URL")
            .starts_with("http://127.0.0.1:")
    );
    assert!(
        service("supabase.api")["url"]
            .as_str()
            .expect("API URL")
            .starts_with("http://127.0.0.1:")
    );
    assert!(
        service("supabase.db")["url"]
            .as_str()
            .expect("database URL")
            .starts_with("postgresql://127.0.0.1:")
    );
    assert!(
        service("supabase.db.shadow")["url"]
            .as_str()
            .expect("shadow database URL")
            .starts_with("postgresql://127.0.0.1:")
    );
    assert!(
        service("supabase.studio")["url"]
            .as_str()
            .expect("Studio URL")
            .starts_with("http://127.0.0.1:")
    );
    assert!(
        service("supabase.mail")["url"]
            .as_str()
            .expect("mail URL")
            .starts_with("http://127.0.0.1:")
    );

    let db_port = service("supabase.db")["port"]
        .as_u64()
        .expect("database port");
    assert_eq!(
        first_json["data"]["environment"]["DUCKFLAP_SUPABASE_DB_PORT"],
        db_port.to_string()
    );
    assert_eq!(
        first_json["data"]["environment"]["DUCKFLAP_SUPABASE_DB_URL"],
        format!("postgresql://127.0.0.1:{db_port}")
    );

    let repeated = run_env(&repo, &state);
    assert!(repeated.status.success(), "{repeated:?}");
    let repeated_json: Value =
        serde_json::from_slice(&repeated.stdout).expect("parse repeated env response");
    assert_eq!(repeated_json["changed"], false);
    assert_eq!(
        repeated_json["data"]["services"],
        first_json["data"]["services"]
    );

    let status = run_status(&repo, &state);
    assert!(status.status.success(), "{status:?}");
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("parse status response");
    let db_status = status_json["data"]["services"]
        .as_array()
        .expect("status services")
        .iter()
        .find(|service| service["service_key"] == "supabase.db")
        .expect("database status");
    assert_eq!(db_status["readiness"], "not_started");
    assert_eq!(
        db_status["url"],
        format!("postgresql://127.0.0.1:{db_port}")
    );

    install_fake_next(&repo);
    let started = run_detached_with_path(&repo, &state, &fake_path);
    assert!(started.status.success(), "{started:?}");
    let started_json: Value = serde_json::from_slice(&started.stdout).expect("parse mixed run");
    let started_services = started_json["data"]["services"]
        .as_array()
        .expect("mixed run services");
    assert_eq!(started_services.len(), 5);
    assert!(
        started_services
            .iter()
            .any(|service| service["service_key"] == "web")
    );
    assert!(
        started_services
            .iter()
            .any(|service| service["service_key"] == "supabase.api")
    );
    let started_ports = service_ports(&started_json);
    assert!(started_ports.iter().all(|port| tcp_port_is_open(*port)));
    let session_id = started_json["data"]["runtime_session_id"]
        .as_str()
        .expect("mixed runtime session ID");
    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let component_counts = connection
        .query_row(
            "SELECT
                (SELECT COUNT(*) FROM runtime_processes WHERE session_id = ?1),
                (SELECT COUNT(*) FROM runtime_adapters WHERE session_id = ?1)",
            [session_id],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .expect("count mixed runtime components");
    assert_eq!(component_counts, (1, 1));

    let repeated_run = run_detached_with_path(&repo, &state, &fake_path);
    assert!(repeated_run.status.success(), "{repeated_run:?}");
    let repeated_run_json: Value =
        serde_json::from_slice(&repeated_run.stdout).expect("parse repeated mixed run");
    assert_eq!(repeated_run_json["changed"], false);
    assert_eq!(
        repeated_run_json["data"]["runtime_session_id"],
        started_json["data"]["runtime_session_id"]
    );
    assert_eq!(
        repeated_run_json["data"]["services"],
        started_json["data"]["services"]
    );

    let running_status = run_status(&repo, &state);
    assert!(running_status.status.success(), "{running_status:?}");
    let running_status_json: Value =
        serde_json::from_slice(&running_status.stdout).expect("parse running mixed status");
    for service in running_status_json["data"]["services"]
        .as_array()
        .expect("running mixed services")
    {
        let expected = match service["service_key"].as_str().expect("service key") {
            "supabase.db.shadow" => "not_started",
            _ => "ready",
        };
        assert_eq!(service["readiness"], expected);
    }
    let stopped = run_stop_with_path(&repo, &state, &fake_path);
    assert!(stopped.status.success(), "{stopped:?}");
    for port in started_ports {
        wait_for_tcp_port(port, false);
    }
    assert_eq!(
        fs::read(&config_path).expect("read config after env"),
        config_before
    );
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn reallocate_atomically_replaces_the_current_detected_service_set() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    add_supabase_config(
        &repo,
        r#"
            project_id = "reallocate-mixed"

            [studio]
            enabled = true
        "#,
    );
    let initial = run_env(&repo, &state);
    assert!(initial.status.success(), "{initial:?}");
    let initial_json: Value =
        serde_json::from_slice(&initial.stdout).expect("parse initial environment");
    let initial_ports = service_port_map(&initial_json["data"]["services"]);
    assert!(initial_ports.contains_key("web"));
    assert!(initial_ports.contains_key("supabase.studio"));

    update_supabase_config(
        &repo,
        r#"
            project_id = "reallocate-mixed"

            [studio]
            enabled = false
        "#,
    );
    let reallocated = run_reallocate(&repo, &state);
    assert!(reallocated.status.success(), "{reallocated:?}");
    assert!(
        reallocated.stderr.is_empty(),
        "stderr was not empty: {reallocated:?}"
    );
    let reallocated_json: Value =
        serde_json::from_slice(&reallocated.stdout).expect("parse reallocation");
    assert_eq!(reallocated_json["command"], "reallocate");
    assert_eq!(reallocated_json["changed"], true);
    let previous_ports = service_port_map(&reallocated_json["data"]["previous_services"]);
    let replacement_ports = service_port_map(&reallocated_json["data"]["services"]);
    assert_eq!(previous_ports, initial_ports);
    assert!(previous_ports.contains_key("supabase.studio"));
    assert!(!replacement_ports.contains_key("supabase.studio"));
    assert!(replacement_ports.iter().all(|(service_key, port)| {
        previous_ports
            .get(service_key)
            .is_some_and(|previous| previous != port)
    }));

    let stable = run_env(&repo, &state);
    assert!(stable.status.success(), "{stable:?}");
    let stable_json: Value =
        serde_json::from_slice(&stable.stdout).expect("parse stable environment");
    assert_eq!(stable_json["changed"], false);
    assert_eq!(
        service_port_map(&stable_json["data"]["services"]),
        replacement_ports
    );
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn mixed_runtime_restarts_the_whole_stack_when_nextjs_is_lost() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    add_supabase_config(&repo, "project_id = \"mixed-stale\"");
    install_fake_next(&repo);
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);

    let first = run_detached_with_path(&repo, &state, &fake_path);
    assert!(first.status.success(), "{first:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse first run");
    let first_session = first_json["data"]["runtime_session_id"]
        .as_str()
        .expect("first session ID");
    let instance_id = first_json["data"]["project_instance_id"]
        .as_str()
        .expect("project instance ID");
    let ports = service_ports(&first_json);
    let marker = state
        .join("runtimes")
        .join(instance_id)
        .join(".fake-supabase.pid");
    let first_supabase_pid = fs::read_to_string(&marker).expect("read first Supabase PID");
    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let web_process_group = connection
        .query_row(
            "SELECT process_group_id FROM runtime_processes WHERE session_id = ?1 AND service_key = 'web'",
            [first_session],
            |row| row.get::<_, u32>(0),
        )
        .expect("read web process group");
    terminate_process_group(web_process_group).expect("terminate the recorded web process group");

    let restarted = run_detached_with_path(&repo, &state, &fake_path);
    assert!(restarted.status.success(), "{restarted:?}");
    let restarted_json: Value =
        serde_json::from_slice(&restarted.stdout).expect("parse restarted run");
    assert_eq!(restarted_json["changed"], true);
    assert_ne!(restarted_json["data"]["runtime_session_id"], first_session);
    assert_eq!(service_ports(&restarted_json), ports);
    let second_supabase_pid = fs::read_to_string(&marker).expect("read restarted Supabase PID");
    assert_ne!(second_supabase_pid, first_supabase_pid);
    assert!(ports.iter().all(|port| tcp_port_is_open(*port)));

    let stopped = run_stop_with_path(&repo, &state, &fake_path);
    assert!(stopped.status.success(), "{stopped:?}");
    for port in ports {
        wait_for_tcp_port(port, false);
    }
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn active_runtime_reconciles_with_the_current_detected_shape() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next(&repo);
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);

    let next_only = run_detached_with_path(&repo, &state, &fake_path);
    assert!(next_only.status.success(), "{next_only:?}");
    let next_only_json: Value =
        serde_json::from_slice(&next_only.stdout).expect("parse Next-only run");
    let next_only_session = next_only_json["data"]["runtime_session_id"].clone();
    assert_eq!(
        next_only_json["data"]["services"]
            .as_array()
            .expect("Next-only services")
            .len(),
        1
    );

    add_supabase_config(&repo, "project_id = \"shape-transition\"");
    let mixed = run_detached_with_path(&repo, &state, &fake_path);
    assert!(mixed.status.success(), "{mixed:?}");
    let mixed_json: Value = serde_json::from_slice(&mixed.stdout).expect("parse mixed run");
    assert_eq!(mixed_json["changed"], true);
    assert_ne!(mixed_json["data"]["runtime_session_id"], next_only_session);
    assert!(
        mixed_json["data"]["services"]
            .as_array()
            .expect("mixed services")
            .iter()
            .any(|service| service["service_key"] == "web")
    );
    assert!(
        mixed_json["data"]["services"]
            .as_array()
            .expect("mixed services")
            .iter()
            .any(|service| service["service_key"] == "supabase.api")
    );

    update_package_json(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    let supabase_only = run_detached_with_path(&repo, &state, &fake_path);
    assert!(supabase_only.status.success(), "{supabase_only:?}");
    let supabase_only_json: Value =
        serde_json::from_slice(&supabase_only.stdout).expect("parse Supabase-only run");
    assert_eq!(supabase_only_json["changed"], true);
    assert_ne!(
        supabase_only_json["data"]["runtime_session_id"],
        mixed_json["data"]["runtime_session_id"]
    );
    assert!(
        supabase_only_json["data"]["services"]
            .as_array()
            .expect("Supabase-only services")
            .iter()
            .all(|service| service["service_key"] != "web")
    );

    let repeated = run_detached_with_path(&repo, &state, &fake_path);
    assert!(repeated.status.success(), "{repeated:?}");
    let repeated_json: Value =
        serde_json::from_slice(&repeated.stdout).expect("parse repeated Supabase-only run");
    assert_eq!(repeated_json["changed"], false);
    assert_eq!(
        repeated_json["data"]["runtime_session_id"],
        supabase_only_json["data"]["runtime_session_id"]
    );

    let status = run_status(&repo, &state);
    assert!(status.status.success(), "{status:?}");
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("parse status");
    let historical_web = status_json["data"]["services"]
        .as_array()
        .expect("status services")
        .iter()
        .find(|service| service["service_key"] == "web")
        .expect("historical web allocation");
    assert_eq!(historical_web["readiness"], "not_started");

    let stopped = run_stop_with_path(&repo, &state, &fake_path);
    assert!(stopped.status.success(), "{stopped:?}");
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn supabase_only_run_is_idempotent_ready_stoppable_and_git_clean() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(&repo, "project_id = \"supabase-only\"");
    fs::create_dir(&state).expect("create permissive state directory");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o777))
        .expect("make state directory permissive");
    let migration = repo.join("supabase/migrations/0001_test.sql");
    fs::create_dir_all(migration.parent().expect("migration parent"))
        .expect("create migrations directory");
    fs::write(&migration, "select 1;\n").expect("write migration");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["add", "supabase/migrations/0001_test.sql"])
            .status()
            .expect("stage migration")
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
                "-m",
                "add migration",
            ])
            .status()
            .expect("commit migration")
            .success()
    );
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);

    let first = run_detached_with_path(&repo, &state, &fake_path);
    assert!(first.status.success(), "{first:?}");
    assert!(first.stderr.is_empty(), "stderr was not empty: {first:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse run response");
    assert_eq!(first_json["changed"], true);
    let session_id = first_json["data"]["runtime_session_id"]
        .as_str()
        .expect("runtime session ID");
    let services = first_json["data"]["services"]
        .as_array()
        .expect("run services");
    assert_eq!(services.len(), 4);
    assert!(
        services
            .iter()
            .all(|service| service["readiness"] == "ready")
    );
    let ports = services
        .iter()
        .map(|service| {
            u16::try_from(service["port"].as_u64().expect("service port")).expect("TCP port")
        })
        .collect::<Vec<_>>();
    assert!(ports.iter().all(|port| tcp_port_is_open(*port)));

    let active_env = run_env(&repo, &state);
    assert!(active_env.status.success(), "{active_env:?}");
    let active_env_json: Value =
        serde_json::from_slice(&active_env.stdout).expect("parse active environment");
    assert_eq!(active_env_json["changed"], false);
    assert_eq!(
        active_env_json["data"]["project_instance_id"],
        first_json["data"]["project_instance_id"]
    );
    assert_eq!(
        active_env_json["data"]["services"]
            .as_array()
            .expect("allocated services")
            .len(),
        6
    );

    let project_instance_id = first_json["data"]["project_instance_id"]
        .as_str()
        .expect("project instance ID");
    let generated_root = state.join("runtimes").join(project_instance_id);
    let session_root = state.join("sessions").join(session_id);
    for directory in [
        &state,
        &state.join("runtimes"),
        &generated_root,
        &session_root,
    ] {
        assert_eq!(
            fs::metadata(directory)
                .unwrap_or_else(|error| panic!("read {directory:?} metadata: {error}"))
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "directory {directory:?} was not private"
        );
    }
    assert_eq!(
        fs::metadata(session_root.join("supabase.log"))
            .expect("read Supabase log metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let generated_config = fs::read_to_string(generated_root.join("supabase/config.toml"))
        .expect("read generated config");
    assert!(generated_config.contains("project_id = \"duckflap"));
    assert!(!generated_config.contains("project_id = \"supabase-only\""));
    assert_eq!(
        fs::read_to_string(generated_root.join("supabase/migrations/0001_test.sql"))
            .expect("read copied migration"),
        "select 1;\n"
    );

    let repeated = run_detached_with_path(&repo, &state, &fake_path);
    assert!(repeated.status.success(), "{repeated:?}");
    let repeated_json: Value =
        serde_json::from_slice(&repeated.stdout).expect("parse repeated run");
    assert_eq!(repeated_json["changed"], false);
    assert_eq!(repeated_json["data"]["runtime_session_id"], session_id);

    let status = run_status(&repo, &state);
    assert!(status.status.success(), "{status:?}");
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("parse status");
    assert_eq!(status_json["data"]["runtime_session_id"], session_id);
    let status_services = status_json["data"]["services"]
        .as_array()
        .expect("status services");
    assert!(status_services.iter().all(|service| {
        let key = service["service_key"].as_str().expect("service key");
        let expected = match key {
            "supabase.db.shadow" | "supabase.edge_inspector" => "not_started",
            _ => "ready",
        };
        service["readiness"] == expected
    }));

    let stopped = run_stop_with_path(&repo, &state, &fake_path);
    assert!(stopped.status.success(), "{stopped:?}");
    let stopped_json: Value = serde_json::from_slice(&stopped.stdout).expect("parse stop");
    assert_eq!(stopped_json["changed"], true);
    for port in ports {
        wait_for_tcp_port(port, false);
    }
    let repeated_stop = run_stop_with_path(&repo, &state, &fake_path);
    assert!(repeated_stop.status.success(), "{repeated_stop:?}");
    let repeated_stop_json: Value =
        serde_json::from_slice(&repeated_stop.stdout).expect("parse repeated stop");
    assert_eq!(repeated_stop_json["changed"], false);
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn supabase_runtime_snapshot_ignores_a_historical_disabled_service() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(
        &repo,
        "project_id = \"service-snapshot\"\n[studio]\nenabled = true\n",
    );
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);

    let first = run_detached_with_path(&repo, &state, &fake_path);
    assert!(first.status.success(), "{first:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse first run");
    assert!(
        first_json["data"]["services"]
            .as_array()
            .expect("first services")
            .iter()
            .any(|service| service["service_key"] == "supabase.studio")
    );
    let first_session = first_json["data"]["runtime_session_id"].clone();

    let stopped = run_stop_with_path(&repo, &state, &fake_path);
    assert!(stopped.status.success(), "{stopped:?}");
    update_supabase_config(
        &repo,
        "project_id = \"service-snapshot\"\n[studio]\nenabled = false\n",
    );

    let restarted = run_detached_with_path(&repo, &state, &fake_path);
    assert!(restarted.status.success(), "{restarted:?}");
    let restarted_json: Value =
        serde_json::from_slice(&restarted.stdout).expect("parse restarted run");
    assert_ne!(restarted_json["data"]["runtime_session_id"], first_session);
    assert!(
        restarted_json["data"]["services"]
            .as_array()
            .expect("restarted services")
            .iter()
            .all(|service| service["service_key"] != "supabase.studio")
    );

    let repeated = run_detached_with_path(&repo, &state, &fake_path);
    assert!(repeated.status.success(), "{repeated:?}");
    let repeated_json: Value =
        serde_json::from_slice(&repeated.stdout).expect("parse repeated run");
    assert_eq!(repeated_json["changed"], false);
    assert_eq!(
        repeated_json["data"]["runtime_session_id"],
        restarted_json["data"]["runtime_session_id"]
    );

    let status = run_status(&repo, &state);
    assert!(status.status.success(), "{status:?}");
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("parse status");
    let studio = status_json["data"]["services"]
        .as_array()
        .expect("status services")
        .iter()
        .find(|service| service["service_key"] == "supabase.studio")
        .expect("historical Studio allocation");
    assert_eq!(studio["readiness"], "not_started");
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn stop_follows_a_supabase_replacement_without_cleaning_the_predecessor_again() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    let stop_entered = temp.path().join("replacement-stop-entered");
    let continue_stop = temp.path().join("continue-replacement-stop");
    let stop_count = temp.path().join("replacement-stop-count");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(
        &repo,
        "project_id = \"stop-follows-replacement\"\n[studio]\nenabled = true\n",
    );
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);

    let first = run_detached_with_path(&repo, &state, &fake_path);
    assert!(first.status.success(), "{first:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse first run");
    let first_session = first_json["data"]["runtime_session_id"]
        .as_str()
        .expect("first session ID")
        .to_owned();
    update_supabase_config(
        &repo,
        "project_id = \"stop-follows-replacement\"\n[studio]\nenabled = false\n",
    );

    let replacement = run_detached_command(&repo, &state)
        .env("PATH", &fake_path)
        .env("DUCKFLAP_FAKE_SUPABASE_STOP_ENTERED", &stop_entered)
        .env("DUCKFLAP_FAKE_SUPABASE_STOP_CONTINUE", &continue_stop)
        .env("DUCKFLAP_FAKE_SUPABASE_STOP_COUNT", &stop_count)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start gated Supabase replacement");
    wait_for_path(&stop_entered);

    let mut stopping = stop_command(&repo, &state)
        .env("PATH", &fake_path)
        .env("DUCKFLAP_FAKE_SUPABASE_STOP_COUNT", &stop_count)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("stop during Supabase replacement");
    thread::sleep(Duration::from_millis(200));
    assert!(
        stopping
            .try_wait()
            .expect("check replacement-following stop")
            .is_none(),
        "stop did not wait for the replacement handoff"
    );

    fs::write(&continue_stop, []).expect("release predecessor cleanup");
    let replacement = replacement
        .wait_with_output()
        .expect("finish Supabase replacement");
    let stopped = stopping
        .wait_with_output()
        .expect("finish replacement-following stop");
    assert!(replacement.status.success(), "{replacement:?}");
    assert!(stopped.status.success(), "{stopped:?}");
    let replacement_json: Value =
        serde_json::from_slice(&replacement.stdout).expect("parse replacement");
    let stopped_json: Value = serde_json::from_slice(&stopped.stdout).expect("parse stop");
    assert_ne!(
        replacement_json["data"]["runtime_session_id"],
        first_session
    );
    assert_eq!(
        stopped_json["data"]["runtime_session_id"],
        replacement_json["data"]["runtime_session_id"]
    );
    assert_eq!(
        fs::read_to_string(&stop_count)
            .expect("read replacement cleanup count")
            .lines()
            .count(),
        2,
        "the predecessor and successor must each be stopped exactly once"
    );
    for port in service_ports(&replacement_json) {
        wait_for_tcp_port(port, false);
    }
    assert_no_active_runtime(&state);
}

#[test]
fn supabase_run_restarts_a_recorded_stack_after_readiness_is_lost() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(&repo, "project_id = \"stale-stack\"");
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);

    let first = run_detached_with_path(&repo, &state, &fake_path);
    assert!(first.status.success(), "{first:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse first run");
    let first_session = first_json["data"]["runtime_session_id"]
        .as_str()
        .expect("first session ID");
    let ports = service_ports(&first_json);
    let project_instance_id = first_json["data"]["project_instance_id"]
        .as_str()
        .expect("project instance ID");
    let marker = state
        .join("runtimes")
        .join(project_instance_id)
        .join(".fake-supabase.pid");
    let pid = fs::read_to_string(&marker).expect("read fake stack PID");
    assert!(
        Command::new("kill")
            .arg(pid.trim())
            .status()
            .expect("terminate fake stack")
            .success()
    );
    for port in &ports {
        wait_for_tcp_port(*port, false);
    }
    wait_for_path_absent(&marker);

    let restarted = run_detached_with_path(&repo, &state, &fake_path);
    assert!(restarted.status.success(), "{restarted:?}");
    let restarted_json: Value =
        serde_json::from_slice(&restarted.stdout).expect("parse restarted run");
    assert_eq!(restarted_json["changed"], true);
    assert_ne!(restarted_json["data"]["runtime_session_id"], first_session);
    assert_eq!(service_ports(&restarted_json), ports);
    assert!(ports.iter().all(|port| tcp_port_is_open(*port)));

    let stopped = run_stop_with_path(&repo, &state, &fake_path);
    assert!(stopped.status.success(), "{stopped:?}");
    for port in ports {
        wait_for_tcp_port(port, false);
    }
}

#[test]
fn supabase_start_failure_cleans_up_the_partial_stack() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(&repo, "project_id = \"failed-stack\"");
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);
    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    let environment_json: Value =
        serde_json::from_slice(&environment.stdout).expect("parse environment");
    let project_instance_id = environment_json["data"]["project_instance_id"]
        .as_str()
        .expect("project instance ID");
    let _partial_cleanup = PidFileCleanup(
        state
            .join("runtimes")
            .join(project_instance_id)
            .join(".fake-supabase.pid"),
    );
    let persistent_ports = environment_json["data"]["services"]
        .as_array()
        .expect("allocated services")
        .iter()
        .filter(|service| {
            !matches!(
                service["service_key"].as_str().expect("service key"),
                "supabase.db.shadow" | "supabase.edge_inspector" | "supabase.analytics.vector"
            )
        })
        .map(|service| {
            u16::try_from(service["port"].as_u64().expect("service port")).expect("TCP port")
        })
        .collect::<Vec<_>>();

    let failed = run_detached_command(&repo, &state)
        .env("PATH", &fake_path)
        .env("DUCKFLAP_FAKE_SUPABASE_START_FAIL", "1")
        .output()
        .expect("run failing Supabase start");
    assert!(!failed.status.success(), "{failed:?}");
    let failed_json: Value = serde_json::from_slice(&failed.stdout).expect("parse start failure");
    assert_eq!(failed_json["error"]["code"], "SUPABASE_START_FAILED");
    for port in persistent_ports {
        wait_for_tcp_port(port, false);
    }
    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM runtime_sessions WHERE status IN ('starting', 'ready', 'stopping')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("count active runtime sessions"),
        0
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM runtime_sessions ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("read failed runtime status"),
        "failed"
    );
}

#[test]
fn supabase_exit_127_after_launch_cleans_up_the_partial_stack() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(&repo, "project_id = \"exit-127\"");
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);

    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    let environment_json: Value =
        serde_json::from_slice(&environment.stdout).expect("parse environment");
    let project_instance_id = environment_json["data"]["project_instance_id"]
        .as_str()
        .expect("project instance ID");
    let _partial_cleanup = PidFileCleanup(
        state
            .join("runtimes")
            .join(project_instance_id)
            .join(".fake-supabase.pid"),
    );
    let persistent_ports = persistent_supabase_ports(&environment_json);

    let failed = run_detached_command(&repo, &state)
        .env("PATH", &fake_path)
        .env("DUCKFLAP_FAKE_SUPABASE_START_EXIT", "127")
        .output()
        .expect("run Supabase start that exits 127 after launch");
    assert!(!failed.status.success(), "{failed:?}");
    let failed_json: Value = serde_json::from_slice(&failed.stdout).expect("parse start failure");
    assert_eq!(failed_json["error"]["code"], "SUPABASE_START_FAILED");
    for port in persistent_ports {
        wait_for_tcp_port(port, false);
    }
    assert_no_active_runtime(&state);

    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM runtime_sessions ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("read failed runtime status"),
        "failed"
    );
}

#[test]
fn unavailable_supabase_cli_leaves_no_active_runtime() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let isolated_bin = temp.path().join("git-only-bin");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(&repo, "project_id = \"missing-cli\"");
    let isolated_path = install_git_only_path(&isolated_bin);

    let failed = run_detached_with_path(&repo, &state, &isolated_path);
    assert!(!failed.status.success(), "{failed:?}");
    let failed_json: Value = serde_json::from_slice(&failed.stdout).expect("parse CLI error");
    assert_eq!(failed_json["error"]["code"], "SUPABASE_CLI_UNAVAILABLE");
    assert_no_active_runtime(&state);

    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM runtime_sessions ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("read failed runtime status"),
        "failed"
    );
}

#[test]
fn failed_start_cleanup_keeps_ownership_until_stop_retries_it() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(&repo, "project_id = \"cleanup-retry\"");
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);

    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    let environment_json: Value =
        serde_json::from_slice(&environment.stdout).expect("parse environment");
    let ports = persistent_supabase_ports(&environment_json);

    let failed = run_detached_command(&repo, &state)
        .env("PATH", &fake_path)
        .env("DUCKFLAP_FAKE_SUPABASE_START_FAIL", "1")
        .env("DUCKFLAP_FAKE_SUPABASE_STOP_FAIL", "1")
        .output()
        .expect("run start with failed cleanup");
    assert!(!failed.status.success(), "{failed:?}");
    let failed_json: Value = serde_json::from_slice(&failed.stdout).expect("parse cleanup failure");
    assert_eq!(failed_json["error"]["code"], "SUPABASE_STOP_FAILED");
    assert!(ports.iter().all(|port| tcp_port_is_open(*port)));

    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM runtime_sessions ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("read retained runtime status"),
        "starting"
    );
    drop(connection);

    let release = run_release(&repo, &state);
    assert!(!release.status.success(), "{release:?}");
    let release_json: Value = serde_json::from_slice(&release.stdout).expect("parse release error");
    assert_eq!(release_json["error"]["code"], "RUNTIME_ACTIVE");

    let stopped = run_stop_with_path(&repo, &state, &fake_path);
    assert!(stopped.status.success(), "{stopped:?}");
    for port in ports {
        wait_for_tcp_port(port, false);
    }
    assert_no_active_runtime(&state);
}

#[test]
fn failed_stop_keeps_ownership_until_a_later_stop_succeeds() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(&repo, "project_id = \"stop-retry\"");
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);

    let started = run_detached_with_path(&repo, &state, &fake_path);
    assert!(started.status.success(), "{started:?}");
    let started_json: Value = serde_json::from_slice(&started.stdout).expect("parse started run");
    let ports = service_ports(&started_json);

    let failed = stop_command(&repo, &state)
        .env("PATH", &fake_path)
        .env("DUCKFLAP_FAKE_SUPABASE_STOP_FAIL", "1")
        .output()
        .expect("run failing stop");
    assert!(!failed.status.success(), "{failed:?}");
    let failed_json: Value = serde_json::from_slice(&failed.stdout).expect("parse stop failure");
    assert_eq!(failed_json["error"]["code"], "SUPABASE_STOP_FAILED");
    assert!(ports.iter().all(|port| tcp_port_is_open(*port)));

    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM runtime_sessions ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("read retained runtime status"),
        "stopping"
    );
    drop(connection);

    let release = run_release(&repo, &state);
    assert!(!release.status.success(), "{release:?}");
    let release_json: Value = serde_json::from_slice(&release.stdout).expect("parse release error");
    assert_eq!(release_json["error"]["code"], "RUNTIME_ACTIVE");

    let stopped = run_stop_with_path(&repo, &state, &fake_path);
    assert!(stopped.status.success(), "{stopped:?}");
    for port in ports {
        wait_for_tcp_port(port, false);
    }
    assert_no_active_runtime(&state);
}

#[test]
fn stop_rejects_a_live_adapter_start_without_orphaning_the_stack() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    let entered = temp.path().join("start-entered");
    let continue_start = temp.path().join("continue-start");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(&repo, "project_id = \"start-stop-race\"");
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);

    let running = run_detached_command(&repo, &state)
        .env("PATH", &fake_path)
        .env("DUCKFLAP_FAKE_SUPABASE_START_ENTERED", &entered)
        .env("DUCKFLAP_FAKE_SUPABASE_START_CONTINUE", &continue_start)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start gated Supabase runtime");
    wait_for_path(&entered);

    let stopped_while_starting = run_stop_with_path(&repo, &state, &fake_path);
    assert!(
        !stopped_while_starting.status.success(),
        "{stopped_while_starting:?}"
    );
    let stopped_json: Value = serde_json::from_slice(&stopped_while_starting.stdout)
        .expect("parse stop-during-start response");
    assert_eq!(stopped_json["error"]["code"], "RUNTIME_STARTING");
    assert_eq!(stopped_json["changed"], false);
    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM runtime_sessions ORDER BY rowid DESC LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .expect("read runtime status during start"),
        "starting"
    );
    drop(connection);

    fs::write(&continue_start, []).expect("release gated Supabase start");
    let started = running.wait_with_output().expect("wait for gated start");
    assert!(started.status.success(), "{started:?}");
    let started_json: Value = serde_json::from_slice(&started.stdout).expect("parse started stack");
    let ports = service_ports(&started_json);
    assert!(ports.iter().all(|port| tcp_port_is_open(*port)));

    let stopped = run_stop_with_path(&repo, &state, &fake_path);
    assert!(stopped.status.success(), "{stopped:?}");
    for port in ports {
        wait_for_tcp_port(port, false);
    }
    assert_no_active_runtime(&state);
}

#[test]
fn abandoned_supabase_startup_child_is_stopped_before_adapter_cleanup() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    let entered = temp.path().join("start-entered");
    let continue_start = temp.path().join("continue-start");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(&repo, "project_id = \"abandoned-start-child\"");
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);

    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    let environment_json: Value =
        serde_json::from_slice(&environment.stdout).expect("parse environment");
    let project_instance_id = environment_json["data"]["project_instance_id"]
        .as_str()
        .expect("project instance ID");
    let ports = persistent_supabase_ports(&environment_json);
    let _partial_cleanup = PidFileCleanup(
        state
            .join("runtimes")
            .join(project_instance_id)
            .join(".fake-supabase.pid"),
    );

    let mut launcher = run_detached_command(&repo, &state)
        .env("PATH", &fake_path)
        .env("DUCKFLAP_FAKE_SUPABASE_START_ENTERED", &entered)
        .env("DUCKFLAP_FAKE_SUPABASE_START_CONTINUE", &continue_start)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start gated Supabase runtime");
    wait_for_path(&entered);

    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let startup_process_group = connection
        .query_row(
            "SELECT process_group_id FROM runtime_processes
             WHERE service_key = 'supabase.startup'",
            [],
            |row| row.get::<_, u32>(0),
        )
        .expect("read Supabase startup process group");
    let _startup_cleanup = ProcessGroupCleanup(startup_process_group);
    drop(connection);

    launcher.kill().expect("kill only the Duckflap launcher");
    launcher.wait().expect("reap killed Duckflap launcher");

    let stopped = run_stop_with_path(&repo, &state, &fake_path);
    assert!(stopped.status.success(), "{stopped:?}");
    fs::write(&continue_start, []).expect("release any surviving fake start");
    assert_tcp_ports_remain_closed(&ports, Duration::from_secs(1));
    assert_no_active_runtime(&state);
}

#[test]
fn concurrent_abandoned_start_recovery_runs_adapter_cleanup_once() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    let start_entered = temp.path().join("start-entered");
    let continue_start = temp.path().join("continue-start");
    let stop_entered = temp.path().join("stop-entered");
    let continue_stop = temp.path().join("continue-stop");
    let stop_count = temp.path().join("stop-count");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(&repo, "project_id = \"exclusive-abandoned-cleanup\"");
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);

    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    let environment_json: Value =
        serde_json::from_slice(&environment.stdout).expect("parse environment");
    let project_instance_id = environment_json["data"]["project_instance_id"]
        .as_str()
        .expect("project instance ID");
    let _partial_cleanup = PidFileCleanup(
        state
            .join("runtimes")
            .join(project_instance_id)
            .join(".fake-supabase.pid"),
    );

    let mut launcher = run_detached_command(&repo, &state)
        .env("PATH", &fake_path)
        .env("DUCKFLAP_FAKE_SUPABASE_START_ENTERED", &start_entered)
        .env("DUCKFLAP_FAKE_SUPABASE_START_CONTINUE", &continue_start)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start gated Supabase runtime");
    wait_for_path(&start_entered);
    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let startup_process_group = connection
        .query_row(
            "SELECT process_group_id FROM runtime_processes
             WHERE service_key = 'supabase.startup'",
            [],
            |row| row.get::<_, u32>(0),
        )
        .expect("read Supabase startup process group");
    let _startup_cleanup = ProcessGroupCleanup(startup_process_group);
    drop(connection);
    launcher.kill().expect("kill only the Duckflap launcher");
    launcher.wait().expect("reap killed Duckflap launcher");

    let recovery = || {
        run_detached_command(&repo, &state)
            .env("PATH", &fake_path)
            .env("DUCKFLAP_FAKE_SUPABASE_STOP_ENTERED", &stop_entered)
            .env("DUCKFLAP_FAKE_SUPABASE_STOP_CONTINUE", &continue_stop)
            .env("DUCKFLAP_FAKE_SUPABASE_STOP_COUNT", &stop_count)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start abandoned-start recovery")
    };
    let first = recovery();
    let second = recovery();
    wait_for_path(&stop_entered);
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        fs::read_to_string(&stop_count)
            .expect("read adapter cleanup count")
            .lines()
            .count(),
        1,
        "only the exact-session claim winner may clean the adapter"
    );

    fs::write(&continue_stop, []).expect("release claimed adapter cleanup");
    let first = first.wait_with_output().expect("wait for first recovery");
    let second = second.wait_with_output().expect("wait for second recovery");
    assert!(first.status.success(), "{first:?}");
    assert!(second.status.success(), "{second:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse first recovery");
    let second_json: Value = serde_json::from_slice(&second.stdout).expect("parse second recovery");
    assert_eq!(
        first_json["data"]["runtime_session_id"],
        second_json["data"]["runtime_session_id"]
    );
    assert_eq!(
        fs::read_to_string(&stop_count)
            .expect("reread adapter cleanup count")
            .lines()
            .count(),
        1
    );
}

#[test]
fn stop_recovers_a_legacy_empty_starting_session_with_a_live_reused_pid() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(&repo, "project_id = \"empty-abandoned-start\"");

    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    let environment_json: Value =
        serde_json::from_slice(&environment.stdout).expect("parse environment");
    let project_instance_id = environment_json["data"]["project_instance_id"]
        .as_str()
        .expect("project instance ID");
    let session_id = "00000000-0000-4000-8000-000000000002";
    let live_unrelated_owner = current_process_identity().expect("read test process identity");
    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    connection
        .execute(
            "INSERT INTO runtime_sessions
                (id, project_instance_id, status, launcher_pid)
             VALUES (?1, ?2, 'starting', ?3)",
            rusqlite::params![session_id, project_instance_id, live_unrelated_owner.pid],
        )
        .expect("insert legacy empty runtime with a reused launcher PID");
    drop(connection);

    let stopped = run_stop(&repo, &state);
    assert!(stopped.status.success(), "{stopped:?}");
    let stopped_json: Value = serde_json::from_slice(&stopped.stdout).expect("parse stop response");
    assert_eq!(stopped_json["changed"], true);
    assert_eq!(stopped_json["data"]["runtime_session_id"], session_id);
    assert_no_active_runtime(&state);

    let connection = Connection::open(state.join("registry.sqlite3")).expect("reopen registry");
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM runtime_sessions WHERE id = ?1",
                [session_id],
                |row| row.get::<_, String>(0),
            )
            .expect("read stopped empty session"),
        "stopped"
    );
}

#[test]
fn invalid_abandoned_adapter_remains_stopping_for_recovery() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(&repo, "project_id = \"invalid-abandoned-adapter\"");

    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    let environment_json: Value =
        serde_json::from_slice(&environment.stdout).expect("parse environment");
    let project_instance_id = environment_json["data"]["project_instance_id"]
        .as_str()
        .expect("project instance ID");
    let session_id = "00000000-0000-4000-8000-000000000001";
    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    connection
        .execute(
            "INSERT INTO runtime_sessions (id, project_instance_id, status, launcher_pid)
             VALUES (?1, ?2, 'starting', ?3)",
            rusqlite::params![session_id, project_instance_id, u32::MAX],
        )
        .expect("insert abandoned runtime session");
    connection
        .execute(
            "INSERT INTO runtime_adapters
                (session_id, adapter_key, working_directory, runtime_project_id, log_path)
             VALUES (?1, 'unknown', '/tmp/unused', 'unused', '/tmp/unused.log')",
            [session_id],
        )
        .expect("insert invalid adapter record");
    drop(connection);

    let stopped = run_stop(&repo, &state);
    assert!(!stopped.status.success(), "{stopped:?}");
    let stopped_json: Value = serde_json::from_slice(&stopped.stdout).expect("parse stop error");
    assert_eq!(stopped_json["error"]["code"], "INVALID_RUNTIME_RECORD");
    assert_eq!(stopped_json["changed"], true);

    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM runtime_sessions WHERE id = ?1",
                [session_id],
                |row| row.get::<_, String>(0),
            )
            .expect("read recoverable runtime status"),
        "stopping"
    );
}

#[test]
fn mixed_supabase_failure_never_starts_nextjs() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    add_supabase_config(&repo, "project_id = \"mixed-supabase-failure\"");
    install_fake_next(&repo);
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);
    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    let environment_json: Value =
        serde_json::from_slice(&environment.stdout).expect("parse environment");
    let web_port = environment_json["data"]["services"]
        .as_array()
        .expect("allocated services")
        .iter()
        .find(|service| service["service_key"] == "web")
        .and_then(|service| service["port"].as_u64())
        .and_then(|port| u16::try_from(port).ok())
        .expect("web port");

    let failed = run_detached_command(&repo, &state)
        .env("PATH", &fake_path)
        .env("DUCKFLAP_FAKE_SUPABASE_START_FAIL", "1")
        .output()
        .expect("run failing mixed stack");
    assert!(!failed.status.success(), "{failed:?}");
    let failed_json: Value = serde_json::from_slice(&failed.stdout).expect("parse start failure");
    assert_eq!(failed_json["error"]["code"], "SUPABASE_START_FAILED");
    assert!(!tcp_port_is_open(web_port));
    assert_no_active_runtime(&state);
}

#[test]
fn mixed_nextjs_failure_rolls_back_supabase() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    add_supabase_config(&repo, "project_id = \"mixed-next-failure\"");
    install_fake_next_script(&repo, "#!/bin/sh\nexit 17\n");
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);

    let failed = run_detached_with_path(&repo, &state, &fake_path);
    assert!(!failed.status.success(), "{failed:?}");
    let failed_json: Value = serde_json::from_slice(&failed.stdout).expect("parse start failure");
    assert_eq!(failed_json["error"]["code"], "RUNTIME_EXITED_BEFORE_READY");

    let status = run_status(&repo, &state);
    assert!(status.status.success(), "{status:?}");
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("parse status");
    for service in status_json["data"]["services"]
        .as_array()
        .expect("status services")
    {
        if service["service_key"] != "supabase.db.shadow" {
            let port =
                u16::try_from(service["port"].as_u64().expect("service port")).expect("TCP port");
            wait_for_tcp_port(port, false);
        }
    }
    assert_no_active_runtime(&state);
}

#[test]
fn mixed_start_requires_final_combined_readiness() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    add_supabase_config(&repo, "project_id = \"combined-readiness\"");
    install_fake_next(&repo);
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);
    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    let environment_json: Value =
        serde_json::from_slice(&environment.stdout).expect("parse environment");
    let all_ports = service_ports(&environment_json);

    let failed = run_detached_command(&repo, &state)
        .env("PATH", &fake_path)
        .env("DUCKFLAP_FAKE_SUPABASE_EXIT_AFTER", "3")
        .output()
        .expect("run mixed stack with failing Supabase component");
    assert!(!failed.status.success(), "{failed:?}");
    let failed_json: Value =
        serde_json::from_slice(&failed.stdout).expect("parse combined readiness failure");
    assert_eq!(
        failed_json["error"]["code"], "RUNTIME_READINESS_TIMEOUT",
        "{failed:?}"
    );
    for port in all_ports {
        wait_for_tcp_port(port, false);
    }
    assert_no_active_runtime(&state);
}

#[test]
fn mixed_stop_targets_only_the_current_worktree_instance() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let linked = temp.path().join("linked");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    add_supabase_config(&repo, "project_id = \"shared-source-id\"");
    add_linked_worktree(&repo, &linked);
    install_fake_next(&repo);
    install_fake_next(&linked);
    let fake_path = install_fake_supabase(&fake_bin);
    let _primary_cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);
    let _linked_cleanup = SupabaseRuntimeCleanup::new(&linked, &state, &fake_path);

    let primary = run_detached_with_path(&repo, &state, &fake_path);
    let sibling = run_detached_with_path(&linked, &state, &fake_path);
    assert!(primary.status.success(), "{primary:?}");
    assert!(sibling.status.success(), "{sibling:?}");
    let primary_json: Value = serde_json::from_slice(&primary.stdout).expect("parse primary run");
    let sibling_json: Value = serde_json::from_slice(&sibling.stdout).expect("parse sibling run");
    assert_ne!(
        primary_json["data"]["project_instance_id"],
        sibling_json["data"]["project_instance_id"]
    );
    let primary_ports = service_ports(&primary_json);
    let sibling_ports = service_ports(&sibling_json);
    assert!(
        primary_ports
            .iter()
            .all(|port| !sibling_ports.contains(port))
    );

    let stopped = run_stop_with_path(&repo, &state, &fake_path);
    assert!(stopped.status.success(), "{stopped:?}");
    for port in primary_ports {
        wait_for_tcp_port(port, false);
    }
    assert!(sibling_ports.iter().all(|port| tcp_port_is_open(*port)));
    let sibling_status = run_status(&linked, &state);
    assert!(sibling_status.status.success(), "{sibling_status:?}");
    let sibling_status_json: Value =
        serde_json::from_slice(&sibling_status.stdout).expect("parse sibling status");
    assert!(
        sibling_status_json["data"]["services"]
            .as_array()
            .expect("sibling services")
            .iter()
            .all(|service| {
                let key = service["service_key"].as_str().expect("service key");
                let expected = match key {
                    "supabase.db.shadow" | "supabase.edge_inspector" => "not_started",
                    _ => "ready",
                };
                service["readiness"] == expected
            })
    );

    let sibling_stopped = run_stop_with_path(&linked, &state, &fake_path);
    assert!(sibling_stopped.status.success(), "{sibling_stopped:?}");
    for port in sibling_ports {
        wait_for_tcp_port(port, false);
    }
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
    assert!(git_output(&linked, &["status", "--porcelain"]).is_empty());
}

#[test]
fn invalid_supabase_config_is_json_and_creates_no_state() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(&repo, "[api]\nenabled = \"yes\"");

    let output = run_env(&repo, &state);
    assert!(!output.status.success());
    assert!(output.stderr.is_empty(), "stderr was not empty: {output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse config error");
    assert_eq!(json["changed"], false);
    assert_eq!(json["error"]["code"], "INVALID_SUPABASE_CONFIG");
    assert!(!state.exists());
}

#[test]
fn env_accepts_environment_backed_supabase_listener_fields() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(
        &repo,
        r#"
            [api]
            enabled = "env(DUCKFLAP_TEST_API_ENABLED)"
            port = "env(DUCKFLAP_TEST_API_PORT)"

            [api.tls]
            enabled = "env(DUCKFLAP_TEST_TLS_ENABLED)"

            [studio]
            enabled = false

            [inbucket]
            enabled = false

            [edge_runtime]
            enabled = false
        "#,
    );

    let output = env_command(&repo, &state)
        .env("DUCKFLAP_TEST_API_ENABLED", "true")
        .env("DUCKFLAP_TEST_API_PORT", "54321")
        .env("DUCKFLAP_TEST_TLS_ENABLED", "false")
        .output()
        .expect("run env with Supabase config environment");

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "stderr was not empty: {output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse env response");
    let keys = json["data"]["services"]
        .as_array()
        .expect("service array")
        .iter()
        .map(|service| service["service_key"].as_str().expect("service key"))
        .collect::<Vec<_>>();
    assert_eq!(keys, ["supabase.api", "supabase.db", "supabase.db.shadow"]);
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn invalid_supabase_environment_values_are_json_and_create_no_state() {
    let _test_lock = lock_cli_test();
    let cases = [
        (
            "[api]\nenabled = \"env(DUCKFLAP_TEST_MISSING_ENABLED_019FF1C9)\"",
            None,
        ),
        (
            "[api]\nport = \"env(DUCKFLAP_TEST_INVALID_API_PORT)\"",
            Some(("DUCKFLAP_TEST_INVALID_API_PORT", "not-a-port")),
        ),
    ];

    for (index, (config, environment)) in cases.into_iter().enumerate() {
        let temp = tempdir().expect("create temp dir");
        let repo = temp.path().join("repo");
        let state = temp.path().join(format!("state-{index}"));
        initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
        add_supabase_config(&repo, config);

        let mut command = env_command(&repo, &state);
        if let Some((key, value)) = environment {
            command.env(key, value);
        }
        let output = command.output().expect("run invalid Supabase env");

        assert!(!output.status.success());
        assert!(output.stderr.is_empty(), "stderr was not empty: {output:?}");
        let json: Value = serde_json::from_slice(&output.stdout).expect("parse environment error");
        assert_eq!(json["changed"], false);
        assert_eq!(json["error"]["code"], "INVALID_SUPABASE_CONFIG");
        assert!(!state.exists());
    }
}

#[test]
fn unsupported_supabase_tls_is_json_and_creates_no_state() {
    let _test_lock = lock_cli_test();
    let cases = [
        ("[api.tls]\nenabled = true", None),
        (
            "[api.tls]\nenabled = \"env(DUCKFLAP_TEST_TLS_ENABLED_TRUE)\"",
            Some(("DUCKFLAP_TEST_TLS_ENABLED_TRUE", "true")),
        ),
    ];

    for (index, (config, environment)) in cases.into_iter().enumerate() {
        let temp = tempdir().expect("create temp dir");
        let repo = temp.path().join("repo");
        let state = temp.path().join(format!("state-{index}"));
        initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
        add_supabase_config(&repo, config);

        let mut command = env_command(&repo, &state);
        if let Some((key, value)) = environment {
            command.env(key, value);
        }
        let output = command.output().expect("run unsupported Supabase TLS");

        assert!(!output.status.success());
        assert!(output.stderr.is_empty(), "stderr was not empty: {output:?}");
        let json: Value = serde_json::from_slice(&output.stdout).expect("parse TLS error");
        assert_eq!(json["changed"], false);
        assert_eq!(json["error"]["code"], "UNSUPPORTED_SUPABASE_CONFIG");
        assert!(!state.exists());
    }
}

#[test]
fn exec_injects_stable_environment_and_preserves_arguments() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    let script = r#"printf '%s\n' "$PORT" "$DUCKFLAP_WEB_PORT" "$DUCKFLAP_WEB_URL" "$DUCKFLAP_TEST_PARENT" "$1" "$PWD""#;

    let first = exec_command(&repo, &state, &["sh", "-c", script, "sh", "-n"])
        .env("PORT", "9999")
        .env("DUCKFLAP_TEST_PARENT", "inherited")
        .output()
        .expect("run first duckflap exec");
    assert!(first.status.success(), "{first:?}");
    assert!(first.stderr.is_empty(), "stderr was not empty: {first:?}");
    let first_stdout = String::from_utf8(first.stdout).expect("UTF-8 child output");
    let first_lines = first_stdout.lines().collect::<Vec<_>>();
    assert_eq!(first_lines.len(), 6);
    let port = first_lines[0].parse::<u16>().expect("allocated port");
    assert_ne!(port, 9999);
    assert_eq!(first_lines[1], port.to_string());
    assert_eq!(first_lines[2], format!("http://127.0.0.1:{port}"));
    assert_eq!(first_lines[3], "inherited");
    assert_eq!(first_lines[4], "-n");
    assert_eq!(
        first_lines[5],
        fs::canonicalize(&repo)
            .expect("canonical worktree path")
            .to_string_lossy()
    );

    let second = exec_command(&repo, &state, &["sh", "-c", script, "sh", "-n"])
        .env("DUCKFLAP_TEST_PARENT", "inherited")
        .output()
        .expect("run second duckflap exec");
    assert!(second.status.success(), "{second:?}");
    let second_stdout = String::from_utf8(second.stdout).expect("UTF-8 child output");
    let second_port = second_stdout
        .lines()
        .next()
        .expect("child port")
        .parse::<u16>()
        .expect("stable port");
    assert_eq!(second_port, port);
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn exec_returns_child_exit_and_signal_codes() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );

    let exited = run_exec(&repo, &state, &["sh", "-c", "exit 23"]);
    assert_eq!(exited.status.code(), Some(23), "{exited:?}");

    let signalled = run_exec(&repo, &state, &["sh", "-c", "kill -TERM $$"]);
    assert_eq!(signalled.status.signal(), Some(15), "{signalled:?}");
}

#[test]
fn exec_replaces_duckflap_without_changing_the_pid() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );

    let child = exec_command(&repo, &state, &["sh", "-c", "printf '%s\\n' \"$$\""])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start duckflap exec");
    let duckflap_pid = child.id();
    let output = child.wait_with_output().expect("wait for executed command");
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "stderr was not empty: {output:?}");
    let executed_pid = String::from_utf8(output.stdout)
        .expect("UTF-8 PID output")
        .trim()
        .parse::<u32>()
        .expect("numeric executed PID");

    assert_eq!(executed_pid, duckflap_pid);
}

#[test]
fn exec_failure_preserves_the_allocation() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );

    let output = run_exec(
        &repo,
        &state,
        &["duckflap-command-that-does-not-exist-7f32f23d"],
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout was not empty: {output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to execute command"),
        "unexpected stderr: {output:?}"
    );

    let status = run_status(&repo, &state);
    assert!(status.status.success(), "{status:?}");
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("parse status response");
    assert_eq!(
        status_json["data"]["services"].as_array().map(Vec::len),
        Some(1)
    );
}

#[test]
fn exec_does_not_start_a_child_when_detection_fails() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let marker = temp.path().join("child-started");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "react": "latest" },
            "scripts": { "dev": "vite" }
        }"#,
    );

    let output = exec_command(
        &repo,
        &state,
        &["sh", "-c", "touch \"$DUCKFLAP_TEST_MARKER\""],
    )
    .env("DUCKFLAP_TEST_MARKER", &marker)
    .output()
    .expect("run duckflap exec");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "stdout was not empty: {output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("no supported listening services were detected"),
        "unexpected stderr: {output:?}"
    );
    assert!(!marker.exists());
    assert!(!state.exists());
}

#[test]
fn concurrent_linked_worktree_execs_receive_distinct_ports() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let linked = temp.path().join("linked");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    add_linked_worktree(&repo, &linked);

    let state_paths = StatePaths::from_root(state.clone());
    drop(Registry::open_mutating(&state_paths).expect("initialize registry"));
    let gate = Connection::open(state_paths.registry()).expect("open registry gate");
    gate.execute_batch("BEGIN IMMEDIATE")
        .expect("hold registry write gate");
    let script = r#"printf '%s\n' "$PORT""#;
    let mut first = exec_command(&repo, &state, &["sh", "-c", script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start primary exec");
    let mut second = exec_command(&linked, &state, &["sh", "-c", script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start linked exec");
    thread::sleep(Duration::from_millis(100));
    assert!(
        first.try_wait().expect("check primary exec").is_none(),
        "primary exec did not wait at the registry gate"
    );
    assert!(
        second.try_wait().expect("check linked exec").is_none(),
        "linked exec did not wait at the registry gate"
    );
    gate.execute_batch("COMMIT")
        .expect("release registry write gate");

    let first = first.wait_with_output().expect("wait for primary exec");
    let second = second.wait_with_output().expect("wait for linked exec");
    assert!(first.status.success(), "{first:?}");
    assert!(second.status.success(), "{second:?}");
    assert!(first.stderr.is_empty(), "stderr was not empty: {first:?}");
    assert!(second.stderr.is_empty(), "stderr was not empty: {second:?}");
    let first_port = String::from_utf8(first.stdout)
        .expect("UTF-8 primary output")
        .trim()
        .parse::<u16>()
        .expect("primary port");
    let second_port = String::from_utf8(second.stdout)
        .expect("UTF-8 linked output")
        .trim()
        .parse::<u16>()
        .expect("linked port");
    assert_ne!(first_port, second_port);
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
    assert!(git_output(&linked, &["status", "--porcelain"]).is_empty());
}

#[test]
fn detached_run_is_ready_idempotent_and_stoppable() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev --turbopack" }
        }"#,
    );
    install_fake_next(&repo);

    let first = run_detached(&repo, &state);
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    assert!(first.status.success(), "{first:?}");
    assert!(first.stderr.is_empty(), "stderr was not empty: {first:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse run response");
    assert_eq!(first_json["command"], "run");
    assert_eq!(first_json["changed"], true);
    assert_eq!(first_json["data"]["services"][0]["readiness"], "ready");
    let session_id = first_json["data"]["runtime_session_id"].clone();
    let port = first_json["data"]["services"][0]["port"]
        .as_u64()
        .expect("runtime port") as u16;
    assert!(tcp_port_is_open(port));

    let repeated = run_detached(&repo, &state);
    assert!(repeated.status.success(), "{repeated:?}");
    let repeated_json: Value =
        serde_json::from_slice(&repeated.stdout).expect("parse repeated run response");
    assert_eq!(repeated_json["changed"], false);
    assert_eq!(repeated_json["data"]["runtime_session_id"], session_id);

    let status = run_status(&repo, &state);
    assert!(status.status.success(), "{status:?}");
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("parse status response");
    assert_eq!(status_json["data"]["runtime_session_id"], session_id);
    assert_eq!(status_json["data"]["services"][0]["readiness"], "ready");

    let registry_path = state.join("registry.sqlite3");
    let registry_before_human_status =
        fs::read(&registry_path).expect("read registry before human status");
    let human_status = run_status_human(&repo, &state);
    assert!(human_status.status.success(), "{human_status:?}");
    assert!(
        human_status.stderr.is_empty(),
        "stderr was not empty: {human_status:?}"
    );
    let project_id = first_json["data"]["project_id"]
        .as_str()
        .expect("project ID");
    let project_instance_id = first_json["data"]["project_instance_id"]
        .as_str()
        .expect("project instance ID");
    let session_id_text = session_id.as_str().expect("runtime session ID");
    assert_eq!(
        String::from_utf8(human_status.stdout).expect("UTF-8 human status"),
        format!(
            "project: {project_id}\nproject instance: {project_instance_id}\nruntime session: {session_id_text}\nservice: web tcp/{port} ready http://127.0.0.1:{port}\n"
        )
    );
    assert_eq!(
        fs::read(&registry_path).expect("read registry after human status"),
        registry_before_human_status
    );

    let stopped = run_stop(&repo, &state);
    assert!(stopped.status.success(), "{stopped:?}");
    let stopped_json: Value = serde_json::from_slice(&stopped.stdout).expect("parse stop response");
    assert_eq!(stopped_json["changed"], true);
    assert_eq!(stopped_json["data"]["runtime_session_id"], session_id);
    assert!(!tcp_port_is_open(port));

    let stopped_status = run_status(&repo, &state);
    assert!(stopped_status.status.success(), "{stopped_status:?}");
    let stopped_status_json: Value =
        serde_json::from_slice(&stopped_status.stdout).expect("parse stopped status");
    assert_eq!(
        stopped_status_json["data"]["services"][0]["readiness"],
        "stopped"
    );
    assert_eq!(
        stopped_status_json["data"]["runtime_session_id"],
        session_id
    );

    let repeated_stop = run_stop(&repo, &state);
    assert!(repeated_stop.status.success(), "{repeated_stop:?}");
    let repeated_stop_json: Value =
        serde_json::from_slice(&repeated_stop.stdout).expect("parse repeated stop response");
    assert_eq!(repeated_stop_json["changed"], false);
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn wait_returns_ready_status_without_mutating_state_or_blocking_on_history() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    add_supabase_config(
        &repo,
        r#"
            project_id = "historical-supabase"

            [api]
            enabled = true
            port = 54321

            [db]
            port = 54322
            shadow_port = 54320
        "#,
    );
    install_fake_next(&repo);

    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    fs::remove_dir_all(repo.join("supabase")).expect("remove Supabase project inputs");
    let started = run_detached(&repo, &state);
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    assert!(started.status.success(), "{started:?}");
    let started_json: Value = serde_json::from_slice(&started.stdout).expect("parse run response");
    let registry_path = state.join("registry.sqlite3");
    let registry_before = fs::read(&registry_path).expect("read registry before wait");

    let waited = run_wait(&repo, &state, 1);
    assert!(waited.status.success(), "{waited:?}");
    assert!(waited.stderr.is_empty(), "stderr was not empty: {waited:?}");
    let waited_json: Value = serde_json::from_slice(&waited.stdout).expect("parse wait response");
    assert_eq!(waited_json["command"], "wait");
    assert_eq!(waited_json["changed"], false);
    assert_eq!(
        waited_json["data"]["runtime_session_id"],
        started_json["data"]["runtime_session_id"]
    );
    let services = waited_json["data"]["services"]
        .as_array()
        .expect("wait services");
    assert!(
        services
            .iter()
            .any(|service| { service["service_key"] == "web" && service["readiness"] == "ready" })
    );
    assert!(services.iter().any(|service| {
        service["service_key"] == "supabase.api" && service["readiness"] == "not_started"
    }));
    assert_eq!(
        fs::read(&registry_path).expect("read registry after wait"),
        registry_before
    );
}

#[test]
fn wait_observes_a_runtime_that_becomes_ready_later() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(
        &repo,
        &format!("#!/bin/sh\nsleep 0.2\n{FAKE_TCP_LISTENER}\n"),
    );

    let starting = run_detached_command(&repo, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start delayed runtime");
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    wait_for_runtime_status(&state, "starting");

    let waited = run_wait(&repo, &state, 5);
    assert!(waited.status.success(), "{waited:?}");
    let waited_json: Value = serde_json::from_slice(&waited.stdout).expect("parse wait response");
    assert_eq!(waited_json["changed"], false);
    assert_eq!(waited_json["data"]["services"][0]["readiness"], "ready");

    let started = starting.wait_with_output().expect("wait for delayed run");
    assert!(started.status.success(), "{started:?}");
    let started_json: Value = serde_json::from_slice(&started.stdout).expect("parse run response");
    assert_eq!(
        waited_json["data"]["runtime_session_id"],
        started_json["data"]["runtime_session_id"]
    );
}

#[test]
fn wait_observes_only_the_atomic_runtime_replacement_handoff() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next(&repo);

    let started = run_detached(&repo, &state);
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    assert!(started.status.success(), "{started:?}");
    let started_json: Value = serde_json::from_slice(&started.stdout).expect("parse run response");
    let first_session = started_json["data"]["runtime_session_id"]
        .as_str()
        .expect("first session ID")
        .to_owned();
    let replacement_session = "00000000-0000-4000-8000-000000000002";

    let mut connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    connection
        .execute(
            "UPDATE runtime_sessions SET status = 'stopping' WHERE id = ?1",
            [&first_session],
        )
        .expect("begin replacement handoff");

    let transaction = connection.transaction().expect("begin replacement claim");
    transaction
        .execute(
            "UPDATE runtime_sessions
             SET status = 'stopped', ended_at = CURRENT_TIMESTAMP
             WHERE id = ?1",
            [&first_session],
        )
        .expect("stage predecessor completion");

    let mut waiting = wait_command(&repo, &state, 5)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start wait during replacement transaction");
    thread::sleep(Duration::from_millis(700));
    assert!(
        waiting
            .try_wait()
            .expect("check atomic handoff wait")
            .is_none(),
        "wait observed the uncommitted stopped predecessor"
    );

    transaction
        .execute(
            "INSERT INTO runtime_sessions (id, project_instance_id, status, launcher_pid, ready_at)
             SELECT ?1, project_instance_id, 'ready', launcher_pid, CURRENT_TIMESTAMP
             FROM runtime_sessions
             WHERE id = ?2",
            params![replacement_session, first_session],
        )
        .expect("insert replacement session");
    transaction
        .execute(
            "INSERT INTO runtime_processes
                (session_id, service_key, pid, process_group_id, process_start, executable, log_path)
             SELECT ?1, service_key, pid, process_group_id, process_start, executable, log_path
             FROM runtime_processes
             WHERE session_id = ?2",
            params![replacement_session, first_session],
        )
        .expect("record replacement process");
    transaction
        .commit()
        .expect("atomically commit runtime replacement");

    let waited = waiting.wait_with_output().expect("finish replacement wait");
    assert!(waited.status.success(), "{waited:?}");
    assert!(waited.stderr.is_empty(), "stderr was not empty: {waited:?}");
    let waited_json: Value = serde_json::from_slice(&waited.stdout).expect("parse wait response");
    assert_eq!(waited_json["changed"], false);
    assert_eq!(
        waited_json["data"]["runtime_session_id"],
        replacement_session
    );
    assert_eq!(waited_json["data"]["services"][0]["readiness"], "ready");
}

#[test]
fn wait_times_out_without_changing_a_starting_runtime() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(&repo, &format!("#!/bin/sh\nsleep 5\n{FAKE_TCP_LISTENER}\n"));

    let starting = run_detached_command(&repo, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start slow runtime");
    wait_for_runtime_status(&state, "starting");

    let waited = run_wait(&repo, &state, 1);
    assert!(!waited.status.success(), "{waited:?}");
    assert!(waited.stderr.is_empty(), "stderr was not empty: {waited:?}");
    let waited_json: Value = serde_json::from_slice(&waited.stdout).expect("parse wait timeout");
    assert_eq!(waited_json["changed"], false);
    assert_eq!(waited_json["error"]["code"], "RUNTIME_WAIT_TIMEOUT");

    let status = run_status(&repo, &state);
    assert!(status.status.success(), "{status:?}");
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("parse status response");
    assert_eq!(status_json["data"]["services"][0]["readiness"], "starting");

    let stopped = run_stop(&repo, &state);
    assert!(stopped.status.success(), "{stopped:?}");
    let started = starting
        .wait_with_output()
        .expect("wait for interrupted run");
    assert!(!started.status.success(), "{started:?}");
}

#[test]
fn wait_reports_terminal_failure_and_missing_runtime_without_mutation() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );

    let missing = run_wait(&repo, &state, 1);
    assert!(!missing.status.success(), "{missing:?}");
    let missing_json: Value = serde_json::from_slice(&missing.stdout).expect("parse missing error");
    assert_eq!(missing_json["changed"], false);
    assert_eq!(missing_json["error"]["code"], "NO_MANAGED_RUNTIME");
    assert!(!state.exists());

    install_fake_next_script(&repo, "#!/bin/sh\nexit 9\n");
    let failed = run_detached(&repo, &state);
    assert!(!failed.status.success(), "{failed:?}");
    let registry_path = state.join("registry.sqlite3");
    let registry_before = fs::read(&registry_path).expect("read registry before failed wait");

    let terminal = run_wait(&repo, &state, 1);
    assert!(!terminal.status.success(), "{terminal:?}");
    let terminal_json: Value =
        serde_json::from_slice(&terminal.stdout).expect("parse terminal error");
    assert_eq!(terminal_json["changed"], false);
    assert_eq!(terminal_json["error"]["code"], "RUNTIME_FAILED");
    assert_eq!(
        fs::read(&registry_path).expect("read registry after failed wait"),
        registry_before
    );
}

#[test]
fn managed_runtime_allows_env_and_exec_to_reuse_its_allocation() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next(&repo);

    let started = run_detached(&repo, &state);
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    assert!(started.status.success(), "{started:?}");
    let started_json: Value = serde_json::from_slice(&started.stdout).expect("parse run response");
    let port = started_json["data"]["services"][0]["port"]
        .as_u64()
        .expect("runtime port");

    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    let environment_json: Value =
        serde_json::from_slice(&environment.stdout).expect("parse env response");
    assert_eq!(environment_json["changed"], false);
    assert_eq!(environment_json["data"]["services"][0]["port"], port);

    let executed = run_exec(
        &repo,
        &state,
        &["sh", "-c", r#"printf '%s|%s' "$PORT" "$DUCKFLAP_WEB_URL""#],
    );
    assert!(executed.status.success(), "{executed:?}");
    assert!(
        executed.stderr.is_empty(),
        "stderr was not empty: {executed:?}"
    );
    assert_eq!(
        String::from_utf8(executed.stdout).expect("UTF-8 exec output"),
        format!("{port}|http://127.0.0.1:{port}")
    );
}

#[test]
fn release_rejects_an_active_runtime_and_succeeds_after_stop() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next(&repo);

    let started = run_detached(&repo, &state);
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    assert!(started.status.success(), "{started:?}");
    let started_json: Value = serde_json::from_slice(&started.stdout).expect("parse run response");
    let port = started_json["data"]["services"][0]["port"]
        .as_u64()
        .expect("runtime port") as u16;

    let active_release = run_release(&repo, &state);
    assert!(!active_release.status.success(), "{active_release:?}");
    assert!(
        active_release.stderr.is_empty(),
        "stderr was not empty: {active_release:?}"
    );
    let active_release_json: Value =
        serde_json::from_slice(&active_release.stdout).expect("parse active release error");
    assert_eq!(active_release_json["changed"], false);
    assert_eq!(active_release_json["error"]["code"], "RUNTIME_ACTIVE");
    assert!(tcp_port_is_open(port));

    let stopped = run_stop(&repo, &state);
    assert!(stopped.status.success(), "{stopped:?}");
    assert!(!tcp_port_is_open(port));
    let released = run_release(&repo, &state);
    assert!(released.status.success(), "{released:?}");
    let released_json: Value =
        serde_json::from_slice(&released.stdout).expect("parse release response");
    assert_eq!(released_json["changed"], true);
    assert_eq!(released_json["data"]["released_services"][0]["port"], port);
}

#[test]
fn reallocate_rejects_an_active_runtime_and_succeeds_after_stop() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next(&repo);

    let started = run_detached(&repo, &state);
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    assert!(started.status.success(), "{started:?}");
    let started_json: Value = serde_json::from_slice(&started.stdout).expect("parse run response");
    let port = started_json["data"]["services"][0]["port"]
        .as_u64()
        .expect("runtime port");

    let active = run_reallocate(&repo, &state);
    assert!(!active.status.success(), "{active:?}");
    assert!(active.stderr.is_empty(), "{active:?}");
    let active_json: Value =
        serde_json::from_slice(&active.stdout).expect("parse active reallocation error");
    assert_eq!(active_json["command"], "reallocate");
    assert_eq!(active_json["changed"], false);
    assert_eq!(active_json["error"]["code"], "RUNTIME_ACTIVE");
    assert!(tcp_port_is_open(
        u16::try_from(port).expect("u16 runtime port")
    ));

    let stopped = run_stop(&repo, &state);
    assert!(stopped.status.success(), "{stopped:?}");
    let reallocated = run_reallocate(&repo, &state);
    assert!(reallocated.status.success(), "{reallocated:?}");
    let reallocated_json: Value =
        serde_json::from_slice(&reallocated.stdout).expect("parse stopped reallocation");
    assert_eq!(reallocated_json["changed"], true);
    assert_eq!(
        reallocated_json["data"]["previous_services"][0]["port"],
        port
    );
    assert_ne!(reallocated_json["data"]["services"][0]["port"], port);
}

#[test]
fn concurrent_linked_worktree_runs_are_isolated() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let linked = temp.path().join("linked");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    add_linked_worktree(&repo, &linked);
    install_fake_next(&repo);
    install_fake_next(&linked);

    let first = run_detached_command(&repo, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start primary run");
    let second = run_detached_command(&linked, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start linked run");
    let first = first.wait_with_output().expect("wait for primary run");
    let second = second.wait_with_output().expect("wait for linked run");
    let _cleanup_primary = RuntimeCleanup::new(&repo, &state);
    let _cleanup_linked = RuntimeCleanup::new(&linked, &state);
    assert!(first.status.success(), "{first:?}");
    assert!(second.status.success(), "{second:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse primary run");
    let second_json: Value = serde_json::from_slice(&second.stdout).expect("parse linked run");
    let first_port = first_json["data"]["services"][0]["port"]
        .as_u64()
        .expect("primary port") as u16;
    let second_port = second_json["data"]["services"][0]["port"]
        .as_u64()
        .expect("linked port") as u16;
    assert_ne!(first_port, second_port);
    assert!(tcp_port_is_open(first_port));
    assert!(tcp_port_is_open(second_port));

    let stopped = run_stop(&repo, &state);
    assert!(stopped.status.success(), "{stopped:?}");
    assert!(!tcp_port_is_open(first_port));
    assert!(tcp_port_is_open(second_port));
    let stopped_linked = run_stop(&linked, &state);
    assert!(stopped_linked.status.success(), "{stopped_linked:?}");
    assert!(!tcp_port_is_open(second_port));
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
    assert!(git_output(&linked, &["status", "--porcelain"]).is_empty());
}

#[test]
fn concurrent_runs_converge_during_a_delayed_successful_startup() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(&repo, &format!("#!/bin/sh\nsleep 4\n{FAKE_TCP_LISTENER}\n"));

    let first = run_detached_command(&repo, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start first run");
    let second = run_detached_command(&repo, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start second run");
    let first = first.wait_with_output().expect("wait for first run");
    let second = second.wait_with_output().expect("wait for second run");
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    assert!(first.status.success(), "{first:?}");
    assert!(second.status.success(), "{second:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse first run");
    let second_json: Value = serde_json::from_slice(&second.stdout).expect("parse second run");
    assert_eq!(
        first_json["data"]["runtime_session_id"],
        second_json["data"]["runtime_session_id"]
    );
    assert_eq!(
        first_json["data"]["services"][0]["port"],
        second_json["data"]["services"][0]["port"]
    );
    assert!(
        first_json["changed"] == true || second_json["changed"] == true,
        "one command must create the runtime"
    );

    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let active_sessions = connection
        .query_row(
            "SELECT COUNT(*) FROM runtime_sessions WHERE status IN ('starting', 'ready', 'stopping')",
            [],
            |row| row.get::<_, i64>(0),
        )
        .expect("count active sessions");
    assert_eq!(active_sessions, 1);
}

#[test]
fn detached_run_reports_launch_failure_and_preserves_history() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );

    let output = run_detached(&repo, &state);
    assert!(!output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "stderr was not empty: {output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse launch error");
    assert_eq!(json["command"], "run");
    assert_eq!(json["changed"], true);
    assert_eq!(json["error"]["code"], "RUNTIME_LAUNCH_FAILED");

    let status = run_status(&repo, &state);
    assert!(status.status.success(), "{status:?}");
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("parse failed status");
    assert_eq!(
        status_json["data"]["services"][0]["readiness"],
        "not_started"
    );
    assert!(status_json["data"]["runtime_session_id"].is_string());
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn logs_tails_a_failed_web_runtime_without_mutating_state() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(
        &repo,
        "#!/bin/sh\nprintf 'first line\\nsecond line\\nthird line\\n' >&2\nexit 1\n",
    );

    let failed = run_detached(&repo, &state);
    assert!(!failed.status.success(), "{failed:?}");
    let registry_path = state.join("registry.sqlite3");
    let registry_before = fs::read(&registry_path).expect("read registry before logs");
    let registry_modified_before = fs::metadata(&registry_path)
        .expect("read registry metadata before logs")
        .modified()
        .expect("read registry modified time before logs");
    let git_before = git_output(&repo, &["status", "--porcelain"]);

    let logs = run_logs(&repo, &state, "web", 2);
    assert!(logs.status.success(), "{logs:?}");
    assert!(logs.stderr.is_empty(), "{logs:?}");
    assert_eq!(logs.stdout, b"second line\nthird line\n");
    assert_eq!(
        fs::read(&registry_path).expect("read registry after logs"),
        registry_before
    );
    assert_eq!(
        fs::metadata(&registry_path)
            .expect("read registry metadata after logs")
            .modified()
            .expect("read registry modified time after logs"),
        registry_modified_before
    );
    assert_eq!(git_output(&repo, &["status", "--porcelain"]), git_before);

    let unknown = run_logs(&repo, &state, "missing.service", 20);
    assert!(!unknown.status.success(), "{unknown:?}");
    assert!(unknown.stdout.is_empty(), "{unknown:?}");
    assert!(
        String::from_utf8_lossy(&unknown.stderr).contains("UNKNOWN_LOG_SERVICE"),
        "{unknown:?}"
    );
}

#[test]
fn logs_searches_history_for_the_latest_matching_service() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let fake_bin = temp.path().join("bin");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(
        &repo,
        "#!/bin/sh\nprintf 'older web session\\n' >&2\nexit 1\n",
    );
    let web_failed = run_detached(&repo, &state);
    assert!(!web_failed.status.success(), "{web_failed:?}");

    update_package_json(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);
    add_supabase_config(&repo, "project_id = \"newer-supabase-session\"");
    let fake_path = install_fake_supabase(&fake_bin);
    let _cleanup = SupabaseRuntimeCleanup::new(&repo, &state, &fake_path);
    let supabase_failed = run_detached_command(&repo, &state)
        .env("PATH", &fake_path)
        .env("DUCKFLAP_FAKE_SUPABASE_START_FAIL", "1")
        .output()
        .expect("run failing Supabase start");
    assert!(!supabase_failed.status.success(), "{supabase_failed:?}");

    let web_logs = run_logs(&repo, &state, "web", 20);
    assert!(web_logs.status.success(), "{web_logs:?}");
    assert_eq!(web_logs.stdout, b"older web session\n");

    let api_logs = run_logs(&repo, &state, "supabase.api", 20);
    assert!(api_logs.status.success(), "{api_logs:?}");
    assert!(
        String::from_utf8_lossy(&api_logs.stdout).contains("fake Supabase startup failed"),
        "{api_logs:?}"
    );
    let db_logs = run_logs(&repo, &state, "supabase.db", 20);
    assert!(db_logs.status.success(), "{db_logs:?}");
    assert_eq!(db_logs.stdout, api_logs.stdout);
}

#[test]
fn logs_rejects_recorded_paths_outside_duckflap_state() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let outside = temp.path().join("outside-secret.log");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(&repo, "#!/bin/sh\nexit 1\n");
    let failed = run_detached(&repo, &state);
    assert!(!failed.status.success(), "{failed:?}");
    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let original_log = connection
        .query_row(
            "SELECT log_path FROM runtime_processes WHERE service_key = 'web'",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("read original log path");
    fs::remove_file(&original_log).expect("remove recorded log");
    let missing = run_logs(&repo, &state, "web", 20);
    assert!(!missing.status.success(), "{missing:?}");
    assert!(
        String::from_utf8_lossy(&missing.stderr).contains("LOG_NOT_FOUND"),
        "{missing:?}"
    );

    fs::write(&outside, "must not be printed\n").expect("write external log");
    std::os::unix::fs::symlink(&outside, &original_log).expect("link recorded log outside state");
    let symlinked = run_logs(&repo, &state, "web", 20);
    assert!(!symlinked.status.success(), "{symlinked:?}");
    assert!(symlinked.stdout.is_empty(), "{symlinked:?}");
    assert!(
        String::from_utf8_lossy(&symlinked.stderr).contains("UNSAFE_LOG_PATH"),
        "{symlinked:?}"
    );
    fs::remove_file(&original_log).expect("remove external log link");

    connection
        .execute(
            "UPDATE runtime_processes SET log_path = ?1 WHERE service_key = 'web'",
            [outside.to_string_lossy().as_ref()],
        )
        .expect("corrupt recorded log path");

    let logs = run_logs(&repo, &state, "web", 20);
    assert!(!logs.status.success(), "{logs:?}");
    assert!(logs.stdout.is_empty(), "{logs:?}");
    let stderr = String::from_utf8_lossy(&logs.stderr);
    assert!(stderr.contains("UNSAFE_LOG_PATH"), "{logs:?}");
    assert!(!stderr.contains("must not be printed"), "{logs:?}");

    connection
        .execute(
            "UPDATE runtime_processes SET log_path = ?1 WHERE service_key = 'web'",
            [state.join("registry.sqlite3").to_string_lossy().as_ref()],
        )
        .expect("point recorded log at registry");
    let internal = run_logs(&repo, &state, "web", 20);
    assert!(!internal.status.success(), "{internal:?}");
    assert!(internal.stdout.is_empty(), "{internal:?}");
    assert!(
        String::from_utf8_lossy(&internal.stderr).contains("UNSAFE_LOG_PATH"),
        "{internal:?}"
    );
}

#[test]
fn logs_rejects_another_sessions_log_and_arbitrary_session_files() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(&repo, "#!/bin/sh\nprintf 'older log\\n' >&2\nexit 1\n");
    let older = run_detached(&repo, &state);
    assert!(!older.status.success(), "{older:?}");

    install_fake_next_script(&repo, "#!/bin/sh\nprintf 'newer log\\n' >&2\nexit 1\n");
    let newer = run_detached(&repo, &state);
    assert!(!newer.status.success(), "{newer:?}");

    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let records = {
        let mut statement = connection
            .prepare(
                "SELECT runtime_sessions.id, runtime_processes.log_path
                 FROM runtime_sessions
                 JOIN runtime_processes ON runtime_processes.session_id = runtime_sessions.id
                 WHERE runtime_processes.service_key = 'web'
                 ORDER BY runtime_sessions.rowid DESC",
            )
            .expect("prepare runtime log query");
        statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .expect("query runtime logs")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect runtime logs")
    };
    let [(newer_session, newer_log), (_, older_log)] = records.as_slice() else {
        panic!("expected two runtime log records: {records:?}");
    };

    connection
        .execute(
            "UPDATE runtime_processes SET log_path = ?1 WHERE session_id = ?2",
            [older_log, newer_session],
        )
        .expect("point newer session at older log");
    let cross_session = run_logs(&repo, &state, "web", 20);
    assert!(!cross_session.status.success(), "{cross_session:?}");
    assert!(cross_session.stdout.is_empty(), "{cross_session:?}");
    assert!(
        String::from_utf8_lossy(&cross_session.stderr).contains("UNSAFE_LOG_PATH"),
        "{cross_session:?}"
    );

    let arbitrary = Path::new(newer_log)
        .parent()
        .expect("newer session directory")
        .join("notes.txt");
    fs::write(&arbitrary, "not a runtime log\n").expect("write arbitrary session file");
    connection
        .execute(
            "UPDATE runtime_processes SET log_path = ?1 WHERE session_id = ?2",
            [arbitrary.to_string_lossy().as_ref(), newer_session],
        )
        .expect("point newer session at arbitrary file");
    let arbitrary_file = run_logs(&repo, &state, "web", 20);
    assert!(!arbitrary_file.status.success(), "{arbitrary_file:?}");
    assert!(arbitrary_file.stdout.is_empty(), "{arbitrary_file:?}");
    assert!(
        String::from_utf8_lossy(&arbitrary_file.stderr).contains("UNSAFE_LOG_PATH"),
        "{arbitrary_file:?}"
    );
}

#[test]
fn logs_rejects_a_symlinked_selected_session_directory() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(&repo, "#!/bin/sh\nprintf 'hidden log\\n' >&2\nexit 1\n");
    let failed = run_detached(&repo, &state);
    assert!(!failed.status.success(), "{failed:?}");

    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let log_path = connection
        .query_row(
            "SELECT log_path FROM runtime_processes WHERE service_key = 'web'",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("read log path");
    let session_path = Path::new(&log_path)
        .parent()
        .expect("session log parent")
        .to_path_buf();
    let backing_path = state.join("sessions/session-backing");
    fs::rename(&session_path, &backing_path).expect("move selected session directory");
    std::os::unix::fs::symlink(&backing_path, &session_path)
        .expect("link selected session directory inside sessions");

    let logs = run_logs(&repo, &state, "web", 20);
    assert!(!logs.status.success(), "{logs:?}");
    assert!(logs.stdout.is_empty(), "{logs:?}");
    assert!(
        String::from_utf8_lossy(&logs.stderr).contains("UNSAFE_LOG_PATH"),
        "{logs:?}"
    );
}

#[test]
fn logs_remain_available_after_runtime_stop() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(
        &repo,
        &format!("#!/bin/sh\nprintf 'started web runtime\\n' >&2\n{FAKE_TCP_LISTENER}\n"),
    );
    let started = run_detached(&repo, &state);
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    assert!(started.status.success(), "{started:?}");
    let stopped = run_stop(&repo, &state);
    assert!(stopped.status.success(), "{stopped:?}");

    let logs = run_logs(&repo, &state, "web", 20);
    assert!(logs.status.success(), "{logs:?}");
    assert!(
        String::from_utf8_lossy(&logs.stdout).contains("started web runtime"),
        "{logs:?}"
    );
}

#[test]
fn logs_on_unseen_state_fails_without_creating_state() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(&repo, r#"{ "dependencies": {}, "scripts": {} }"#);

    let logs = run_logs(&repo, &state, "web", 20);
    assert!(!logs.status.success(), "{logs:?}");
    assert!(logs.stdout.is_empty(), "{logs:?}");
    assert!(
        String::from_utf8_lossy(&logs.stderr).contains("NO_RUNTIME_HISTORY"),
        "{logs:?}"
    );
    assert!(!state.exists());
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn stop_owns_nextjs_after_its_launcher_dies_during_gated_startup() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let entered = temp.path().join("next-entered");
    let continue_start = temp.path().join("continue-next");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(
        &repo,
        &format!(
            "#!/bin/sh\n: > \"$DUCKFLAP_FAKE_NEXT_ENTERED\"\nwhile [ ! -e \"$DUCKFLAP_FAKE_NEXT_CONTINUE\" ]; do sleep 0.01; done\n{FAKE_TCP_LISTENER}\n"
        ),
    );
    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    let environment_json: Value =
        serde_json::from_slice(&environment.stdout).expect("parse environment");
    let port = u16::try_from(
        environment_json["data"]["services"][0]["port"]
            .as_u64()
            .expect("web port"),
    )
    .expect("TCP port");

    let mut launcher = run_detached_command(&repo, &state)
        .env("DUCKFLAP_FAKE_NEXT_ENTERED", &entered)
        .env("DUCKFLAP_FAKE_NEXT_CONTINUE", &continue_start)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start gated Next.js runtime");
    wait_for_path(&entered);

    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let process_group_id = connection
        .query_row(
            "SELECT process_group_id FROM runtime_processes WHERE service_key = 'web'",
            [],
            |row| row.get::<_, u32>(0),
        )
        .expect("read recorded Next.js process group");
    let _cleanup = ProcessGroupCleanup(process_group_id);
    drop(connection);

    launcher.kill().expect("kill only the Duckflap launcher");
    launcher.wait().expect("reap killed Duckflap launcher");

    let stopped = run_stop(&repo, &state);
    assert!(stopped.status.success(), "{stopped:?}");
    fs::write(&continue_start, []).expect("release any surviving Next.js process");
    assert_tcp_ports_remain_closed(&[port], Duration::from_secs(1));
    assert_no_active_runtime(&state);
}

#[test]
fn detached_run_rejects_a_transient_listener() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(
        &repo,
        "#!/bin/sh\nexec python3 -c 'import os,socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((\"127.0.0.1\",int(os.environ[\"PORT\"]))); s.listen(); time.sleep(0.1)'\n",
    );

    let output = run_detached(&repo, &state);
    assert!(!output.status.success(), "{output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse transient error");
    assert_eq!(json["error"]["code"], "RUNTIME_EXITED_BEFORE_READY");
    let status = run_status(&repo, &state);
    assert!(status.status.success(), "{status:?}");
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("parse stale status");
    assert_eq!(status_json["data"]["services"][0]["readiness"], "stale");

    let doctor = run_doctor(&repo, &state);
    assert!(doctor.status.success(), "{doctor:?}");
    let doctor_json: Value =
        serde_json::from_slice(&doctor.stdout).expect("parse stale doctor response");
    assert_eq!(doctor_json["data"]["healthy"], false);
    let failed = doctor_json["data"]["checks"]
        .as_array()
        .expect("doctor checks")
        .iter()
        .find(|check| check["code"] == "RUNTIME_FAILED")
        .expect("failed runtime check");
    assert_eq!(failed["status"], "failure");
    assert_eq!(
        failed["remediation"]["command"],
        "duckflap run --detach --json"
    );
    assert_eq!(failed["remediation"]["changes_allocations"], false);
}

#[test]
fn detached_run_rejects_a_listener_that_exits_during_startup_stability() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(
        &repo,
        "#!/bin/sh\nexec python3 -c 'import os,socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((\"127.0.0.1\",int(os.environ[\"PORT\"]))); s.listen(); time.sleep(1.2)'\n",
    );

    let output = run_detached(&repo, &state);
    assert!(!output.status.success(), "{output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse startup error");
    assert_eq!(json["error"]["code"], "RUNTIME_EXITED_BEFORE_READY");

    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let status = connection
        .query_row(
            "SELECT status FROM runtime_sessions ORDER BY rowid DESC LIMIT 1",
            [],
            |row| row.get::<_, String>(0),
        )
        .expect("read runtime status");
    assert_eq!(status, "failed");
}

#[test]
fn failed_start_terminates_descendants_left_by_the_runtime_leader() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(
        &repo,
        "#!/bin/sh\npython3 -c 'import os,socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((\"127.0.0.1\",int(os.environ[\"PORT\"]))); s.listen(); time.sleep(30)' &\nsleep 0.1\nexit 17\n",
    );

    let output = run_detached(&repo, &state);
    assert!(!output.status.success(), "{output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse run failure");
    assert_eq!(json["error"]["code"], "RUNTIME_EXITED_BEFORE_READY");

    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let (port, process_group_id, status) = connection
        .query_row(
            "SELECT allocations.port, runtime_processes.process_group_id, runtime_sessions.status
             FROM runtime_sessions
             JOIN runtime_processes ON runtime_processes.session_id = runtime_sessions.id
             JOIN allocations ON allocations.project_instance_id = runtime_sessions.project_instance_id
             ORDER BY runtime_sessions.rowid DESC
             LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, u16>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )
        .expect("read failed runtime");
    let _cleanup = ProcessGroupCleanup(process_group_id);
    assert_eq!(status, "failed");
    assert!(
        !tcp_port_is_open(port),
        "runtime descendant still owns port"
    );
}

#[test]
fn detached_run_restarts_an_owned_runtime_that_loses_readiness() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(
        &repo,
        "#!/bin/sh\nexec python3 -c 'import os,socket,time; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((\"127.0.0.1\",int(os.environ[\"PORT\"]))); s.listen(); time.sleep(2.5); s.close(); time.sleep(30)'\n",
    );

    let first = run_detached(&repo, &state);
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    assert!(first.status.success(), "{first:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse first run");
    let first_session = first_json["data"]["runtime_session_id"].clone();
    let port = first_json["data"]["services"][0]["port"]
        .as_u64()
        .expect("runtime port") as u16;
    wait_for_tcp_port(port, false);

    let second = run_detached(&repo, &state);
    assert!(second.status.success(), "{second:?}");
    let second_json: Value = serde_json::from_slice(&second.stdout).expect("parse second run");
    assert_eq!(second_json["changed"], true);
    assert_ne!(second_json["data"]["runtime_session_id"], first_session);
    assert_eq!(second_json["data"]["services"][0]["port"], port);
    assert!(tcp_port_is_open(port));

    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let first_status = connection
        .query_row(
            "SELECT status FROM runtime_sessions WHERE id = ?1",
            [first_session.as_str().expect("session ID")],
            |row| row.get::<_, String>(0),
        )
        .expect("read reconciled session");
    assert_eq!(first_status, "stopped");
}

#[test]
fn failed_replacement_preparation_finalizes_the_cleaned_predecessor() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next(&repo);

    let first = run_detached(&repo, &state);
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    assert!(first.status.success(), "{first:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse first run");
    let first_session = first_json["data"]["runtime_session_id"]
        .as_str()
        .expect("first session ID")
        .to_owned();
    let port = u16::try_from(
        first_json["data"]["services"][0]["port"]
            .as_u64()
            .expect("runtime port"),
    )
    .expect("TCP port");
    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let process_group = connection
        .query_row(
            "SELECT process_group_id FROM runtime_processes WHERE session_id = ?1",
            [&first_session],
            |row| row.get::<_, u32>(0),
        )
        .expect("read runtime process group");
    drop(connection);
    terminate_process_group(process_group).expect("terminate first runtime");
    wait_for_tcp_port(port, false);
    let foreign = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
        .expect("occupy the established allocation");

    let failed = run_detached(&repo, &state);
    assert!(!failed.status.success(), "{failed:?}");
    let failed_json: Value = serde_json::from_slice(&failed.stdout).expect("parse failed run");
    assert_eq!(failed_json["error"]["code"], "ESTABLISHED_PORT_OCCUPIED");
    assert_no_active_runtime(&state);
    let connection = Connection::open(state.join("registry.sqlite3")).expect("reopen registry");
    let predecessor_status = connection
        .query_row(
            "SELECT status FROM runtime_sessions WHERE id = ?1",
            [&first_session],
            |row| row.get::<_, String>(0),
        )
        .expect("read predecessor status");
    assert_eq!(predecessor_status, "stopped");
    drop(connection);

    let repeated = run_detached(&repo, &state);
    assert!(!repeated.status.success(), "{repeated:?}");
    let repeated_json: Value =
        serde_json::from_slice(&repeated.stdout).expect("parse repeated failure");
    assert_eq!(repeated_json["error"]["code"], "ESTABLISHED_PORT_OCCUPIED");
    drop(foreign);

    let recovered = run_detached(&repo, &state);
    assert!(recovered.status.success(), "{recovered:?}");
    let recovered_json: Value =
        serde_json::from_slice(&recovered.stdout).expect("parse recovered run");
    assert_ne!(recovered_json["data"]["runtime_session_id"], first_session);
}

#[test]
fn run_takes_over_a_stopping_replacement_after_owner_pid_reuse() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next(&repo);

    let first = run_detached(&repo, &state);
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    assert!(first.status.success(), "{first:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse first run");
    let first_session = first_json["data"]["runtime_session_id"]
        .as_str()
        .expect("first session ID")
        .to_owned();
    let live_owner = current_process_identity().expect("read live owner identity");
    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    connection
        .execute(
            "UPDATE runtime_sessions
             SET status = 'stopping', launcher_pid = ?2, launcher_process_start = ?3
             WHERE id = ?1",
            params![first_session, live_owner.pid, live_owner.process_start],
        )
        .expect("record live replacement owner");
    drop(connection);

    let mut recovered = run_detached_command(&repo, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start replacement recovery");
    thread::sleep(Duration::from_millis(250));
    assert!(
        recovered
            .try_wait()
            .expect("check matching owner identity")
            .is_none(),
        "a matching live owner identity must retain the transition"
    );
    let connection = Connection::open(state.join("registry.sqlite3")).expect("reopen registry");
    connection
        .execute(
            "UPDATE runtime_sessions
             SET launcher_process_start = 'different-process-start'
             WHERE id = ?1",
            [&first_session],
        )
        .expect("simulate transition-owner PID reuse");
    drop(connection);

    let recovered = recovered
        .wait_with_output()
        .expect("finish replacement recovery");
    assert!(recovered.status.success(), "{recovered:?}");
    let recovered_json: Value =
        serde_json::from_slice(&recovered.stdout).expect("parse recovered run");
    assert_eq!(recovered_json["changed"], true);
    assert_ne!(recovered_json["data"]["runtime_session_id"], first_session);
    let connection = Connection::open(state.join("registry.sqlite3")).expect("reopen registry");
    assert_eq!(
        connection
            .query_row(
                "SELECT status FROM runtime_sessions WHERE id = ?1",
                [&first_session],
                |row| row.get::<_, String>(0),
            )
            .expect("read recovered predecessor"),
        "stopped"
    );
}

#[test]
fn detached_run_preserves_a_runtime_during_a_transient_readiness_drop() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    let drop_trigger = temp.path().join("drop-listener");
    let dropped_marker = temp.path().join("listener-dropped");
    let recover_trigger = temp.path().join("recover-listener");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    let script = format!(
        "#!/bin/sh\nexec python3 - \"$PORT\" \"{}\" \"{}\" \"{}\" <<'PY'\nimport socket\nimport sys\nimport time\nfrom pathlib import Path\n\ndef listen(port):\n    listener = socket.socket()\n    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n    listener.bind((\"127.0.0.1\", port))\n    listener.listen()\n    return listener\n\nport = int(sys.argv[1])\ndrop_trigger = Path(sys.argv[2])\ndropped_marker = Path(sys.argv[3])\nrecover_trigger = Path(sys.argv[4])\nlistener = listen(port)\nif not dropped_marker.exists():\n    while not drop_trigger.exists():\n        time.sleep(0.01)\n    listener.close()\n    dropped_marker.touch()\n    while not recover_trigger.exists():\n        time.sleep(0.01)\n    listener = listen(port)\ntime.sleep(30)\nPY\n",
        drop_trigger.display(),
        dropped_marker.display(),
        recover_trigger.display(),
    );
    install_fake_next_script(&repo, &script);

    let first = run_detached(&repo, &state);
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    assert!(first.status.success(), "{first:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse first run");
    let first_session = first_json["data"]["runtime_session_id"].clone();
    let port = first_json["data"]["services"][0]["port"]
        .as_u64()
        .expect("runtime port") as u16;

    fs::write(&drop_trigger, []).expect("request listener drop");
    wait_for_path(&dropped_marker);
    wait_for_tcp_port(port, false);
    let mut repeated = run_detached_command(&repo, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start repeated run during listener drop");
    thread::sleep(Duration::from_millis(150));
    assert!(
        repeated.try_wait().expect("check repeated run").is_none(),
        "repeated run did not confirm sustained readiness loss"
    );
    fs::write(&recover_trigger, []).expect("restore listener");

    let repeated = repeated.wait_with_output().expect("wait for repeated run");
    assert!(repeated.status.success(), "{repeated:?}");
    let repeated_json: Value =
        serde_json::from_slice(&repeated.stdout).expect("parse repeated run");
    assert_eq!(repeated_json["changed"], false);
    assert_eq!(repeated_json["data"]["runtime_session_id"], first_session);
    assert_eq!(repeated_json["data"]["services"][0]["port"], port);
    wait_for_tcp_port(port, true);

    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let session_count = connection
        .query_row("SELECT COUNT(*) FROM runtime_sessions", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect("count runtime sessions");
    assert_eq!(session_count, 1);
}

#[test]
fn stop_refuses_a_process_identity_mismatch() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next(&repo);
    let started = run_detached(&repo, &state);
    assert!(started.status.success(), "{started:?}");
    let started_json: Value = serde_json::from_slice(&started.stdout).expect("parse run response");
    let port = started_json["data"]["services"][0]["port"]
        .as_u64()
        .expect("runtime port") as u16;

    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let process_group_id = connection
        .query_row(
            "SELECT process_group_id FROM runtime_processes LIMIT 1",
            [],
            |row| row.get::<_, u32>(0),
        )
        .expect("read process group");
    let _cleanup = ProcessGroupCleanup(process_group_id);
    connection
        .execute(
            "UPDATE runtime_processes SET process_start = 'not-the-recorded-process'",
            [],
        )
        .expect("tamper process identity");

    let stopped = run_stop(&repo, &state);
    assert!(!stopped.status.success(), "{stopped:?}");
    let stopped_json: Value = serde_json::from_slice(&stopped.stdout).expect("parse stop error");
    assert_eq!(stopped_json["error"]["code"], "RUNTIME_OWNERSHIP_MISMATCH");
    assert_eq!(stopped_json["changed"], true);
    assert!(tcp_port_is_open(port), "mismatched process was terminated");
}

#[test]
fn stop_can_claim_a_runtime_that_has_spawned_but_is_still_starting() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(&repo, &format!("#!/bin/sh\nsleep 2\n{FAKE_TCP_LISTENER}\n"));

    let running = run_detached_command(&repo, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start delayed runtime");
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let process_recorded = Connection::open(state.join("registry.sqlite3"))
            .ok()
            .and_then(|connection| {
                connection
                    .query_row(
                        "SELECT EXISTS(
                            SELECT 1
                            FROM runtime_sessions
                            JOIN runtime_processes ON runtime_processes.session_id = runtime_sessions.id
                            WHERE runtime_sessions.status = 'starting'
                        )",
                        [],
                        |row| row.get::<_, bool>(0),
                    )
                    .ok()
            })
            .unwrap_or(false);
        if process_recorded {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "runtime process was not recorded while starting"
        );
        thread::sleep(Duration::from_millis(20));
    }

    let stopped = run_stop(&repo, &state);
    assert!(stopped.status.success(), "{stopped:?}");
    let stopped_json: Value = serde_json::from_slice(&stopped.stdout).expect("parse stop response");
    assert_eq!(stopped_json["changed"], true);
    let run_output = running
        .wait_with_output()
        .expect("wait for interrupted run");
    assert!(!run_output.status.success(), "{run_output:?}");
    let run_json: Value = serde_json::from_slice(&run_output.stdout).expect("parse run failure");
    assert_eq!(run_json["error"]["code"], "RUNTIME_SESSION_CHANGED");

    let status = run_status(&repo, &state);
    assert!(status.status.success(), "{status:?}");
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("parse status response");
    assert_eq!(status_json["data"]["services"][0]["readiness"], "stopped");
}

#[test]
fn concurrent_stops_converge_on_one_runtime() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next(&repo);
    let started = run_detached(&repo, &state);
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    assert!(started.status.success(), "{started:?}");

    let first = stop_command(&repo, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start first stop");
    let second = stop_command(&repo, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start second stop");
    let first = first.wait_with_output().expect("wait for first stop");
    let second = second.wait_with_output().expect("wait for second stop");
    assert!(first.status.success(), "{first:?}");
    assert!(second.status.success(), "{second:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse first stop");
    let second_json: Value = serde_json::from_slice(&second.stdout).expect("parse second stop");
    assert_eq!(
        first_json["data"]["runtime_session_id"],
        second_json["data"]["runtime_session_id"]
    );

    let status = run_status(&repo, &state);
    assert!(status.status.success(), "{status:?}");
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("parse status response");
    assert_eq!(status_json["data"]["services"][0]["readiness"], "stopped");
}

#[test]
fn invalid_json_arguments_use_the_json_error_contract() {
    let _test_lock = lock_cli_test();
    let output = Command::new(env!("CARGO_BIN_EXE_duckflap"))
        .args(["env", "--json", "--shell", "zsh"])
        .output()
        .expect("run duckflap with invalid arguments");

    assert!(!output.status.success());
    assert!(output.stderr.is_empty(), "stderr was not empty: {output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse error response");
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["command"], "env");
    assert_eq!(json["ok"], false);
    assert_eq!(json["changed"], false);
    assert_eq!(json["error"]["code"], "INVALID_ARGUMENTS");

    let invalid_wait = Command::new(env!("CARGO_BIN_EXE_duckflap"))
        .args(["wait", "--timeout", "0", "--json"])
        .output()
        .expect("run duckflap wait with invalid arguments");
    assert!(!invalid_wait.status.success());
    assert!(
        invalid_wait.stderr.is_empty(),
        "stderr was not empty: {invalid_wait:?}"
    );
    let wait_json: Value =
        serde_json::from_slice(&invalid_wait.stdout).expect("parse wait error response");
    assert_eq!(wait_json["command"], "wait");
    assert_eq!(wait_json["changed"], false);
    assert_eq!(wait_json["error"]["code"], "INVALID_ARGUMENTS");

    let invalid_inspect = Command::new(env!("CARGO_BIN_EXE_duckflap"))
        .args(["inspect", "0", "--json"])
        .output()
        .expect("run duckflap inspect with invalid arguments");
    assert!(!invalid_inspect.status.success());
    assert!(
        invalid_inspect.stderr.is_empty(),
        "stderr was not empty: {invalid_inspect:?}"
    );
    let inspect_json: Value =
        serde_json::from_slice(&invalid_inspect.stdout).expect("parse inspect error response");
    assert_eq!(inspect_json["command"], "inspect");
    assert_eq!(inspect_json["changed"], false);
    assert_eq!(inspect_json["error"]["code"], "INVALID_ARGUMENTS");

    let invalid_reallocate = Command::new(env!("CARGO_BIN_EXE_duckflap"))
        .args(["reallocate", "--unknown", "--json"])
        .output()
        .expect("run duckflap reallocate with invalid arguments");
    assert!(!invalid_reallocate.status.success());
    assert!(
        invalid_reallocate.stderr.is_empty(),
        "stderr was not empty: {invalid_reallocate:?}"
    );
    let reallocate_json: Value = serde_json::from_slice(&invalid_reallocate.stdout)
        .expect("parse reallocate error response");
    assert_eq!(reallocate_json["command"], "reallocate");
    assert_eq!(reallocate_json["changed"], false);
    assert_eq!(reallocate_json["error"]["code"], "INVALID_ARGUMENTS");

    let invalid_doctor = Command::new(env!("CARGO_BIN_EXE_duckflap"))
        .args(["doctor", "--unknown", "--json"])
        .output()
        .expect("run duckflap doctor with invalid arguments");
    assert!(!invalid_doctor.status.success());
    assert!(invalid_doctor.stderr.is_empty(), "{invalid_doctor:?}");
    let doctor_json: Value =
        serde_json::from_slice(&invalid_doctor.stdout).expect("parse doctor error response");
    assert_eq!(doctor_json["command"], "doctor");
    assert_eq!(doctor_json["changed"], false);
    assert_eq!(doctor_json["error"]["code"], "INVALID_ARGUMENTS");
}

#[test]
fn quoted_next_port_argument_is_ambiguous_and_creates_no_state() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev \"-p\" 3000" }
        }"#,
    );

    let output = run_env(&repo, &state);

    assert!(!output.status.success());
    assert!(output.stderr.is_empty(), "stderr was not empty: {output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse error response");
    assert_eq!(json["changed"], false);
    assert_eq!(json["error"]["code"], "AMBIGUOUS_NEXT_SCRIPT");
    assert!(!state.exists());
}

#[test]
fn explicit_next_hostname_is_rejected_and_creates_no_state() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev --hostname localhost" }
        }"#,
    );

    let output = run_env(&repo, &state);

    assert!(!output.status.success());
    assert!(output.stderr.is_empty(), "stderr was not empty: {output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse error response");
    assert_eq!(json["changed"], false);
    assert_eq!(json["error"]["code"], "EXPLICIT_HOSTNAME");
    assert!(!state.exists());
}

#[test]
fn concurrent_env_calls_report_only_the_committed_change() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );

    let first = env_command(&repo, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start first duckflap env");
    let second = env_command(&repo, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start second duckflap env");
    let first = first.wait_with_output().expect("wait for first env");
    let second = second.wait_with_output().expect("wait for second env");

    assert!(first.status.success(), "{first:?}");
    assert!(second.status.success(), "{second:?}");
    assert!(first.stderr.is_empty(), "stderr was not empty: {first:?}");
    assert!(second.stderr.is_empty(), "stderr was not empty: {second:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse first response");
    let second_json: Value = serde_json::from_slice(&second.stdout).expect("parse second response");
    let changes = [
        first_json["changed"].as_bool().expect("first changed flag"),
        second_json["changed"]
            .as_bool()
            .expect("second changed flag"),
    ];
    assert!(changes.contains(&true));
    assert_eq!(
        first_json["data"]["project_instance_id"],
        second_json["data"]["project_instance_id"]
    );
    assert_eq!(
        first_json["data"]["services"][0]["port"],
        second_json["data"]["services"][0]["port"]
    );
}

#[test]
fn linked_worktrees_receive_distinct_stable_allocations_concurrently() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let linked = temp.path().join("linked");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    add_supabase_config(&repo, "project_id = \"linked-test\"");
    add_linked_worktree(&repo, &linked);

    let state_paths = StatePaths::from_root(state.clone());
    drop(Registry::open_mutating(&state_paths).expect("initialize registry"));
    let gate = Connection::open(state_paths.registry()).expect("open registry gate");
    gate.execute_batch("BEGIN IMMEDIATE")
        .expect("hold registry write gate");

    let mut first = env_command(&repo, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start primary worktree env");
    let mut second = env_command(&linked, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start linked worktree env");
    thread::sleep(Duration::from_millis(100));
    assert!(
        first.try_wait().expect("check primary process").is_none(),
        "primary process did not wait at the registry gate"
    );
    assert!(
        second.try_wait().expect("check linked process").is_none(),
        "linked process did not wait at the registry gate"
    );
    gate.execute_batch("COMMIT")
        .expect("release registry write gate");

    let first = first.wait_with_output().expect("wait for primary env");
    let second = second.wait_with_output().expect("wait for linked env");
    assert!(first.status.success(), "{first:?}");
    assert!(second.status.success(), "{second:?}");
    assert!(first.stderr.is_empty(), "stderr was not empty: {first:?}");
    assert!(second.stderr.is_empty(), "stderr was not empty: {second:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse primary response");
    let second_json: Value = serde_json::from_slice(&second.stdout).expect("parse linked response");

    assert_eq!(first_json["changed"], true);
    assert_eq!(second_json["changed"], true);
    assert_eq!(
        first_json["data"]["project_id"],
        second_json["data"]["project_id"]
    );
    assert_ne!(
        first_json["data"]["project_instance_id"],
        second_json["data"]["project_instance_id"]
    );
    let first_ports = first_json["data"]["services"]
        .as_array()
        .expect("primary services")
        .iter()
        .map(|service| service["port"].as_u64().expect("primary port"))
        .collect::<Vec<_>>();
    let second_ports = second_json["data"]["services"]
        .as_array()
        .expect("linked services")
        .iter()
        .map(|service| service["port"].as_u64().expect("linked port"))
        .collect::<Vec<_>>();
    assert_eq!(first_ports.len(), 7);
    assert_eq!(second_ports.len(), 7);
    assert!(
        first_ports.iter().all(|port| !second_ports.contains(port)),
        "linked worktrees shared a port: {first_ports:?} and {second_ports:?}"
    );

    let first_again = run_env(&repo, &state);
    let second_again = run_env(&linked, &state);
    assert!(first_again.status.success(), "{first_again:?}");
    assert!(second_again.status.success(), "{second_again:?}");
    let first_again: Value =
        serde_json::from_slice(&first_again.stdout).expect("parse repeated primary response");
    let second_again: Value =
        serde_json::from_slice(&second_again.stdout).expect("parse repeated linked response");
    assert_eq!(first_again["changed"], false);
    assert_eq!(second_again["changed"], false);
    assert_eq!(
        first_again["data"]["services"],
        first_json["data"]["services"]
    );
    assert_eq!(
        second_again["data"]["services"],
        second_json["data"]["services"]
    );
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
    assert!(git_output(&linked, &["status", "--porcelain"]).is_empty());
}

#[test]
fn no_supported_services_is_json_and_creates_no_state() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "react": "latest" },
            "scripts": { "dev": "vite" }
        }"#,
    );

    let output = run_env(&repo, &state);
    assert!(!output.status.success());
    assert!(output.stderr.is_empty(), "stderr was not empty: {output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse error response");
    assert_eq!(json["ok"], false);
    assert_eq!(json["changed"], false);
    assert_eq!(json["error"]["code"], "NO_SUPPORTED_SERVICES");
    assert!(!state.exists());
}

#[test]
fn release_is_idempotent_without_service_detection_and_preserves_identity() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    let env_output = run_env(&repo, &state);
    assert!(env_output.status.success(), "{env_output:?}");
    let env_json: Value = serde_json::from_slice(&env_output.stdout).expect("parse env response");
    fs::remove_file(repo.join("package.json")).expect("remove package manifest");

    let first = run_release(&repo, &state);
    assert!(first.status.success(), "{first:?}");
    assert!(first.stderr.is_empty(), "stderr was not empty: {first:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse release response");
    assert_eq!(first_json["schema_version"], 1);
    assert_eq!(first_json["command"], "release");
    assert_eq!(first_json["ok"], true);
    assert_eq!(first_json["changed"], true);
    assert_eq!(
        first_json["data"]["project_id"],
        env_json["data"]["project_id"]
    );
    assert_eq!(
        first_json["data"]["project_instance_id"],
        env_json["data"]["project_instance_id"]
    );
    assert_eq!(
        first_json["data"]["released_services"][0]["service_key"],
        "web"
    );
    assert_eq!(
        first_json["data"]["released_services"][0]["protocol"],
        "tcp"
    );
    assert_eq!(
        first_json["data"]["released_services"][0]["port"],
        env_json["data"]["services"][0]["port"]
    );

    let status = run_status(&repo, &state);
    assert!(status.status.success(), "{status:?}");
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("parse status response");
    assert_eq!(
        status_json["data"]["project_id"],
        env_json["data"]["project_id"]
    );
    assert_eq!(
        status_json["data"]["project_instance_id"],
        env_json["data"]["project_instance_id"]
    );
    assert_eq!(
        status_json["data"]["services"].as_array().map(Vec::len),
        Some(0)
    );

    let second = run_release(&repo, &state);
    assert!(second.status.success(), "{second:?}");
    let second_json: Value = serde_json::from_slice(&second.stdout).expect("parse repeat response");
    assert_eq!(second_json["changed"], false);
    assert_eq!(
        second_json["data"]["project_instance_id"],
        env_json["data"]["project_instance_id"]
    );
    assert_eq!(
        second_json["data"]["released_services"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
}

#[test]
fn release_on_unseen_state_creates_nothing() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );

    let output = run_release(&repo, &state);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "stderr was not empty: {output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse release response");
    assert_eq!(json["changed"], false);
    assert!(json["data"]["project_id"].is_null());
    assert!(json["data"]["project_instance_id"].is_null());
    assert_eq!(
        json["data"]["released_services"].as_array().map(Vec::len),
        Some(0)
    );
    assert!(!state.exists());
}

#[test]
fn release_on_an_unknown_worktree_does_not_change_existing_state() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let known = temp.path().join("known");
    let unknown = temp.path().join("unknown");
    let state = temp.path().join("state");
    let manifest = r#"{
        "dependencies": { "next": "15.0.0" },
        "scripts": { "dev": "next dev" }
    }"#;
    initialize_repo(&known, manifest);
    initialize_repo(&unknown, manifest);
    let env_output = run_env(&known, &state);
    assert!(env_output.status.success(), "{env_output:?}");
    let registry_path = state.join("registry.sqlite3");
    let registry_before = fs::read(&registry_path).expect("read registry before release");

    let output = run_release(&unknown, &state);
    assert!(output.status.success(), "{output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse release response");
    assert_eq!(json["changed"], false);
    assert!(json["data"]["project_id"].is_null());
    assert!(json["data"]["project_instance_id"].is_null());
    assert_eq!(
        fs::read(&registry_path).expect("read registry after release"),
        registry_before
    );
}

#[test]
fn release_does_not_affect_a_linked_sibling() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let linked = temp.path().join("linked");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    add_linked_worktree(&repo, &linked);
    let primary_env = run_env(&repo, &state);
    let sibling_env = run_env(&linked, &state);
    assert!(primary_env.status.success(), "{primary_env:?}");
    assert!(sibling_env.status.success(), "{sibling_env:?}");
    let primary_json: Value =
        serde_json::from_slice(&primary_env.stdout).expect("parse primary env");
    let sibling_json: Value =
        serde_json::from_slice(&sibling_env.stdout).expect("parse sibling env");

    let released = run_release(&repo, &state);
    assert!(released.status.success(), "{released:?}");
    let sibling_status = run_status(&linked, &state);
    assert!(sibling_status.status.success(), "{sibling_status:?}");
    let sibling_status_json: Value =
        serde_json::from_slice(&sibling_status.stdout).expect("parse sibling status");

    assert_ne!(
        primary_json["data"]["project_instance_id"],
        sibling_json["data"]["project_instance_id"]
    );
    assert_eq!(
        sibling_status_json["data"]["project_instance_id"],
        sibling_json["data"]["project_instance_id"]
    );
    assert_eq!(
        sibling_status_json["data"]["services"][0]["port"],
        sibling_json["data"]["services"][0]["port"]
    );
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
    assert!(git_output(&linked, &["status", "--porcelain"]).is_empty());
}

#[test]
fn release_does_not_stop_a_listener() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    let env_output = run_env(&repo, &state);
    assert!(env_output.status.success(), "{env_output:?}");
    let env_json: Value = serde_json::from_slice(&env_output.stdout).expect("parse env response");
    let port = u16::try_from(
        env_json["data"]["services"][0]["port"]
            .as_u64()
            .expect("numeric port"),
    )
    .expect("TCP port");
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))
        .expect("start foreign listener");

    let released = run_release(&repo, &state);
    assert!(released.status.success(), "{released:?}");
    let connection = TcpStream::connect(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
        .expect("listener remains reachable");

    drop(connection);
    drop(listener);
}

#[test]
fn concurrent_releases_report_only_the_committed_change() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    let env_output = run_env(&repo, &state);
    assert!(env_output.status.success(), "{env_output:?}");

    let gate = Connection::open(state.join("registry.sqlite3")).expect("open registry gate");
    gate.execute_batch("BEGIN IMMEDIATE")
        .expect("hold registry write gate");
    let mut first = release_command(&repo, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start first release");
    let mut second = release_command(&repo, &state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start second release");
    thread::sleep(Duration::from_millis(100));
    assert!(
        first.try_wait().expect("check first release").is_none(),
        "first release did not wait at the registry gate"
    );
    assert!(
        second.try_wait().expect("check second release").is_none(),
        "second release did not wait at the registry gate"
    );
    gate.execute_batch("COMMIT")
        .expect("release registry write gate");

    let first = first.wait_with_output().expect("wait for first release");
    let second = second.wait_with_output().expect("wait for second release");
    assert!(first.status.success(), "{first:?}");
    assert!(second.status.success(), "{second:?}");
    assert!(first.stderr.is_empty(), "stderr was not empty: {first:?}");
    assert!(second.stderr.is_empty(), "stderr was not empty: {second:?}");
    let first_json: Value = serde_json::from_slice(&first.stdout).expect("parse first release");
    let second_json: Value = serde_json::from_slice(&second.stdout).expect("parse second release");
    let mut changes = [
        first_json["changed"].as_bool().expect("first changed flag"),
        second_json["changed"]
            .as_bool()
            .expect("second changed flag"),
    ];
    changes.sort_unstable();
    let mut released_counts = [
        first_json["data"]["released_services"]
            .as_array()
            .map(Vec::len)
            .expect("first released services"),
        second_json["data"]["released_services"]
            .as_array()
            .map(Vec::len)
            .expect("second released services"),
    ];
    released_counts.sort_unstable();

    assert_eq!(changes, [false, true]);
    assert_eq!(released_counts, [0, 1]);
    let status = run_status(&repo, &state);
    assert!(status.status.success(), "{status:?}");
    let status_json: Value = serde_json::from_slice(&status.stdout).expect("parse status response");
    assert_eq!(
        status_json["data"]["services"].as_array().map(Vec::len),
        Some(0)
    );
}

#[test]
fn status_on_an_unseen_worktree_creates_no_state() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );

    let output = run_status(&repo, &state);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "stderr was not empty: {output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse status response");
    assert_eq!(json["ok"], true);
    assert_eq!(json["changed"], false);
    assert!(json["data"]["project_id"].is_null());
    assert!(json["data"]["project_instance_id"].is_null());
    assert_eq!(json["data"]["services"].as_array().map(Vec::len), Some(0));
    assert!(json["data"]["runtime_session_id"].is_null());
    assert!(!state.exists());

    let human = run_status_human(&repo, &state);
    assert!(human.status.success(), "{human:?}");
    assert!(human.stderr.is_empty(), "stderr was not empty: {human:?}");
    assert_eq!(
        String::from_utf8(human.stdout).expect("UTF-8 human status"),
        "project: none\nproject instance: none\nruntime session: none\nservice: none\n"
    );
    assert!(!state.exists());
}

#[test]
fn status_reads_allocations_without_changing_the_registry() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    let env_output = run_env(&repo, &state);
    assert!(env_output.status.success(), "{env_output:?}");
    let env_json: Value = serde_json::from_slice(&env_output.stdout).expect("parse env response");
    let registry_path = state.join("registry.sqlite3");
    let registry_before = fs::read(&registry_path).expect("read registry before status");
    fs::remove_file(repo.join("package.json")).expect("remove package manifest");

    let status_output = run_status(&repo, &state);
    assert!(status_output.status.success(), "{status_output:?}");
    assert!(
        status_output.stderr.is_empty(),
        "stderr was not empty: {status_output:?}"
    );
    let status_json: Value =
        serde_json::from_slice(&status_output.stdout).expect("parse status response");
    assert_eq!(status_json["changed"], false);
    assert_eq!(
        status_json["data"]["project_id"],
        env_json["data"]["project_id"]
    );
    assert_eq!(
        status_json["data"]["project_instance_id"],
        env_json["data"]["project_instance_id"]
    );
    assert_eq!(
        status_json["data"]["services"][0]["port"],
        env_json["data"]["services"][0]["port"]
    );
    assert_eq!(
        status_json["data"]["services"][0]["owner_project_instance_id"],
        env_json["data"]["project_instance_id"]
    );
    assert_eq!(
        status_json["data"]["services"][0]["readiness"],
        "not_started"
    );
    assert!(status_json["data"]["runtime_session_id"].is_null());
    assert_eq!(
        fs::read(&registry_path).expect("read registry after status"),
        registry_before
    );

    let human = run_status_human(&repo, &state);
    assert!(human.status.success(), "{human:?}");
    assert!(human.stderr.is_empty(), "stderr was not empty: {human:?}");
    let project_id = env_json["data"]["project_id"].as_str().expect("project ID");
    let project_instance_id = env_json["data"]["project_instance_id"]
        .as_str()
        .expect("project instance ID");
    let port = env_json["data"]["services"][0]["port"]
        .as_u64()
        .expect("web port");
    assert_eq!(
        String::from_utf8(human.stdout).expect("UTF-8 human status"),
        format!(
            "project: {project_id}\nproject instance: {project_instance_id}\nruntime session: none\nservice: web tcp/{port} not_started http://127.0.0.1:{port}\n"
        )
    );
    assert_eq!(
        fs::read(&registry_path).expect("read registry after human status"),
        registry_before
    );
}

#[test]
fn doctor_reports_supported_unallocated_project_without_creating_state() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );

    let output = run_doctor(&repo, &state);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse doctor response");
    assert_eq!(json["command"], "doctor");
    assert_eq!(json["ok"], true);
    assert_eq!(json["changed"], false);
    assert_eq!(json["data"]["healthy"], true);
    let checks = json["data"]["checks"].as_array().expect("doctor checks");
    let missing = checks
        .iter()
        .find(|check| check["code"] == "ALLOCATION_MISSING")
        .expect("missing allocation check");
    assert_eq!(missing["status"], "warning");
    assert_eq!(missing["service_key"], "web");
    assert_eq!(missing["remediation"]["command"], "duckflap env --json");
    assert_eq!(missing["remediation"]["changes_allocations"], true);
    assert!(!state.exists(), "doctor created Duckflap state");
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn doctor_reports_available_allocation_without_mutating_registry() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    let registry_path = state.join("registry.sqlite3");
    let registry_before = fs::read(&registry_path).expect("read registry before doctor");

    let output = run_doctor(&repo, &state);
    assert!(output.status.success(), "{output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse doctor response");
    assert_eq!(json["changed"], false);
    assert_eq!(json["data"]["healthy"], true);
    assert!(json["data"]["project_id"].is_string());
    let checks = json["data"]["checks"].as_array().expect("doctor checks");
    assert!(checks.iter().any(|check| {
        check["code"] == "ALLOCATION_AVAILABLE"
            && check["status"] == "pass"
            && check["service_key"] == "web"
    }));
    assert_eq!(
        fs::read(&registry_path).expect("read registry after doctor"),
        registry_before
    );
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

#[test]
fn doctor_warns_about_historical_allocations() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    add_supabase_config(&repo, "project_id = \"doctor-historical\"");
    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    fs::write(
        repo.join("package.json"),
        r#"{ "dependencies": {}, "scripts": {} }"#,
    )
    .expect("disable Next.js detection");
    let registry_path = state.join("registry.sqlite3");
    let registry_before = fs::read(&registry_path).expect("read registry before doctor");
    let worktree_before = git_output(&repo, &["status", "--porcelain"]);

    let output = run_doctor(&repo, &state);
    assert!(output.status.success(), "{output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse doctor response");
    assert_eq!(json["data"]["healthy"], true);
    let historical = json["data"]["checks"]
        .as_array()
        .expect("doctor checks")
        .iter()
        .find(|check| check["code"] == "HISTORICAL_ALLOCATION")
        .expect("historical allocation check");
    assert_eq!(historical["status"], "warning");
    assert_eq!(historical["service_key"], "web");
    assert_eq!(
        historical["remediation"]["command"],
        "duckflap release --json"
    );
    assert_eq!(historical["remediation"]["changes_allocations"], true);
    assert_eq!(
        fs::read(&registry_path).expect("read registry after doctor"),
        registry_before
    );
    assert_eq!(
        git_output(&repo, &["status", "--porcelain"]),
        worktree_before
    );
}

#[test]
fn doctor_reports_foreign_listener_with_explicit_reallocation() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    let environment_json: Value =
        serde_json::from_slice(&environment.stdout).expect("parse environment");
    let port = u16::try_from(
        environment_json["data"]["services"][0]["port"]
            .as_u64()
            .expect("allocated port"),
    )
    .expect("u16 port");
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
        .expect("start foreign listener");
    let registry_path = state.join("registry.sqlite3");
    let registry_before = fs::read(&registry_path).expect("read registry before doctor");

    let output = run_doctor(&repo, &state);
    assert!(output.status.success(), "{output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse doctor response");
    assert_eq!(json["ok"], true);
    assert_eq!(json["changed"], false);
    assert_eq!(json["data"]["healthy"], false);
    let conflict = json["data"]["checks"]
        .as_array()
        .expect("doctor checks")
        .iter()
        .find(|check| check["code"] == "ALLOCATION_CONFLICT")
        .expect("allocation conflict");
    assert_eq!(conflict["status"], "failure");
    assert_eq!(conflict["port"], port);
    assert_eq!(
        conflict["remediation"]["command"],
        "duckflap reallocate --json"
    );
    assert_eq!(conflict["remediation"]["changes_allocations"], true);
    assert_eq!(
        fs::read(&registry_path).expect("read registry after doctor"),
        registry_before
    );
    drop(listener);
}

#[test]
fn doctor_reports_a_healthy_managed_runtime() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next(&repo);
    let started = run_detached(&repo, &state);
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    assert!(started.status.success(), "{started:?}");

    let output = run_doctor(&repo, &state);
    assert!(output.status.success(), "{output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse doctor response");
    assert_eq!(json["data"]["healthy"], true);
    let checks = json["data"]["checks"].as_array().expect("doctor checks");
    assert!(checks.iter().any(|check| check["code"] == "SERVICE_READY"));
    assert!(checks.iter().any(|check| check["code"] == "RUNTIME_READY"));
}

#[test]
fn doctor_reports_abandoned_runtime_transitions_as_failures() {
    let _test_lock = lock_cli_test();
    for (index, status) in ["starting", "stopping"].into_iter().enumerate() {
        let temp = tempdir().expect("create temp dir");
        let repo = temp.path().join("repo");
        let state = temp.path().join(format!("state-{index}"));
        initialize_repo(
            &repo,
            r#"{
                "dependencies": { "next": "15.0.0" },
                "scripts": { "dev": "next dev" }
            }"#,
        );
        let environment = run_env(&repo, &state);
        assert!(environment.status.success(), "{environment:?}");
        let environment_json: Value =
            serde_json::from_slice(&environment.stdout).expect("parse environment");
        let project_instance_id = environment_json["data"]["project_instance_id"]
            .as_str()
            .expect("project instance ID");
        let session_id = format!("00000000-0000-4000-8000-00000000001{index}");
        let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
        connection
            .execute(
                "INSERT INTO runtime_sessions
                    (id, project_instance_id, status, launcher_pid, launcher_process_start)
                 VALUES (?1, ?2, ?3, ?4, 'dead-transition-owner')",
                params![session_id, project_instance_id, status, u32::MAX],
            )
            .expect("insert abandoned transition");
        drop(connection);
        let registry_path = state.join("registry.sqlite3");
        let registry_before = fs::read(&registry_path).expect("read registry before doctor");

        let output = run_doctor(&repo, &state);
        assert!(output.status.success(), "{output:?}");
        let json: Value = serde_json::from_slice(&output.stdout).expect("parse doctor response");
        assert_eq!(json["data"]["healthy"], false);
        let abandoned = json["data"]["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .find(|check| check["code"] == "RUNTIME_TRANSITION_ABANDONED")
            .expect("abandoned transition check");
        assert_eq!(abandoned["status"], "failure");
        assert_eq!(abandoned["remediation"]["command"], "duckflap stop --json");
        assert_eq!(abandoned["remediation"]["changes_allocations"], false);
        assert_eq!(
            fs::read(&registry_path).expect("read registry after doctor"),
            registry_before
        );

        let reallocated = run_reallocate(&repo, &state);
        assert!(!reallocated.status.success(), "{reallocated:?}");
        let reallocated_json: Value =
            serde_json::from_slice(&reallocated.stdout).expect("parse reallocate error");
        assert_eq!(reallocated_json["error"]["code"], "RUNTIME_ACTIVE");

        let stopped = run_stop(&repo, &state);
        assert!(stopped.status.success(), "{stopped:?}");
        let stopped_json: Value =
            serde_json::from_slice(&stopped.stdout).expect("parse stop response");
        assert_eq!(stopped_json["changed"], true);
        assert_no_active_runtime(&state);
    }
}

#[test]
fn doctor_marks_failed_runtime_retry_as_allocation_changing_when_services_were_added() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next_script(&repo, "#!/bin/sh\nexit 1\n");
    let failed = run_detached(&repo, &state);
    assert!(!failed.status.success(), "{failed:?}");
    add_supabase_config(&repo, "project_id = \"doctor-added-supabase\"");
    let registry_path = state.join("registry.sqlite3");
    let registry_before = fs::read(&registry_path).expect("read registry before doctor");

    let output = run_doctor(&repo, &state);
    assert!(output.status.success(), "{output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse doctor response");
    assert_eq!(json["data"]["healthy"], false);
    let failed_checks = json["data"]["checks"]
        .as_array()
        .expect("doctor checks")
        .iter()
        .filter(|check| check["code"] == "RUNTIME_FAILED")
        .collect::<Vec<_>>();
    assert!(!failed_checks.is_empty(), "missing failed-runtime checks");
    assert!(failed_checks.iter().all(|check| {
        check["remediation"]["command"] == "duckflap run --detach --json"
            && check["remediation"]["changes_allocations"] == true
    }));
    assert!(
        json["data"]["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .any(|check| check["code"] == "ALLOCATION_MISSING")
    );
    assert_eq!(
        fs::read(&registry_path).expect("read registry after doctor"),
        registry_before
    );
}

#[test]
fn doctor_recommends_stop_before_reallocating_an_active_conflict() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    install_fake_next(&repo);
    let started = run_detached(&repo, &state);
    let _cleanup = RuntimeCleanup::new(&repo, &state);
    assert!(started.status.success(), "{started:?}");
    let started_json: Value = serde_json::from_slice(&started.stdout).expect("parse run response");
    let port = u16::try_from(
        started_json["data"]["services"][0]["port"]
            .as_u64()
            .expect("runtime port"),
    )
    .expect("TCP port");
    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    let process_group_id = connection
        .query_row(
            "SELECT process_group_id FROM runtime_processes WHERE service_key = 'web'",
            [],
            |row| row.get::<_, u32>(0),
        )
        .expect("read runtime process group");
    drop(connection);
    terminate_process_group(process_group_id).expect("terminate managed runtime");
    wait_for_tcp_port(port, false);
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
        .expect("start foreign listener on stale allocation");

    let output = run_doctor(&repo, &state);
    assert!(output.status.success(), "{output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse doctor response");
    assert_eq!(json["data"]["healthy"], false);
    let conflict = json["data"]["checks"]
        .as_array()
        .expect("doctor checks")
        .iter()
        .find(|check| check["code"] == "ALLOCATION_CONFLICT")
        .expect("active allocation conflict");
    assert_eq!(conflict["remediation"]["command"], "duckflap stop --json");
    assert_eq!(conflict["remediation"]["changes_allocations"], false);

    let blocked = run_reallocate(&repo, &state);
    assert!(!blocked.status.success(), "{blocked:?}");
    let blocked_json: Value =
        serde_json::from_slice(&blocked.stdout).expect("parse blocked reallocation");
    assert_eq!(blocked_json["error"]["code"], "RUNTIME_ACTIVE");

    let stopped = run_stop(&repo, &state);
    assert!(stopped.status.success(), "{stopped:?}");
    let after_stop = run_doctor(&repo, &state);
    assert!(after_stop.status.success(), "{after_stop:?}");
    let after_stop_json: Value =
        serde_json::from_slice(&after_stop.stdout).expect("parse stopped doctor response");
    let stopped_conflict = after_stop_json["data"]["checks"]
        .as_array()
        .expect("doctor checks")
        .iter()
        .find(|check| check["code"] == "ALLOCATION_CONFLICT")
        .expect("stopped allocation conflict");
    assert_eq!(
        stopped_conflict["remediation"]["command"],
        "duckflap reallocate --json"
    );
    assert_eq!(stopped_conflict["remediation"]["changes_allocations"], true);
    drop(listener);
}

#[test]
fn doctor_returns_unhealthy_diagnosis_for_invalid_project_input() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(&repo, "not valid JSON");

    let output = run_doctor(&repo, &state);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse doctor response");
    assert_eq!(json["ok"], true);
    assert_eq!(json["changed"], false);
    assert_eq!(json["data"]["healthy"], false);
    assert!(
        json["data"]["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .any(|check| check["code"] == "INVALID_PACKAGE_JSON")
    );
    assert!(!state.exists(), "doctor created state for invalid input");
}

#[test]
fn doctor_returns_unhealthy_diagnosis_outside_git() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let working_directory = temp.path().join("cwd");
    let state = temp.path().join("state");
    fs::create_dir(&working_directory).expect("create working directory");

    let output = run_doctor(&working_directory, &state);
    assert!(output.status.success(), "{output:?}");
    let json: Value = serde_json::from_slice(&output.stdout).expect("parse doctor response");
    assert_eq!(json["ok"], true);
    assert_eq!(json["changed"], false);
    assert_eq!(json["data"]["healthy"], false);
    assert!(
        json["data"]["checks"]
            .as_array()
            .expect("doctor checks")
            .iter()
            .any(|check| check["code"] == "NOT_GIT_WORKTREE")
    );
    assert!(!state.exists(), "doctor created state outside Git");
}

#[test]
fn inspect_free_port_is_observational_and_supports_human_output() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let working_directory = temp.path().join("cwd");
    let state = temp.path().join("state");
    fs::create_dir(&working_directory).expect("create working directory");
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("reserve candidate port");
    let port = listener.local_addr().expect("candidate address").port();
    drop(listener);

    let inspected = run_inspect(&working_directory, &state, port, true);
    assert!(inspected.status.success(), "{inspected:?}");
    assert!(inspected.stderr.is_empty(), "{inspected:?}");
    let inspected_json: Value =
        serde_json::from_slice(&inspected.stdout).expect("parse inspection");
    assert_eq!(inspected_json["command"], "inspect");
    assert_eq!(inspected_json["changed"], false);
    assert_eq!(inspected_json["data"]["protocol"], "tcp");
    assert_eq!(inspected_json["data"]["port"], port);
    assert_eq!(inspected_json["data"]["state"], "free");
    assert!(inspected_json["data"]["allocation"].is_null());
    assert_eq!(inspected_json["data"]["process_evidence"], "not_applicable");
    assert_eq!(inspected_json["data"]["processes"], serde_json::json!([]));
    assert!(!state.exists(), "inspection created Duckflap state");

    let human = run_inspect(&working_directory, &state, port, false);
    assert!(human.status.success(), "{human:?}");
    assert!(human.stderr.is_empty(), "{human:?}");
    assert_eq!(
        String::from_utf8(human.stdout).expect("UTF-8 human output"),
        format!("tcp {port}: free\nallocation: none\n")
    );
    assert!(!state.exists(), "human inspection created Duckflap state");
}

#[test]
fn inspect_reports_a_foreign_listener_without_claiming_ownership() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let working_directory = temp.path().join("cwd");
    let state = temp.path().join("state");
    fs::create_dir(&working_directory).expect("create working directory");
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .expect("start foreign listener");
    let port = listener.local_addr().expect("listener address").port();

    let inspected = run_inspect(&working_directory, &state, port, true);
    assert!(inspected.status.success(), "{inspected:?}");
    let inspected_json: Value =
        serde_json::from_slice(&inspected.stdout).expect("parse inspection");
    assert_eq!(inspected_json["changed"], false);
    assert_eq!(inspected_json["data"]["state"], "listening");
    assert!(inspected_json["data"]["allocation"].is_null());
    assert!(matches!(
        inspected_json["data"]["process_evidence"].as_str(),
        Some("available" | "unavailable")
    ));
    assert!(!state.exists(), "inspection created Duckflap state");
}

#[test]
fn inspect_reports_managed_allocation_without_mutating_registry() {
    let _test_lock = lock_cli_test();
    let temp = tempdir().expect("create temp dir");
    let repo = temp.path().join("repo");
    let state = temp.path().join("state");
    initialize_repo(
        &repo,
        r#"{
            "dependencies": { "next": "15.0.0" },
            "scripts": { "dev": "next dev" }
        }"#,
    );
    let environment = run_env(&repo, &state);
    assert!(environment.status.success(), "{environment:?}");
    let environment_json: Value =
        serde_json::from_slice(&environment.stdout).expect("parse environment");
    let port = u16::try_from(
        environment_json["data"]["services"][0]["port"]
            .as_u64()
            .expect("allocated port"),
    )
    .expect("u16 allocated port");
    let registry_path = state.join("registry.sqlite3");
    let registry_before = fs::read(&registry_path).expect("read registry before inspection");

    let allocated = run_inspect(&repo, &state, port, true);
    assert!(allocated.status.success(), "{allocated:?}");
    let allocated_json: Value =
        serde_json::from_slice(&allocated.stdout).expect("parse allocated inspection");
    assert_eq!(allocated_json["data"]["state"], "free");
    assert_eq!(
        allocated_json["data"]["allocation"]["project_id"],
        environment_json["data"]["project_id"]
    );
    assert_eq!(
        allocated_json["data"]["allocation"]["project_instance_id"],
        environment_json["data"]["project_instance_id"]
    );
    assert_eq!(allocated_json["data"]["allocation"]["service_key"], "web");
    let canonical_repo = repo.canonicalize().expect("canonicalize repository");
    assert_eq!(
        allocated_json["data"]["allocation"]["worktree_root"],
        canonical_repo.to_string_lossy().as_ref()
    );

    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
        .expect("listen on allocated port");
    let listening = run_inspect(&repo, &state, port, true);
    assert!(listening.status.success(), "{listening:?}");
    let listening_json: Value =
        serde_json::from_slice(&listening.stdout).expect("parse listening inspection");
    assert_eq!(listening_json["data"]["state"], "listening");
    assert_eq!(listening_json["data"]["allocation"]["service_key"], "web");
    drop(listener);

    assert_eq!(
        fs::read(&registry_path).expect("read registry after inspection"),
        registry_before
    );
    assert!(git_output(&repo, &["status", "--porcelain"]).is_empty());
}

fn run_env(repo: &Path, state: &Path) -> Output {
    env_command(repo, state).output().expect("run duckflap env")
}

fn run_env_shell(repo: &Path, state: &Path, shell: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_duckflap"))
        .current_dir(repo)
        .env("DUCKFLAP_STATE_DIR", state)
        .args(["env", "--shell", shell])
        .output()
        .expect("run duckflap env shell output")
}

fn env_command(repo: &Path, state: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_duckflap"));
    command
        .current_dir(repo)
        .env("DUCKFLAP_STATE_DIR", state)
        .args(["env", "--json"]);
    command
}

fn run_status(repo: &Path, state: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_duckflap"))
        .current_dir(repo)
        .env("DUCKFLAP_STATE_DIR", state)
        .args(["status", "--json"])
        .output()
        .expect("run duckflap status")
}

fn run_status_human(repo: &Path, state: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_duckflap"))
        .current_dir(repo)
        .env("DUCKFLAP_STATE_DIR", state)
        .arg("status")
        .output()
        .expect("run human duckflap status")
}

fn run_doctor(repo: &Path, state: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_duckflap"))
        .current_dir(repo)
        .env("DUCKFLAP_STATE_DIR", state)
        .args(["doctor", "--json"])
        .output()
        .expect("run duckflap doctor")
}

fn run_inspect(working_directory: &Path, state: &Path, port: u16, json: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_duckflap"));
    command
        .current_dir(working_directory)
        .env("DUCKFLAP_STATE_DIR", state)
        .arg("inspect")
        .arg(port.to_string());
    if json {
        command.arg("--json");
    }
    command.output().expect("run duckflap inspect")
}

fn run_wait(repo: &Path, state: &Path, timeout_seconds: u64) -> Output {
    wait_command(repo, state, timeout_seconds)
        .output()
        .expect("run duckflap wait")
}

fn wait_command(repo: &Path, state: &Path, timeout_seconds: u64) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_duckflap"));
    command
        .current_dir(repo)
        .env("DUCKFLAP_STATE_DIR", state)
        .arg("wait")
        .arg("--timeout")
        .arg(timeout_seconds.to_string())
        .arg("--json");
    command
}

fn run_logs(repo: &Path, state: &Path, service: &str, tail: usize) -> Output {
    Command::new(env!("CARGO_BIN_EXE_duckflap"))
        .current_dir(repo)
        .env("DUCKFLAP_STATE_DIR", state)
        .arg("logs")
        .arg(service)
        .arg("--tail")
        .arg(tail.to_string())
        .output()
        .expect("run duckflap logs")
}

fn run_detached(repo: &Path, state: &Path) -> Output {
    run_detached_command(repo, state)
        .output()
        .expect("run duckflap detached")
}

fn run_detached_with_path(repo: &Path, state: &Path, path: &OsString) -> Output {
    run_detached_command(repo, state)
        .env("PATH", path)
        .output()
        .expect("run Duckflap detached with fake Supabase CLI")
}

fn run_detached_command(repo: &Path, state: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_duckflap"));
    command
        .current_dir(repo)
        .env("DUCKFLAP_STATE_DIR", state)
        .args(["run", "--detach", "--json"]);
    command
}

fn run_stop(repo: &Path, state: &Path) -> Output {
    stop_command(repo, state)
        .output()
        .expect("run duckflap stop")
}

fn run_stop_with_path(repo: &Path, state: &Path, path: &OsString) -> Output {
    stop_command(repo, state)
        .env("PATH", path)
        .output()
        .expect("run Duckflap stop with fake Supabase CLI")
}

fn stop_command(repo: &Path, state: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_duckflap"));
    command
        .current_dir(repo)
        .env("DUCKFLAP_STATE_DIR", state)
        .args(["stop", "--json"]);
    command
}

fn run_exec(repo: &Path, state: &Path, command: &[&str]) -> Output {
    exec_command(repo, state, command)
        .output()
        .expect("run duckflap exec")
}

fn exec_command(repo: &Path, state: &Path, command: &[&str]) -> Command {
    let mut duckflap = Command::new(env!("CARGO_BIN_EXE_duckflap"));
    duckflap
        .current_dir(repo)
        .env("DUCKFLAP_STATE_DIR", state)
        .args(["exec", "--"])
        .args(command);
    duckflap
}

fn run_release(repo: &Path, state: &Path) -> Output {
    release_command(repo, state)
        .output()
        .expect("run duckflap release")
}

fn run_reallocate(repo: &Path, state: &Path) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_duckflap"));
    command
        .current_dir(repo)
        .env("DUCKFLAP_STATE_DIR", state)
        .args(["reallocate", "--json"])
        .output()
        .expect("run duckflap reallocate")
}

fn release_command(repo: &Path, state: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_duckflap"));
    command
        .current_dir(repo)
        .env("DUCKFLAP_STATE_DIR", state)
        .args(["release", "--json"]);
    command
}

fn initialize_repo(repo: &Path, package_json: &str) {
    fs::create_dir(repo).expect("create repo dir");
    assert!(
        Command::new("git")
            .args(["init", "--quiet"])
            .arg(repo)
            .status()
            .expect("run git init")
            .success()
    );
    fs::write(repo.join("package.json"), package_json).expect("write package manifest");
    fs::write(repo.join(".gitignore"), "node_modules/\n").expect("write gitignore");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["add", "package.json", ".gitignore"])
            .status()
            .expect("stage package manifest")
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args([
                "-c",
                "user.name=Duckflap Tests",
                "-c",
                "user.email=tests@duckflap.invalid",
                "commit",
                "--quiet",
                "-m",
                "initial",
            ])
            .status()
            .expect("commit package manifest")
            .success()
    );
}

fn add_supabase_config(repo: &Path, config: &str) {
    let directory = repo.join("supabase");
    fs::create_dir(&directory).expect("create Supabase directory");
    fs::write(directory.join("config.toml"), config).expect("write Supabase config");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["add", "supabase/config.toml"])
            .status()
            .expect("stage Supabase config")
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args([
                "-c",
                "user.name=Duckflap Tests",
                "-c",
                "user.email=tests@duckflap.invalid",
                "commit",
                "--quiet",
                "-m",
                "add Supabase config",
            ])
            .status()
            .expect("commit Supabase config")
            .success()
    );
}

fn update_supabase_config(repo: &Path, config: &str) {
    fs::write(repo.join("supabase/config.toml"), config).expect("update Supabase config");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["add", "supabase/config.toml"])
            .status()
            .expect("stage updated Supabase config")
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args([
                "-c",
                "user.name=Duckflap Tests",
                "-c",
                "user.email=tests@duckflap.invalid",
                "commit",
                "--quiet",
                "-m",
                "update Supabase config",
            ])
            .status()
            .expect("commit updated Supabase config")
            .success()
    );
}

fn update_package_json(repo: &Path, package_json: &str) {
    fs::write(repo.join("package.json"), package_json).expect("update package manifest");
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["add", "package.json"])
            .status()
            .expect("stage updated package manifest")
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args([
                "-c",
                "user.name=Duckflap Tests",
                "-c",
                "user.email=tests@duckflap.invalid",
                "commit",
                "--quiet",
                "-m",
                "update package manifest",
            ])
            .status()
            .expect("commit updated package manifest")
            .success()
    );
}

fn install_fake_next(repo: &Path) {
    install_fake_next_script(repo, &format!("#!/bin/sh\n{FAKE_TCP_LISTENER}\n"));
}

fn install_fake_next_script(repo: &Path, script: &str) {
    let executable = repo.join("node_modules/.bin/next");
    fs::create_dir_all(executable.parent().expect("fake Next.js parent"))
        .expect("create fake Next.js bin directory");
    fs::write(&executable, script).expect("write fake Next.js executable");
    let mut permissions = fs::metadata(&executable)
        .expect("read fake Next.js metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&executable, permissions).expect("make fake Next.js executable");
}

fn install_fake_supabase(bin: &Path) -> OsString {
    fs::create_dir_all(bin).expect("create fake Supabase bin directory");
    let executable = bin.join("supabase");
    fs::write(
        &executable,
        r#"#!/usr/bin/env python3
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import re

def option(name):
    try:
        return sys.argv[sys.argv.index(name) + 1]
    except (ValueError, IndexError):
        return None

def pid_path(workdir):
    return os.path.join(workdir, ".fake-supabase.pid")

def configured_ports(workdir):
    with open(os.path.join(workdir, "supabase", "config.toml"), encoding="utf-8") as config_file:
        config = config_file.readlines()
    persistent = {
        ("api", "port"),
        ("db", "port"),
        ("db.pooler", "port"),
        ("studio", "port"),
        ("inbucket", "port"),
        ("inbucket", "smtp_port"),
        ("inbucket", "pop3_port"),
        ("local_smtp", "port"),
        ("local_smtp", "smtp_port"),
        ("local_smtp", "pop3_port"),
        ("analytics", "port"),
    }
    section = ""
    ports = []
    for line in config:
        section_match = re.match(r"^\s*\[([^]]+)\]\s*$", line)
        if section_match:
            section = section_match.group(1)
            continue
        value_match = re.match(r"^\s*([a-z_]+)\s*=\s*(\d+)\s*$", line)
        if value_match and (section, value_match.group(1)) in persistent:
            ports.append(int(value_match.group(2)))
    return sorted(set(ports))

def configured_project_id(workdir):
    with open(os.path.join(workdir, "supabase", "config.toml"), encoding="utf-8") as config_file:
        config = config_file.read()
    match = re.search(r'(?m)^\s*project_id\s*=\s*"([^"]+)"\s*$', config)
    return match.group(1) if match else None

def serve(workdir):
    listeners = []
    for port in configured_ports(workdir):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", port))
        listener.listen()
        listeners.append(listener)
    def drain(listener):
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            connection.close()
    for listener in listeners:
        threading.Thread(target=drain, args=(listener,), daemon=True).start()
    marker = pid_path(workdir)
    with open(marker, "w", encoding="utf-8") as pid_file:
        pid_file.write(str(os.getpid()))
    def stop(_signum, _frame):
        for listener in listeners:
            listener.close()
        try:
            os.unlink(marker)
        except FileNotFoundError:
            pass
        raise SystemExit(0)
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    exit_after = os.environ.get("DUCKFLAP_FAKE_SUPABASE_EXIT_AFTER")
    if exit_after:
        def exit_later():
            time.sleep(float(exit_after))
            os.kill(os.getpid(), signal.SIGTERM)
        threading.Thread(target=exit_later, daemon=True).start()
    while True:
        signal.pause()

action = sys.argv[1] if len(sys.argv) > 1 else ""
workdir = option("--workdir")
if action == "serve":
    serve(sys.argv[2])
elif action == "start" and workdir:
    entered = os.environ.get("DUCKFLAP_FAKE_SUPABASE_START_ENTERED")
    continue_start = os.environ.get("DUCKFLAP_FAKE_SUPABASE_START_CONTINUE")
    if entered:
        with open(entered, "w", encoding="utf-8"):
            pass
        while continue_start and not os.path.exists(continue_start):
            time.sleep(0.01)
    marker = pid_path(workdir)
    error_path = os.path.join(workdir, ".fake-supabase-error.log")
    with open(error_path, "w", encoding="utf-8") as error_log:
        subprocess.Popen(
            [sys.executable, __file__, "serve", workdir],
            stdin=subprocess.DEVNULL,
            stdout=error_log,
            stderr=error_log,
            start_new_session=True,
        )
    deadline = time.monotonic() + 3
    while not os.path.exists(marker) and time.monotonic() < deadline:
        time.sleep(0.01)
    if not os.path.exists(marker):
        with open(error_path, encoding="utf-8") as error_log:
            sys.stderr.write(error_log.read())
        raise SystemExit(1)
    if os.environ.get("DUCKFLAP_FAKE_SUPABASE_START_FAIL") == "1":
        sys.stderr.write("fake Supabase startup failed\n")
        raise SystemExit(1)
    start_exit = os.environ.get("DUCKFLAP_FAKE_SUPABASE_START_EXIT")
    if start_exit:
        raise SystemExit(int(start_exit))
    raise SystemExit(0)
elif action == "stop" and workdir:
    if option("--project-id") != configured_project_id(workdir):
        raise SystemExit(3)
    stop_count = os.environ.get("DUCKFLAP_FAKE_SUPABASE_STOP_COUNT")
    if stop_count:
        with open(stop_count, "a", encoding="utf-8") as count_file:
            count_file.write("stop\n")
    stop_entered = os.environ.get("DUCKFLAP_FAKE_SUPABASE_STOP_ENTERED")
    continue_stop = os.environ.get("DUCKFLAP_FAKE_SUPABASE_STOP_CONTINUE")
    if stop_entered:
        with open(stop_entered, "w", encoding="utf-8"):
            pass
        while continue_stop and not os.path.exists(continue_stop):
            time.sleep(0.01)
    if os.environ.get("DUCKFLAP_FAKE_SUPABASE_STOP_FAIL") == "1":
        raise SystemExit(1)
    marker = pid_path(workdir)
    try:
        with open(marker, encoding="utf-8") as pid_file:
            pid = int(pid_file.read())
    except FileNotFoundError:
        raise SystemExit(0)
    os.kill(pid, signal.SIGTERM)
    deadline = time.monotonic() + 3
    while os.path.exists(marker) and time.monotonic() < deadline:
        time.sleep(0.01)
    raise SystemExit(0 if not os.path.exists(marker) else 1)
else:
    raise SystemExit(2)
"#,
    )
    .expect("write fake Supabase CLI");
    let mut permissions = fs::metadata(&executable)
        .expect("read fake Supabase metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&executable, permissions).expect("make fake Supabase CLI executable");

    let inherited = env::var_os("PATH").unwrap_or_default();
    env::join_paths(std::iter::once(bin.to_path_buf()).chain(env::split_paths(&inherited)))
        .expect("construct fake Supabase PATH")
}

fn install_git_only_path(bin: &Path) -> OsString {
    fs::create_dir_all(bin).expect("create isolated binary directory");
    let inherited = env::var_os("PATH").unwrap_or_default();
    let git = env::split_paths(&inherited)
        .map(|directory| directory.join("git"))
        .find(|candidate| {
            fs::metadata(candidate).is_ok_and(|metadata| {
                metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
            })
        })
        .expect("find git executable");
    std::os::unix::fs::symlink(git, bin.join("git")).expect("link isolated git executable");
    bin.as_os_str().to_owned()
}

fn tcp_port_is_open(port: u16) -> bool {
    TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}")
            .parse()
            .expect("runtime address"),
        Duration::from_millis(200),
    )
    .is_ok()
}

fn service_ports(response: &Value) -> Vec<u16> {
    response["data"]["services"]
        .as_array()
        .expect("service array")
        .iter()
        .map(|service| {
            u16::try_from(service["port"].as_u64().expect("service port")).expect("TCP port")
        })
        .collect()
}

fn service_port_map(services: &Value) -> BTreeMap<String, u16> {
    services
        .as_array()
        .expect("service array")
        .iter()
        .map(|service| {
            let service_key = service["service_key"]
                .as_str()
                .expect("service key")
                .to_owned();
            let port = u16::try_from(service["port"].as_u64().expect("service port"))
                .expect("u16 service port");
            (service_key, port)
        })
        .collect()
}

fn persistent_supabase_ports(response: &Value) -> Vec<u16> {
    response["data"]["services"]
        .as_array()
        .expect("service array")
        .iter()
        .filter(|service| {
            service["service_key"]
                .as_str()
                .is_some_and(|key| key.starts_with("supabase."))
                && !matches!(
                    service["service_key"].as_str().expect("service key"),
                    "supabase.db.shadow" | "supabase.edge_inspector" | "supabase.analytics.vector"
                )
        })
        .map(|service| {
            u16::try_from(service["port"].as_u64().expect("service port")).expect("TCP port")
        })
        .collect()
}

fn assert_no_active_runtime(state: &Path) {
    let connection = Connection::open(state.join("registry.sqlite3")).expect("open registry");
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM runtime_sessions WHERE status IN ('starting', 'ready', 'stopping')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("count active runtime sessions"),
        0
    );
}

fn wait_for_tcp_port(port: u16, expected_open: bool) {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while tcp_port_is_open(port) != expected_open {
        assert!(
            std::time::Instant::now() < deadline,
            "TCP port {port} did not become {}",
            if expected_open { "open" } else { "closed" }
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn assert_tcp_ports_remain_closed(ports: &[u16], duration: Duration) {
    let deadline = std::time::Instant::now() + duration;
    while std::time::Instant::now() < deadline {
        for port in ports {
            assert!(
                !tcp_port_is_open(*port),
                "TCP port {port} unexpectedly opened"
            );
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_path(path: &Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while !path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "path did not appear: {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_runtime_status(state: &Path, expected_status: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let found = Connection::open(state.join("registry.sqlite3"))
            .ok()
            .and_then(|connection| {
                connection
                    .query_row(
                        "SELECT EXISTS(
                            SELECT 1 FROM runtime_sessions WHERE status = ?1
                        )",
                        [expected_status],
                        |row| row.get::<_, bool>(0),
                    )
                    .ok()
            })
            .unwrap_or(false);
        if found {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "runtime did not reach status {expected_status}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_path_absent(path: &Path) {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while path.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "path did not disappear: {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(20));
    }
}

struct RuntimeCleanup {
    repo: PathBuf,
    state: PathBuf,
}

struct SupabaseRuntimeCleanup {
    repo: PathBuf,
    state: PathBuf,
    path: OsString,
}

impl SupabaseRuntimeCleanup {
    fn new(repo: &Path, state: &Path, path: &OsString) -> Self {
        Self {
            repo: repo.to_path_buf(),
            state: state.to_path_buf(),
            path: path.clone(),
        }
    }
}

impl Drop for SupabaseRuntimeCleanup {
    fn drop(&mut self) {
        let _ = stop_command(&self.repo, &self.state)
            .env("PATH", &self.path)
            .output();
    }
}

impl RuntimeCleanup {
    fn new(repo: &Path, state: &Path) -> Self {
        Self {
            repo: repo.to_path_buf(),
            state: state.to_path_buf(),
        }
    }
}

impl Drop for RuntimeCleanup {
    fn drop(&mut self) {
        for _ in 0..10 {
            let stopped = Command::new(env!("CARGO_BIN_EXE_duckflap"))
                .current_dir(&self.repo)
                .env("DUCKFLAP_STATE_DIR", &self.state)
                .args(["stop", "--json"])
                .output();
            if stopped.is_ok_and(|output| output.status.success()) {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
    }
}

struct ProcessGroupCleanup(u32);

impl Drop for ProcessGroupCleanup {
    fn drop(&mut self) {
        let _ = terminate_process_group(self.0);
    }
}

struct PidFileCleanup(PathBuf);

impl Drop for PidFileCleanup {
    fn drop(&mut self) {
        if let Ok(pid) = fs::read_to_string(&self.0) {
            let _ = Command::new("kill").arg(pid.trim()).status();
        }
    }
}

fn add_linked_worktree(repo: &Path, linked: &Path) {
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["worktree", "add", "--quiet", "--detach"])
            .arg(linked)
            .arg("HEAD")
            .status()
            .expect("create linked worktree")
            .success()
    );
}

fn lock_cli_test() -> MutexGuard<'static, ()> {
    CLI_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn git_output(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("run git");
    assert!(output.status.success());
    String::from_utf8(output.stdout).expect("UTF-8 git output")
}
