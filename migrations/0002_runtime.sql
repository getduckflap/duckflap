CREATE TABLE runtime_sessions (
    id TEXT PRIMARY KEY NOT NULL,
    project_instance_id TEXT NOT NULL REFERENCES project_instances(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('starting', 'ready', 'stopping', 'stopped', 'failed')),
    launcher_pid INTEGER NOT NULL CHECK (launcher_pid > 0),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ready_at TEXT,
    ended_at TEXT
);

CREATE UNIQUE INDEX one_active_runtime_per_instance
ON runtime_sessions(project_instance_id)
WHERE status IN ('starting', 'ready', 'stopping');

CREATE TABLE runtime_processes (
    session_id TEXT NOT NULL REFERENCES runtime_sessions(id) ON DELETE RESTRICT,
    service_key TEXT NOT NULL CHECK (length(service_key) > 0),
    pid INTEGER NOT NULL CHECK (pid > 0),
    process_group_id INTEGER NOT NULL CHECK (process_group_id > 0),
    process_start TEXT NOT NULL CHECK (length(process_start) > 0),
    executable TEXT NOT NULL CHECK (length(executable) > 0),
    log_path TEXT NOT NULL CHECK (length(log_path) > 0),
    PRIMARY KEY (session_id, service_key)
);
