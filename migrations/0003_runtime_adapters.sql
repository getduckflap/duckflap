CREATE TABLE runtime_adapters (
    session_id TEXT PRIMARY KEY NOT NULL REFERENCES runtime_sessions(id) ON DELETE RESTRICT,
    adapter_key TEXT NOT NULL CHECK (length(adapter_key) > 0),
    working_directory TEXT NOT NULL CHECK (length(working_directory) > 0),
    runtime_project_id TEXT NOT NULL CHECK (length(runtime_project_id) > 0),
    log_path TEXT NOT NULL CHECK (length(log_path) > 0)
);

CREATE TABLE runtime_adapter_services (
    session_id TEXT NOT NULL REFERENCES runtime_adapters(session_id) ON DELETE RESTRICT,
    service_key TEXT NOT NULL CHECK (length(service_key) > 0),
    protocol TEXT NOT NULL CHECK (protocol = 'tcp'),
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    PRIMARY KEY (session_id, service_key, protocol),
    UNIQUE (session_id, protocol, port)
);
