CREATE TABLE projects (
    id TEXT PRIMARY KEY NOT NULL,
    git_common_dir TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE project_instances (
    id TEXT PRIMARY KEY NOT NULL,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE RESTRICT,
    worktree_git_dir TEXT NOT NULL UNIQUE,
    worktree_root TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    orphaned_at TEXT
);

CREATE TABLE allocations (
    project_instance_id TEXT NOT NULL REFERENCES project_instances(id) ON DELETE RESTRICT,
    service_key TEXT NOT NULL CHECK (length(service_key) > 0),
    protocol TEXT NOT NULL CHECK (protocol = 'tcp'),
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (project_instance_id, service_key, protocol),
    UNIQUE (protocol, port)
);
