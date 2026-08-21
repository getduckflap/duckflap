# Duckflap

Run your local development stack with one command.

Duckflap detects supported services, assigns stable ports, starts them in the right order, waits until the stack is ready, captures logs, and stops only what it owns—without changing tracked project files.

Currently supports Next.js and local Supabase. No Duckflap-specific configuration is required for supported projects.

## Install

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/getduckflap/duckflap/releases/latest/download/duckflap-installer.sh | sh
```

Verify the installation:

```sh
duckflap --version
```

## Quick start

From a supported project:

```sh
duckflap run --detach --json
duckflap status
```

Duckflap returns after the detected stack is ready. Running the command again safely reuses the healthy stack.

Open the service URL shown by `status`.

Stop the stack:

```sh
duckflap stop --json
```

## Logs and diagnostics

View the latest Next.js log:

```sh
duckflap logs web --tail 50
```

View the Supabase CLI lifecycle log:

```sh
duckflap logs supabase.api --tail 50
```

Diagnose the current worktree:

```sh
duckflap doctor --json
```

Duckflap keeps logs for the latest runtime and up to three earlier stopped or failed sessions per worktree.

## Git worktrees

Run Duckflap from another linked worktree and it automatically receives its own stable ports and, when applicable, its own local Supabase stack.

Allocations remain stable between runs. After stopping a worktree, remove its allocations with:

```sh
duckflap release --json
```

## Use with coding agents

Once Duckflap is installed, give your coding agent this instruction:

```text
Use Duckflap to manage this project's local services.

- Start the stack with `duckflap run --detach --json`.
- Discover service URLs and readiness with `duckflap status --json`.
- If startup fails, diagnose it with `duckflap doctor --json` and `duckflap logs <service>`.
- Stop the stack with `duckflap stop --json`.
- Do not choose ports, edit tracked port configuration, or terminate unknown processes manually.
```

## Supported projects

Duckflap supports macOS, Linux, and WSL projects containing one or both of:

- A root Next.js application with a direct `next dev` development script.
- A local Supabase project with `supabase/config.toml`.

Next.js dependencies must already be installed.

Local Supabase requires:

- A Docker-compatible container runtime.
- A `supabase` executable available on `PATH`.

Duckflap manages only the local Docker-backed Supabase stack. It does not connect to or modify hosted Supabase projects.

## Commands

Duckflap also provides generated environments, foreground command execution, readiness waiting, port inspection, and allocation management.

```sh
duckflap --help
duckflap <command> --help
```

## Feedback

Found a bug or rough edge? [Open an issue](https://github.com/getduckflap/duckflap/issues).

See [CHANGELOG.md](CHANGELOG.md) for release history.

Report security vulnerabilities privately by following [SECURITY.md](SECURITY.md).

## License

Duckflap is licensed under the [MIT License](LICENSE).
