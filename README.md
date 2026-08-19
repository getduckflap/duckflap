# Duckflap

Run local projects side by side without port conflicts.

Duckflap detects Next.js and local Supabase services, gives each Git worktree stable ports, and manages the stack without changing tracked project files.

## Install

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/getduckflap/duckflap/releases/latest/download/duckflap-installer.sh |
  sh
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

Open the service URL shown by `status`.

For a Next.js project, view the latest web log:

```sh
duckflap logs web --tail 50
```

For a Supabase project, view the shared Supabase CLI log:

```sh
duckflap logs supabase.api --tail 50
```

Stop the stack:

```sh
duckflap stop --json
```

Duckflap keeps the worktree's ports stable between runs. Run the same project from another Git worktree and it receives different ports automatically.

To remove a worktree's allocations after stopping it:

```sh
duckflap release --json
```

## Ask your coding agent

Once Duckflap is installed, paste this into your coding agent:

> Use Duckflap to manage this project's local services. Start them with `duckflap run --detach --json` and discover service URLs and readiness with `duckflap status --json`. If startup fails, use `duckflap doctor --json` and `duckflap logs <service>` to diagnose it. Stop the stack with `duckflap stop --json`. Do not choose ports, edit tracked port configuration, or terminate unknown processes manually.

## Supported projects

Duckflap supports macOS, Linux, and WSL projects containing one or both of:

- A root Next.js application with a direct `next dev` development script.
- A local Supabase project with `supabase/config.toml`.

Next.js dependencies must already be installed. Local Supabase requires a Docker-compatible container runtime and a `supabase` executable available on `PATH`.

Duckflap manages only the local Docker-backed Supabase stack. It does not connect to or modify hosted Supabase projects.

Native Windows is not currently supported.

## More

Duckflap also provides commands for generated environments, foreground commands, readiness waiting, diagnostics, port inspection, and allocation management.

```sh
duckflap --help
duckflap <command> --help
```

## Feedback

Found a bug or rough edge? [Open an issue](https://github.com/getduckflap/duckflap/issues).

## License

Duckflap is licensed under the [MIT License](LICENSE).
