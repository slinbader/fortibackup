# Contributing to fortibackup

Thanks for taking the time to contribute. This document covers the local
workflow, code conventions, and the easiest ways to extend the project.

## Development setup

```sh
git clone https://github.com/lherrera/fortibackup.git
cd fortibackup

# Toolchain (rustup is the supported way)
rustup show         # ensure stable >= 1.75

# Run the quality gate locally — CI runs exactly these:
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
cargo test  --all-targets --locked
```

There is also a `Makefile` with `release`, `man`, `completions`, `deb`, and
`docker` targets for packaging.

### Running against a local mock FortiGate

The repo's smoke tests target a tiny Python HTTPS server that imitates the
two endpoints the API transport hits. See `/tmp/fortibackup-smoke/` in the
session notes — or write your own. The relevant endpoints are:

- `GET /api/v2/monitor/system/config/backup?scope=global` — must return the
  config bytes
- `GET /api/v2/monitor/system/status` — must return JSON with `results.hostname`,
  `results.serial`, `results.version`

With a TLS server on `https://127.0.0.1:8443` and `verify_tls = false` in
the device config, `cargo run -- once` will exercise the full pipeline.

## Code conventions

- **No `unwrap()` or `expect()` outside of tests.** Use `?` and convert errors
  through `BackupError` / `thiserror`.
- **Library-side errors** use `thiserror`; **binary** uses `anyhow`.
- **Tracing fields** — when adding a log call, prefer structured fields
  (`info!(device = %name, "msg")`) over interpolated strings, so JSON output
  remains queryable.
- **Comments** describe *why*, not *what*. Skip them when the code is obvious.
- **clippy::pedantic is on.** When you genuinely need to silence a lint, add a
  scoped `#[allow(...)]` with a one-line justification.

## Adding a new transport

The `BackupTransport` trait in `src/transport/mod.rs` is the only surface:

```rust
#[async_trait]
pub trait BackupTransport: Send + Sync {
    async fn fetch_config(&self, device: &Device) -> Result<BackupArtifact, TransportError>;
}
```

1. Create `src/transport/<name>.rs` with the impl.
2. Add a variant to `config::TransportMethod` and route it in
   `transport::new()`.
3. Update `Device` config validation in `config::validate_device` if your
   transport needs new fields (e.g. `tftp_root`, `api_key_id`).
4. Add a unit test in your module (use `wiremock` for HTTP, real fixtures for
   parsers).

## Adding a new storage backend

`storage.rs` is currently filesystem-only. The minimum viable surface to
abstract is `save_backup`, `latest_hash`, `list_entries_for_device`, and
`apply_retention`. When introducing a new backend (S3, GCS, etc.):

1. Extract the four functions above into a `BackupStorage` trait.
2. Keep the filesystem impl as the default.
3. Add a `[storage.<backend>]` block to the config.
4. Wire the choice in `backup::execute`.

## Commit conventions

Loosely follow Conventional Commits — useful prefixes:

- `feat(<scope>):` user-visible new behavior
- `fix(<scope>):` bug fix
- `refactor(<scope>):` internal change with no behavior delta
- `ci:` workflow / packaging
- `docs:` README, comments
- `chore:` deps, lockfile

Commit messages should explain *why*. If the work fixes an incident, link the
postmortem.

## Releasing

See `.github/workflows/release.yml`. The flow is:

1. Bump version in `Cargo.toml` and `debian/changelog`.
2. `git tag v0.X.Y && git push --tags`.
3. The workflow builds binary + .deb + docker image and attaches them to a
   GitHub Release.

## Reporting issues

For security issues (token leakage, TLS bypass, etc.), email the maintainer
directly rather than opening a public issue.
