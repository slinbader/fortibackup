# fortibackup

`fortibackup` is a small Rust CLI / daemon that periodically connects to one or
more FortiGate firewalls, downloads their running configuration, versions it on
disk with metadata, and alerts you when something goes wrong.

It is designed for unattended operation on a Debian/Linux box as a `systemd`
service.

---

## Why

FortiGate devices are usually the single most important piece of network
infrastructure in an organization. The default vendor tooling for configuration
backups is GUI-driven, manual, or tied to FortiManager licenses. `fortibackup`
fills the gap with a small, auditable, dependency-light service:

- pulls the **full** configuration via the documented REST API (preferred) or
  SSH (`show full-configuration`)
- hashes the result and stores **only changes**, with a JSON sidecar
- enforces retention (`N` days, but always keep at least `M` copies)
- notifies via email and/or webhook on failure
- runs on a per-device cron schedule

## Requirements

- Linux (tested on Debian 12+)
- Rust **1.75** or newer
- Outbound network access from the host to each FortiGate (HTTPS or SSH)

## Install

Three options, pick whichever fits:

### 1) Debian package (recommended for Debian/Ubuntu)

```sh
cargo install cargo-deb       # one-off
cargo deb                     # produces target/debian/fortibackup_*_amd64.deb
sudo apt install ./target/debian/fortibackup_0.1.0-1_amd64.deb
```

The postinst creates the `fortibackup` system user, seeds
`/etc/fortibackup/config.toml` from the example, and installs the systemd
unit. After editing the config and `environment` file:

```sh
sudo systemctl enable --now fortibackup.service
```

### 2) Docker

```sh
docker build -t fortibackup:0.1.0 .                              # ~32 MB final image (distroless)
docker run --rm \
  -v $(pwd)/config.toml:/etc/fortibackup/config.toml:ro \
  -v fortibackup-data:/var/lib/fortibackup \
  -e FGT_TOKEN_PRIMARY="$FGT_TOKEN_PRIMARY" \
  fortibackup:0.1.0 once
```

The image runs as the distroless `nonroot` user. Optional `/metrics`
exporter listens on port 9090 — expose with `-p 9090:9090` when enabling
the `[metrics]` block.

### 3) From source

```sh
git clone https://example.com/lherrera/fortibackup.git
cd fortibackup
cargo install --path .
```

The binary is installed at `~/.cargo/bin/fortibackup`. For a system-wide
install, copy it to `/usr/local/bin/fortibackup`.

## Configuration

```sh
sudo mkdir -p /etc/fortibackup /var/lib/fortibackup
sudo cp config.example.toml /etc/fortibackup/config.toml
sudoedit /etc/fortibackup/config.toml
```

See `config.example.toml` for the full schema. Secrets (API tokens, SMTP
passwords, SSH passwords) are **never** stored in the TOML file — each `*_env`
field names an environment variable that is read at runtime. For a systemd
service, put them in `/etc/fortibackup/environment`:

```ini
FGT_TOKEN_PRIMARY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
FGT_SSH_PASSWORD_SECONDARY=changeme
SMTP_PASSWORD=app-specific-password
```

Make sure this file is `chmod 0600` and owned by the `fortibackup` user.

### Getting an API token on FortiGate

REST API access is granted to a dedicated administrator profile:

1. **System → Admin Profiles → Create New**
   - Name: `api_backup_ro`
   - Set `System` → `Configuration` → **Read**
   - Leave everything else at `None`
2. **System → Administrators → Create New → REST API Admin**
   - Username: `fortibackup`
   - Admin profile: `api_backup_ro`
   - **Trusted Hosts**: lock down to the IP of the box running this tool
3. Copy the generated token (shown once) into the environment variable
   referenced by `api_token_env`.

You can quickly verify the token from the command line:

```sh
curl -sk -H "Authorization: Bearer $FGT_TOKEN_PRIMARY" \
  "https://10.0.0.1/api/v2/monitor/system/status" | jq '.results.hostname'
```

### Creating a read-only SSH user on FortiGate

If you prefer SSH (or have a FortiGate that doesn't expose the REST API):

```fortios
config system accprofile
  edit "backup_ro"
    set sysgrp read
  next
end

config system admin
  edit "backup_user"
    set accprofile "backup_ro"
    set vdom "root"
    # Either set a password:
    # set password "..."
    # or upload a public key:
    set ssh-public-key1 "ssh-ed25519 AAAA..."
  next
end
```

Then point `ssh_username` and `ssh_key_path` (or `ssh_password_env`) at this
user in `config.toml`.

## Install as a systemd service

```sh
sudo useradd --system --home /var/lib/fortibackup --shell /usr/sbin/nologin fortibackup
sudo install -m 0755 target/release/fortibackup /usr/local/bin/fortibackup
sudo install -m 0644 systemd/fortibackup.service /etc/systemd/system/
sudo install -m 0600 -o fortibackup -g fortibackup /dev/null /etc/fortibackup/environment
sudo chown -R fortibackup:fortibackup /var/lib/fortibackup /etc/fortibackup
sudo systemctl daemon-reload
sudo systemctl enable --now fortibackup.service
journalctl -u fortibackup -f
```

## Usage

```sh
# Validate config + reachability (no backups taken)
fortibackup verify --config /etc/fortibackup/config.toml

# One-shot backup of every device, then exit
fortibackup once --config /etc/fortibackup/config.toml

# One-shot backup of a single device
fortibackup once --device fortigate-primary

# Run the daemon (this is what the systemd unit does)
fortibackup run

# List stored backups
fortibackup list
fortibackup list --device fortigate-primary
```

## Resulting directory layout

```
/var/lib/fortibackup/
├── fortigate-primary/
│   ├── 2026-05-15_020000.conf
│   ├── 2026-05-15_020000.json     # sidecar: hash, firmware, serial, size
│   ├── 2026-05-16_020000.conf
│   └── 2026-05-16_020000.json
└── fortigate-secondary/
    └── ...
```

When a configuration is byte-identical to the previous run, **no new file is
written**. The event is logged as `no_change` and retention is not triggered.

## Logs

Logs are emitted via `tracing`. By default the format is structured JSON, which
plays nicely with `journalctl -o json` and any log shipper. To switch to a
human-friendly format during development:

```sh
FORTIBACKUP_LOG_FORMAT=pretty RUST_LOG=debug fortibackup once
```

## Development

```sh
cargo fmt
cargo clippy -- -D warnings
cargo test
```

## License

MIT
