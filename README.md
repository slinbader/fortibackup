# fortibackup

`fortibackup` is a small Rust CLI / daemon that periodically connects to one or
more **FortiGate** and **Hillstone StoneOS** firewalls, downloads their running
configuration, versions it on disk with metadata, and alerts you when something
goes wrong.

It is designed for unattended operation on a Debian/Linux box as a `systemd`
service.

---

## Why

FortiGate devices are usually the single most important piece of network
infrastructure in an organization. The default vendor tooling for configuration
backups is GUI-driven, manual, or tied to FortiManager licenses. `fortibackup`
fills the gap with a small, auditable, dependency-light service:

- pulls the **full** configuration from **FortiGate** (documented REST API,
  preferred, or SSH `show full-configuration`) and from **Hillstone StoneOS**
  (interactive SSH `show configuration` — StoneOS has no backup REST API)
- hashes the result and stores **only changes**, with a JSON sidecar
- enforces retention (`N` days, but always keep at least `M` copies)
- notifies via email and/or webhook on failure
- optional overdue-backup watchdog catches the *silent* case (no fetch was
  even attempted) by tracking the last successful run per device
- runs on a per-device cron schedule

## Requirements

- Linux (tested on Debian 12+)
- Rust **1.91** or newer (the `aws-sdk-s3` dependency tree tracks recent stable)
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

## Adding a Hillstone StoneOS device

`fortibackup` also backs up **Hillstone StoneOS** firewalls. StoneOS exposes no
REST configuration-backup endpoint, so these are pulled over **SSH** by driving
the interactive CLI: the tool logs in, disables the pager (`terminal length 0`),
runs `show configuration`, and reads the config back — stripping the login
banner, command echo, and trailing prompt automatically. Because StoneOS prints
stable ciphertext (unlike the FortiGate API, which re-encrypts secrets on every
fetch), change detection works with no vendor-specific tuning.

Set `vendor = "hillstone"` and `method = "ssh"` on the device — there is no API
transport for StoneOS, so `vendor = "hillstone"` with `method = "api"` is
rejected at config load:

```toml
[[devices]]
name = "hillstone-edge"
host = "10.0.0.5"
port = 22
method = "ssh"
vendor = "hillstone"           # default is "fortigate" when omitted
ssh_username = "backup"
ssh_password_env = "HS_EDGE_PASS"   # or use ssh_key_path = "/etc/fortibackup/keys/id_ed25519"
schedule = "0 40 7 * * *"
timeout_secs = 120
```

### Creating the SSH backup user on StoneOS

`show configuration` requires an **admin-role** account. In the WebUI under
*System → Administrators* (or via the CLI), create a dedicated user, give it a
strong password, and restrict its access method to **SSH only**. Reference it
from `ssh_username`, and put its password in the environment variable named by
`ssh_password_env` (or use `ssh_key_path` for key-based auth).

### Deploying to a running systemd service

Adding a device to an already-installed service is **config-only** — no rebuild
or redeploy of the binary:

```sh
# 1) add the password to the service environment (kept out of shell history)
sudo sh -c 'stty -echo; printf "StoneOS backup password: "; read P; stty echo; \
  printf "\nHS_EDGE_PASS=%s\n" "$P" >> /etc/fortibackup/environment'

# 2) append the [[devices]] block above to the config
sudoedit /etc/fortibackup/config.toml

# 3) verify it parses and the device authenticates, WITHOUT touching the service
#    (runs as the service user with its environment; a bad config is caught here
#    instead of failing the live daemon on restart)
sudo systemd-run --uid=fortibackup -p EnvironmentFile=/etc/fortibackup/environment \
  --wait --collect --pty /usr/bin/fortibackup \
  --config /etc/fortibackup/config.toml verify

# 4) once it reports the device reachable, reload the daemon
sudo systemctl restart fortibackup

# 5) (optional) seed the first backup now instead of waiting for the schedule
sudo systemd-run --uid=fortibackup -p EnvironmentFile=/etc/fortibackup/environment \
  --wait --collect --pty /usr/bin/fortibackup \
  --config /etc/fortibackup/config.toml once --device hillstone-edge
```

> **Tip — stagger schedules.** The scheduler runs each device on its own cron
> with no inter-device dependency. To keep backups sequential (never running in
> parallel), offset each device by a few minutes — e.g. a FortiGate at
> `0 30 7 * * *`, then Hillstones at `0 35 7 * * *`, `0 40 7 * * *`, and so on.

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
