# syntax=docker/dockerfile:1.7
# -----------------------------------------------------------------------------
# Build stage: rust toolchain, BuildKit cache mounts for cargo registry/target
# -----------------------------------------------------------------------------
FROM rust:1.95-slim-bookworm AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
# PWA icons are include_bytes!'d by src/webui.rs, so they must be in the context
COPY assets ./assets

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked --bin fortibackup \
    && cp target/release/fortibackup /usr/local/bin/fortibackup

# -----------------------------------------------------------------------------
# Runtime stage: distroless cc gives us libc + ca-certificates (needed for
# verify_tls = true and outbound TLS to SMTP / webhook endpoints), without
# any shell or package manager. Final image is ~25 MB.
# -----------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.title="fortibackup"
LABEL org.opencontainers.image.description="Automated configuration backup for FortiGate devices"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/lherrera/fortibackup"

COPY --from=builder /usr/local/bin/fortibackup /usr/local/bin/fortibackup

# Distroless nonroot user is uid/gid 65532. State and config live on volumes.
USER nonroot:nonroot
VOLUME ["/var/lib/fortibackup", "/etc/fortibackup"]

# Optional Prometheus exporter (enabled via [metrics] in config).
EXPOSE 9090

ENTRYPOINT ["/usr/local/bin/fortibackup"]
CMD ["run", "--config", "/etc/fortibackup/config.toml"]
