# Z-1.R.4 — the relay as one container. Build from the repository root:
#   docker build -f apps/relay/Dockerfile -t zbacs-relay .
#   docker run --rm -p 8787:8787 zbacs-relay
# or, simpler, `docker compose up` (see docker-compose.yml at the root).
#
# The relay holds nothing that needs protecting (relay_protocol §7/§8): no keys, no plaintext,
# only signed envelopes it cannot read, kept in memory for at most 24 h. So the image has no
# volume, no secret, no config file — it is the same binary a developer runs with `cargo run`.

# ---- build: the workspace, but only the relay's dependency graph is compiled
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY apps/relay ./apps/relay
# Workspace members the relay does not use still have to exist for Cargo to resolve the
# workspace; their sources are copied above, they are not built (-p zbacs-relay).
RUN cargo build --release --locked -p zbacs-relay

# ---- run: a small Debian with curl for the health check, as an unprivileged user
FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin zbacs
COPY --from=build /src/target/release/zbacs-relay /usr/local/bin/zbacs-relay
USER zbacs
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8787/v1/health || exit 1
ENTRYPOINT ["zbacs-relay"]
CMD ["--bind", "0.0.0.0:8787"]
