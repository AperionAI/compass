# syntax=docker/dockerfile:1.6
#
# Multi-arch build for aperion-compass.
#
# Published to ghcr.io/aperionai/compass:<version> by
# .github/workflows/release.yml. Intentionally minimal — the static
# binary on top of distroless, no shell or package manager. Compass is
# offline by design; the container makes no network calls.

# ─── Build stage ───────────────────────────────────────────────────────
FROM rust:1.83-slim-bookworm AS build

WORKDIR /src

# Cache the dependency layer. Both Cargo.toml AND Cargo.lock are copied
# so the stub build resolves the same versions the real build uses. The
# crate is a lib+bin hybrid, so the stub must satisfy both targets.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && \
    echo "fn main(){}"       > src/main.rs && \
    echo "// stub for cache" > src/lib.rs && \
    cargo build --release --locked && \
    rm -rf src

# Real source + the catalogs/templates that `include_str!` embeds.
COPY src       ./src
COPY catalogs  ./catalogs
COPY templates ./templates

RUN find src -name '*.rs' -exec touch {} + && \
    cargo build --release --locked && \
    strip target/release/compass

# ─── Runtime stage ─────────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="aperion-compass"
LABEL org.opencontainers.image.description="Local, offline AI governance self-assessment (EU AI Act & IMDA agentic)"
LABEL org.opencontainers.image.source="https://github.com/AperionAI/compass"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.vendor="Aperion"

COPY --from=build /src/target/release/compass /usr/local/bin/compass

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/compass"]
CMD ["--help"]
