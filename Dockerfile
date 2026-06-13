# ---- Build stage ----
FROM rust:1-slim AS builder

WORKDIR /app

# Cache dependencies: copy manifests first, build a stub, then the real source.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -rf src

# Build the actual binary.
COPY src ./src
RUN touch src/main.rs && cargo build --release

# ---- Runtime stage ----
FROM debian:bookworm-slim

# Run as a non-root user.
RUN useradd --system --uid 10001 --no-create-home minidns

WORKDIR /app
COPY --from=builder /app/target/release/mini-dns /usr/local/bin/mini-dns
COPY zones ./zones

USER minidns

# DNS (UDP+TCP). Adjust/publish more as needed: 853 (DoT), 443/8443 (DoH), 9090 (metrics).
EXPOSE 53/udp 53/tcp

ENV MINI_DNS_ADDR=0.0.0.0:53 \
    MINI_DNS_ZONE=/app/zones/example.zone

ENTRYPOINT ["mini-dns"]
