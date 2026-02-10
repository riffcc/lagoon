# Stage 1: Build Rust binaries
FROM rust:1-bookworm AS rust-build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
# Remove web frontend source — we build that separately
RUN rm -rf crates/lagoon-web/web/
# Build both binaries
RUN cargo build --release -p lagoon-server -p lagoon-web

# Stage 2: Build Vue.js frontend
FROM node:22-slim AS web-build
WORKDIR /build
COPY crates/lagoon-web/web/package.json crates/lagoon-web/web/package-lock.json ./
RUN npm ci
COPY crates/lagoon-web/web/ ./
RUN npm run build

# Stage 3: Runtime
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=rust-build /build/target/release/lagoon /usr/local/bin/lagoon
COPY --from=rust-build /build/target/release/lagoon-web /usr/local/bin/lagoon-web
COPY --from=web-build /build/dist/ /opt/lagoon-web/web/dist/

WORKDIR /opt/lagoon-web

# Embedded mode: lagoon-web runs with IRC server built-in.
# No external IRC port — all access via web gateway only.
ENV LAGOON_EMBEDDED=1
ENV LAGOON_WEB_NO_TLS=1
ENV LAGOON_WEB_ADDR=0.0.0.0:8080
ENV LAGOON_IRC_ADDR=127.0.0.1:6667
ENV LAGOON_DATA_DIR=/data
ENV LAGOON_PEERS=lon.lagun.co:443
ENV SERVER_NAME=lagun.co
ENV RUST_LOG=info

EXPOSE 8080

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
