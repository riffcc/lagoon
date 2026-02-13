# Stage 1: Build Rust binaries
FROM rust:1-bookworm AS rust-build

# Install Go (needed by yggbridge crate's build.rs)
RUN curl -fsSL https://go.dev/dl/go1.23.6.linux-amd64.tar.gz | tar -C /usr/local -xzf -
ENV PATH="/usr/local/go/bin:${PATH}"

# Clone citadel (path dependency) at the same absolute path Cargo.toml expects
RUN git clone --depth 1 -b zorlin/v2-rewrite https://github.com/rifflabs/citadel.git \
    /mnt/riffcastle/lagun-project/citadel

WORKDIR /build
# Cache-bust arg: pass --build-arg CACHEBUST=$(date +%s) to force rebuild
ARG CACHEBUST=0
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

EXPOSE 8080

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
