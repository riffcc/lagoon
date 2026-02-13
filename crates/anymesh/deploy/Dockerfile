FROM rust:1.85-slim-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates/anymesh/ crates/anymesh/
# Stub out other workspace members so cargo resolves the workspace.
RUN mkdir -p crates/lagoon-server/src crates/lagoon-web/src crates/lagoon-vdf/src \
    && echo "fn main(){}" > crates/lagoon-server/src/main.rs \
    && echo "fn main(){}" > crates/lagoon-web/src/main.rs \
    && touch crates/lagoon-vdf/src/lib.rs
COPY crates/lagoon-server/Cargo.toml crates/lagoon-server/
COPY crates/lagoon-web/Cargo.toml crates/lagoon-web/
COPY crates/lagoon-vdf/Cargo.toml crates/lagoon-vdf/
RUN cargo build --release -p anymesh && strip target/release/anymesh

FROM debian:bookworm-slim
COPY --from=builder /src/target/release/anymesh /usr/local/bin/anymesh
ENV PORT="42105"
EXPOSE 42105
ENTRYPOINT ["anymesh"]
