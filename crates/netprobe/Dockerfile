FROM rust:1.84-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.toml
COPY src/ src/
RUN cargo build --release

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y iproute2 && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/netprobe /usr/local/bin/netprobe
EXPOSE 58888
CMD ["netprobe"]
