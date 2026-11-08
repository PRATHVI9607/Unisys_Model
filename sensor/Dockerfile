# syntax=docker/dockerfile:1
# Build context: this directory. `minikube image build -t kubeheal.invalid/sensor:v5 sensor/` (deploy/scripts/install.sh does it).
FROM rust:1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang libelf-dev zlib1g-dev libbpf-dev make pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
RUN rustup component add rustfmt
ENV C_INCLUDE_PATH=/usr/include/x86_64-linux-gnu
# cache mounts: a rebuild after a source change recompiles only this crate
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target \
    cargo build --release --locked && cp target/release/kubeheal-sensor /kubeheal-sensor

# libelf/zlib are dynamically linked by libbpf-sys; distroless/cc lacks them
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libelf1 zlib1g && rm -rf /var/lib/apt/lists/*
COPY --from=build /kubeheal-sensor /kubeheal-sensor
ENTRYPOINT ["/kubeheal-sensor"]
