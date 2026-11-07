# Build context: this directory. Trial: `minikube image build -t kubeheal-sensor:trial sensor/`.
FROM rust:1-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends clang libelf-dev zlib1g-dev libbpf-dev make pkg-config \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
RUN rustup component add rustfmt
ENV C_INCLUDE_PATH=/usr/include/x86_64-linux-gnu
RUN cargo build --release --locked

# libelf/zlib are dynamically linked by libbpf-sys; distroless/cc lacks them
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libelf1 zlib1g && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/kubeheal-sensor /kubeheal-sensor
ENTRYPOINT ["/kubeheal-sensor"]
