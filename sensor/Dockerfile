# syntax=docker/dockerfile:1
# Build context: this directory. `minikube image build -t kubeheal.invalid/sensor:v5 sensor/` (deploy/scripts/install.sh does it).
# Multi-arch (linux/amd64, linux/arm64): `docker buildx build --platform linux/amd64,linux/arm64 sensor/`.
# The build stage always runs on the BUILD host's arch and cross-compiles (Debian multiarch + gcc-<arch>-linux-gnu),
# so no QEMU is needed to compile; only the final stage is per-target. Cross beats QEMU here: an emulated rustc+clang
# build is ~10x slower. Base images are pinned by digest (multi-arch index): bump tag and digest together.
FROM --platform=$BUILDPLATFORM rust:1-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS build
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) echo x86_64 >/arch; echo x86_64-linux-gnu >/triple; echo "" >/cross ;; \
      arm64) echo aarch64 >/arch; echo aarch64-linux-gnu >/triple; echo "gcc-aarch64-linux-gnu libc6-dev-arm64-cross" >/cross ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH"; exit 1 ;; esac \
 && if [ "$(cat /arch)" != "$(uname -m)" ]; then dpkg --add-architecture "$TARGETARCH"; fi \
 && apt-get update && apt-get install -y --no-install-recommends clang make pkg-config libbpf-dev \
      libelf-dev:"$TARGETARCH" zlib1g-dev:"$TARGETARCH" $(cat /cross) \
 && rustup target add "$(cat /arch)-unknown-linux-gnu" && rustup component add rustfmt \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
# /cross.sh: the cross-compile environment for $TARGETARCH (native build on a same-arch host).
RUN T="$(cat /arch)-unknown-linux-gnu"; TR="$(cat /triple)"; U="$(echo "$T" | tr a-z- A-Z_)"; L="$(echo "$T" | tr - _)"; CC="$TR-gcc"; \
    if [ "$(cat /arch)" = "$(uname -m)" ]; then CC=gcc; fi; \
    printf 'T=%s\nTR=%s\nexport CARGO_TARGET_%s_LINKER=%s CC_%s=%s PKG_CONFIG_ALLOW_CROSS=1 PKG_CONFIG_PATH=/usr/lib/%s/pkgconfig\n' \
      "$T" "$TR" "$U" "$CC" "$L" "$CC" "$TR" >/cross.sh

# CI: `docker buildx build --target clippy --platform linux/arm64 sensor/` lints the arm64 build (not part of the image).
FROM build AS clippy
ARG TARGETARCH
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target,id=sensor-target-$TARGETARCH \
    . /cross.sh && rustup component add clippy && cargo clippy --release --locked --target "$T" -- -D warnings

# CI: `--target test-bin -o out` exports the cross-compiled unit-test binary; run it under QEMU in the runtime image:
#   docker run --rm --platform linux/arm64 --entrypoint /t -v $PWD/out/kubeheal-sensor-tests:/t:ro <sensor image>
FROM build AS test-build
ARG TARGETARCH
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target,id=sensor-target-$TARGETARCH \
    . /cross.sh && cargo test --release --locked --target "$T" --no-run 2>&1 | tee /log \
 && cp "$(sed -n 's/^ *Executable unittests .*(\(.*\))$/\1/p' /log)" /kubeheal-sensor-tests
FROM scratch AS test-bin
COPY --from=test-build /kubeheal-sensor-tests /

# build.rs adds -I/usr/include/<triple> for the bpf object's asm/ headers (arch-neutral target, per-arch -D__TARGET_ARCH_*).
# cache mounts: a rebuild after a source change recompiles only this crate
FROM build AS release
ARG TARGETARCH
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target,id=sensor-target-$TARGETARCH \
    . /cross.sh && cargo build --release --locked --target "$T" && cp "target/$T/release/kubeheal-sensor" /kubeheal-sensor \
 && mkdir /libs && cp -a /usr/lib/$TR/libelf*.so* /usr/lib/$TR/libz.so.1* /libs/

# libelf/zlib are dynamically linked by libbpf-sys; distroless/cc lacks them. Staged from the build stage
# (the target arch's multiarch lib dir) so this stage has no RUN and needs no QEMU. /usr/lib is on ld.so's default path.
FROM gcr.io/distroless/cc-debian12:latest@sha256:e5d81ddde149641e2a9ba55be4545bc125c67de07508b03ba4c22e6eb0ded5aa
COPY --from=release /libs/ /usr/lib/
COPY --from=release /kubeheal-sensor /kubeheal-sensor
ENTRYPOINT ["/kubeheal-sensor"]
