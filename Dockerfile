# syntax=docker/dockerfile:1
#
# Multi-stage, multi-arch build producing a static musl binary in a distroless
# image.
#
# musl static linking works here only because the dependency tree is entirely
# Rust: DNSSEC, DoT, DoH and DoQ are all disabled, so neither `ring` nor
# `aws-lc-rs` nor `rustls` is pulled in. If a C dependency is ever added, switch
# to glibc + `distroless/cc` rather than fighting musl.

ARG RUST_VERSION=1.97
ARG ALPINE_VERSION=3.22

# --- build -------------------------------------------------------------------
# Cross-compile from the build platform rather than emulating the target under
# QEMU: the latter is roughly an order of magnitude slower for a Rust build.
FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-alpine${ALPINE_VERSION} AS build

RUN apk add --no-cache musl-dev

ARG TARGETARCH
RUN case "$TARGETARCH" in \
      amd64) echo x86_64-unknown-linux-musl  > /target.txt ;; \
      arm64) echo aarch64-unknown-linux-musl > /target.txt ;; \
      *) echo "unsupported TARGETARCH: $TARGETARCH" >&2; exit 1 ;; \
    esac && \
    rustup target add "$(cat /target.txt)"

# Link with rust-lld instead of `cc`.
#
# The build stage runs on the *build* platform, so when the target differs the
# native `cc` is asked to link foreign objects and fails with
# "unrecognized command-line option '-m64'". A C cross-toolchain would fix that,
# but is unnecessary here: the dependency tree is pure Rust (no ring, aws-lc-rs,
# openssl-sys or rustls — enforced in deny.toml), so rust-lld, which ships with
# the toolchain, can link the whole thing on its own.
#
# The path is derived rather than hardcoded so it survives toolchain and host
# changes.
RUN printf '%s/lib/rustlib/%s/bin\n' \
      "$(rustc --print sysroot)" \
      "$(rustc -vV | awk '/^host: /{print $2}')" > /lld-path.txt && \
    test -x "$(cat /lld-path.txt)/rust-lld"
ENV RUSTFLAGS="-C linker=rust-lld"

WORKDIR /src

# Dependency layer first, so editing our own sources does not rebuild the world.
# The dummy sources are the smallest thing that lets `cargo build` resolve and
# compile every dependency.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
RUN mkdir -p src && \
    echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs && \
    PATH="$(cat /lld-path.txt):$PATH" \
      cargo build --release --locked --target "$(cat /target.txt)" && \
    rm -rf src

COPY src ./src
# cargo caches by mtime; touching guarantees our real sources are seen as newer
# than the dummies compiled above.
RUN touch src/main.rs src/lib.rs && \
    PATH="$(cat /lld-path.txt):$PATH" \
      cargo build --release --locked --target "$(cat /target.txt)" && \
    cp "target/$(cat /target.txt)/release/panoptidns" /panoptidns

# --- runtime -----------------------------------------------------------------
# distroless/static:nonroot over scratch: the same effective attack surface, but
# with a real /etc/passwd for uid 65532 and a writable /tmp.
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="PanoptiDNS" \
      org.opencontainers.image.description="Authoritative DNS server that synthesizes IPv6 reverse (PTR) and forward (AAAA) records on the fly" \
      org.opencontainers.image.source="https://github.com/CygnusNetworks/PanoptiDNS" \
      org.opencontainers.image.licenses="BSD-3-Clause"

COPY --from=build /panoptidns /panoptidns

USER 65532:65532
EXPOSE 53/udp 53/tcp

# Exec form: distroless has no shell, so the health check is a subcommand of the
# binary itself. Any well-formed response — including REFUSED — proves the
# server is answering.
HEALTHCHECK --interval=30s --timeout=3s --start-period=2s --retries=3 \
    CMD ["/panoptidns", "--healthcheck"]

ENTRYPOINT ["/panoptidns"]
CMD ["--config", "/etc/panoptidns/panoptidns.conf"]
