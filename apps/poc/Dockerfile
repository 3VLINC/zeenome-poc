# syntax=docker/dockerfile:1.4
# Zeenome POC — trust-chain demo.
# Build from repository root:
#   DOCKER_BUILDKIT=1 docker build -f apps/poc/Dockerfile -t threevl/zeenome-poc .
#
# Runtime: four Rust CLIs, SP1 prover, prebuilt zk-irisplex ELF,
# sample keys + IrisPlex VCF, TypeScript orchestrator.

ARG GO_VERSION=1.22.12
ARG SP1_RELEASE=v6.1.0
ARG SP1_VERSION=6.1.0

# -----------------------------------------------------------------------------
FROM rust:1.91-bookworm AS rust-toolchain
ARG DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
ENV PATH="/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates curl git build-essential pkg-config libssl-dev \
  protobuf-compiler libprotobuf-dev \
  && rm -rf /var/lib/apt/lists/* \
  && mkdir -p /opt/rustup/tmp /opt/cargo /opt/sp1 \
  && bash -euxo pipefail -c '\
    export TMPDIR=/opt/rustup/tmp; \
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
      -y --no-modify-path --profile minimal --default-toolchain 1.91.0; \
    . /opt/cargo/env; \
    rustc --version && cargo --version'

# -----------------------------------------------------------------------------
FROM rust-toolchain AS sp1-toolchain
ARG GO_VERSION
ARG SP1_RELEASE
ARG SP1_VERSION

RUN set -eux; \
  ARCH="$(dpkg --print-architecture)"; \
  case "$ARCH" in \
    amd64) GOARCH=amd64 ;; \
    arm64) GOARCH=arm64 ;; \
    *) echo "unsupported architecture: $ARCH" >&2; exit 1 ;; \
  esac; \
  curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -o /tmp/go.tgz; \
  tar -C /usr/local -xzf /tmp/go.tgz; \
  rm /tmp/go.tgz

ENV SP1_RELEASE=${SP1_RELEASE}

RUN env "SP1_VERSION=${SP1_VERSION}" bash <<'EOS'
set -euxo pipefail
export HOME=/opt/sp1-bootstrap
mkdir -p "${HOME}"
export PATH="/usr/local/go/bin:/opt/cargo/bin:${PATH}"
export TMPDIR=/opt/rustup/tmp
unset RUSTFLAGS
unset RUSTUP_TOOLCHAIN
. /opt/cargo/env
curl -fsSL https://sp1up.succinct.xyz | bash
export PATH="/usr/local/go/bin:/opt/cargo/bin:${HOME}/.sp1/bin:${PATH}"
sp1up -v "${SP1_VERSION}"
if [ -d "${HOME}/.sp1" ]; then cp -a "${HOME}/.sp1"/. /opt/sp1/; fi
rm -rf "${HOME}"
. /opt/cargo/env
SUCCINCT_TOOLCHAIN="$(find /opt/sp1/toolchains -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | head -n1)"
[ -n "${SUCCINCT_TOOLCHAIN}" ]
rustup toolchain uninstall succinct 2>/dev/null || true
rustup toolchain link succinct "${SUCCINCT_TOOLCHAIN}"
EOS

# -----------------------------------------------------------------------------
FROM sp1-toolchain AS rust-builder
WORKDIR /app
COPY .cargo ./.cargo
COPY Cargo.toml Cargo.lock ./
COPY apps ./apps
COPY libs ./libs

ENV PATH="/usr/local/go/bin:/opt/cargo/bin:/opt/sp1/bin:${PATH}"

RUN --mount=type=cache,target=/opt/cargo/registry \
  --mount=type=cache,target=/opt/cargo/git \
  --mount=type=cache,id=poc-cargo-target,target=/app/target \
  cargo build --locked --release \
    -p researcher-cli \
    -p client-cli \
    -p clinician-cli \
    -p accreditor-cli \
  && mkdir -p /out/bin \
  && cp target/cargo/release/researcher /out/bin/researcher \
  && cp target/cargo/release/client /out/bin/client \
  && cp target/cargo/release/clinician /out/bin/clinician \
  && cp target/cargo/release/accreditor /out/bin/accreditor

# Build zk-irisplex guest ELF (content-addressed as bundle_id = sha256(elf)).
RUN --mount=type=cache,target=/opt/cargo/registry \
  --mount=type=cache,target=/opt/cargo/git \
  --mount=type=cache,id=poc-cargo-target,target=/app/target \
  RUST_LOG=info cargo build --release --manifest-path apps/zk-irisplex/scripts/Cargo.toml \
  && mkdir -p /out/guest \
  && ELF="$(find target/cargo/elf-compilation -name zk-irisplex-program -type f | head -n1)" \
  && test -n "$ELF" && test -f "$ELF" \
  && cp "$ELF" /out/guest/program.elf \
  && sha256sum /out/guest/program.elf

# -----------------------------------------------------------------------------
FROM node:22-bookworm-slim AS runtime
ARG DEBIAN_FRONTEND=noninteractive

ENV NODE_ENV=production
ENV RUSTUP_HOME=/opt/rustup
ENV CARGO_HOME=/opt/cargo
ENV PATH="/opt/cargo/bin:/opt/sp1/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV POC_REPO_ROOT=/app
ENV POC_WORK_DIR=/work
ENV POC_KEYS_PATH=/app/apps/poc/fixtures/keys/actors.json
ENV POC_VCF_PATH=/app/apps/poc/fixtures/genomes/ERR3239292_NA11894_irisplex.vcf
ENV POC_PHENOPACKET_PATH=/app/apps/poc/fixtures/phenopackets/demo.json
ENV POC_ELF_PATH=/app/apps/poc/fixtures/guest/program.elf
# CPU proving by default (override at docker run if needed).
ENV SP1_PROVER=cpu

RUN apt-get update && apt-get install -y --no-install-recommends \
  ca-certificates libssl3 curl \
  && rm -rf /var/lib/apt/lists/*

COPY --from=sp1-toolchain /opt/rustup /opt/rustup
COPY --from=sp1-toolchain /opt/cargo /opt/cargo
COPY --from=sp1-toolchain /opt/sp1 /opt/sp1
RUN mkdir -p /opt/rustup/tmp /opt/cargo/registry /opt/cargo/git \
  && chmod -R ugo+rwX /opt/rustup/tmp /opt/cargo/registry /opt/cargo/git \
  && chmod -R ugo+rX /opt/rustup /opt/cargo /opt/sp1 \
  && ln -sf /opt/cargo/bin/cargo /usr/local/bin/cargo \
  && ln -sf /opt/cargo/bin/rustc /usr/local/bin/rustc \
  && ln -sf /opt/cargo/bin/rustup /usr/local/bin/rustup

COPY --from=rust-builder /out/bin/researcher /usr/local/bin/researcher
COPY --from=rust-builder /out/bin/client /usr/local/bin/client
COPY --from=rust-builder /out/bin/clinician /usr/local/bin/clinician
COPY --from=rust-builder /out/bin/accreditor /usr/local/bin/accreditor

WORKDIR /app
# Minimal Node install for the orchestrator + zeenome-poc-signing.
COPY packages/signing ./packages/signing
COPY apps/poc ./apps/poc
COPY --from=rust-builder /out/guest/program.elf ./apps/poc/fixtures/guest/program.elf

# The orchestrator loads zeenome-poc-signing from source, so Node resolves the
# signing package's own runtime deps (@noble/ed25519, @noble/hashes) from
# packages/signing/node_modules. The apps/poc install does not populate that, so
# install them here.
WORKDIR /app/packages/signing
RUN npm install --omit=dev

WORKDIR /app/apps/poc
RUN npm install --omit=dev

# Short mount alias: -v ./keys:/poc/fixtures/keys:ro
RUN ln -sfn /app/apps/poc /poc \
  && mkdir -p /work && chmod 777 /work \
  && chmod +x /app/apps/poc/run.sh

WORKDIR /work
ENTRYPOINT ["/app/apps/poc/run.sh"]
