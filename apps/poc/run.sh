#!/usr/bin/env bash
# Entrypoint for the zeenome-poc container (and local convenience wrapper).
set -euo pipefail

POC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Monorepo root is two levels up from apps/poc in source; in the image
# the same relative layout is /app/apps/poc → /app.
ROOT="$(cd "$POC_DIR/../.." && pwd)"

# Capture where the user invoked the script before we cd elsewhere.
CALLER_PWD="$PWD"

usage() {
  cat <<'EOF'
Usage: ./run.sh --elf PATH [--work-dir PATH] [--verbose] [--no-swap] [--help]

  --elf PATH       Required guest ELF path (sets POC_ELF_PATH).
  --work-dir PATH  Working directory for state/snapshots/data (default: cwd).
  --verbose, -v    Show raw CLI commands and output.
  --no-swap        Skip ensuring swap (SP1 prove often needs ~32 GiB swap on 16 GiB hosts).
  --help           Show this help.

Default output is a human-readable trust-chain story
(https://zeenome.xyz/trust-chain). Artifacts still land under the work dir.

Environment overrides: POC_ELF_PATH, POC_WORK_DIR, POC_VCF_PATH, POC_KEYS_PATH,
POC_PHENOPACKET_PATH, POC_VERBOSE=1, POC_SWAP_SIZE_GB, POC_SWAPFILE, POC_*_BIN.
EOF
}

# Resolve a user path against the directory they invoked the script from
# (we later cd to the repo root for cargo/tsx).
abspath_from_caller() {
  local p="$1"
  if [[ "$p" = /* ]]; then
    printf '%s\n' "$p"
  else
    (cd "$CALLER_PWD" && realpath -m -- "$p")
  fi
}

FORWARD_ARGS=()
ENSURE_SWAP=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --elf)
      [[ $# -ge 2 ]] || { echo "error: --elf requires a path" >&2; exit 2; }
      export POC_ELF_PATH
      POC_ELF_PATH="$(abspath_from_caller "$2")"
      shift 2
      ;;
    --work-dir)
      [[ $# -ge 2 ]] || { echo "error: --work-dir requires a path" >&2; exit 2; }
      export POC_WORK_DIR
      POC_WORK_DIR="$(abspath_from_caller "$2")"
      shift 2
      ;;
    -v|--verbose)
      export POC_VERBOSE=1
      FORWARD_ARGS+=("--verbose")
      shift
      ;;
    --no-swap)
      ENSURE_SWAP=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done
if ((${#FORWARD_ARGS[@]})); then
  set -- "${FORWARD_ARGS[@]}"
else
  set --
fi

export POC_REPO_ROOT="${POC_REPO_ROOT:-$ROOT}"

# SP1 core prove OOMs on ~16 GiB hosts without swap (client was killed at ~14 GiB RSS).
if [[ "$ENSURE_SWAP" == "1" && "${POC_SKIP_SWAP:-}" != "1" ]]; then
  bash "$POC_DIR/scripts/ensure-swap.sh" || true
fi

# Work dir: explicit POC_WORK_DIR, else the directory the script was run from.
# In the container ENTRYPOINT cwd is /work, so that remains the default there.
export POC_WORK_DIR="${POC_WORK_DIR:-$CALLER_PWD}"
mkdir -p "$POC_WORK_DIR"

export POC_KEYS_PATH="${POC_KEYS_PATH:-$POC_DIR/fixtures/keys/actors.json}"
export POC_VCF_PATH="${POC_VCF_PATH:-$POC_DIR/fixtures/genomes/ERR3239292_NA11894_irisplex.vcf}"
export POC_PHENOPACKET_PATH="${POC_PHENOPACKET_PATH:-$POC_DIR/fixtures/phenopackets/demo.json}"
# POC_ELF_PATH must be set via --elf or env (no auto-detect).

# Prefer PATH binaries installed by the image; then monorepo release builds;
# fall back to cargo run in a source checkout.
if ! command -v clinician >/dev/null 2>&1; then
  RELEASE_BIN="$POC_REPO_ROOT/target/cargo/release"
  if [[ -x "$RELEASE_BIN/clinician" && -x "$RELEASE_BIN/client" && \
        -x "$RELEASE_BIN/researcher" && -x "$RELEASE_BIN/accreditor" ]]; then
    export POC_CLINICIAN_BIN="$RELEASE_BIN/clinician"
    export POC_CLIENT_BIN="$RELEASE_BIN/client"
    export POC_RESEARCHER_BIN="$RELEASE_BIN/researcher"
    export POC_ACCREDITOR_BIN="$RELEASE_BIN/accreditor"
  else
    export POC_USE_CARGO=1
  fi
fi

cd "$POC_REPO_ROOT"

if [[ -x "$POC_DIR/node_modules/.bin/tsx" ]]; then
  exec "$POC_DIR/node_modules/.bin/tsx" "$POC_DIR/src/run.ts" "$@"
fi

if command -v tsx >/dev/null 2>&1; then
  exec tsx "$POC_DIR/src/run.ts" "$@"
fi

exec npx --yes tsx "$POC_DIR/src/run.ts" "$@"
