# zeenome-poc

Service-free proof-of-concept that walks the Zeenome trust chain with the four Rust CLIs — told in the same order as [zeenome.xyz/trust-chain](https://zeenome.xyz/trust-chain):

1. **Accreditor** — publishes a signed clinician allowlist
2. **Clinician** — reduces genome + phenotype to Merkle fingerprints
3. **Registry** — publishes epoch / registry roots and clinician seals
4. **Researcher** — publishes an inquiry pinning program hash + allowlist
5. **Patient** — runs real SP1 prove locally; genome never leaves
6. **Researcher** — verifies the succinct proof against the published program

Default console output is that story (human-readable values). Pass `--verbose` for raw CLI chatter.

## Fixtures

Paths below are under `apps/poc/fixtures/`. Override with env vars or Docker mounts (see Run).

### Actors (`keys/actors.json`)

Ed25519 actors for the four CLIs (override with `POC_KEYS_PATH`).

| Field | Role |
|-------|------|
| `accreditor` | Signs the whitelist epoch (`id`, `display_name`, `public_key`, `private_key`) |
| `clinician` | Signs genomic/phenotype epochs; its public key is a whitelist leaf |
| `researcher` | Signs the local `create-job` payload |
| `client.id` | Patient/client identifier used in the demo |
| `catalog_sample_id` | Sample id bound into clinician artifacts (`ERR3239292/NA11894` for the bundled VCF) |
| `job_id` | Inquiry / job id |
| `whitelist_id` | Accreditor whitelist id |

Keys are hex (`public_key`) and base64 (`private_key`) as produced by `zeenome-poc-signing`. Regenerate the committed sample with fixed seeds:

```bash
npx tsx apps/poc/scripts/gen-sample-keys.ts
# or, from apps/poc: npm run gen-keys
```

### Genome (`genomes/ERR3239292_NA11894_irisplex.vcf`)

IrisPlex panel VCF (GRCh38) for 1000 Genomes sample **NA11894** / run **ERR3239292** — six loci with genotypes, used by `clinician process-genome`. Override with `POC_VCF_PATH`. Keep `actors.json` → `catalog_sample_id` in sync if you swap the file.

### Phenopacket (`phenopackets/demo.json`)

Minimal Phenopacket schema v2 JSON used by `clinician process-phenopacket` (subject id matches `client.id`, one HPO feature). Override with `POC_PHENOPACKET_PATH`.

## Run

### Docker

Published image (once pushed):

```bash
docker run --rm -it -v poc-work:/work threevl/zeenome-poc:latest
```

Build locally from repository root (heavy: SP1 toolchain + guest ELF compile):

```bash
DOCKER_BUILDKIT=1 docker build -f apps/poc/Dockerfile \
  -t threevl/zeenome-poc:latest \
  .

docker run --rm -it \
  -v poc-work:/work \
  threevl/zeenome-poc:latest
```

Mount your own fixtures:

```bash
docker run --rm -it \
  -v "$PWD/my-actors.json:/poc/fixtures/keys/actors.json:ro" \
  -v "$PWD/my-sample.vcf:/poc/fixtures/genomes/ERR3239292_NA11894_irisplex.vcf:ro" \
  -v "$PWD/my-pheno.json:/poc/fixtures/phenopackets/demo.json:ro" \
  -v poc-work:/work \
  threevl/zeenome-poc:latest
```

(`/poc` is a symlink to `/app/apps/poc` inside the image.)

### Local (source)

Prerequisites: Rust 1.91, SP1 toolchain, Node 22, built CLIs + irisplex ELF.

```bash
cargo build --release -p accreditor-cli -p clinician-cli -p client-cli -p researcher-cli
cargo build --release -p zk-irisplex

# Required: pass the built guest ELF (from repository root):
./apps/poc/run.sh --elf target/cargo/elf-compilation/riscv64im-succinct-zkvm-elf/release/zk-irisplex-program

# Same via env:
POC_ELF_PATH=target/cargo/elf-compilation/riscv64im-succinct-zkvm-elf/release/zk-irisplex-program \
  ./apps/poc/run.sh

# Raw CLI commands + stdout/stderr:
./apps/poc/run.sh --elf … --verbose
```

Environment knobs:

| Variable | Default |
|----------|---------|
| `POC_WORK_DIR` | Directory you ran the script from (`$PWD`); container ENTRYPOINT uses `/work` |
| `POC_KEYS_PATH` | `apps/poc/fixtures/keys/actors.json` |
| `POC_VCF_PATH` | `apps/poc/fixtures/genomes/ERR3239292_NA11894_irisplex.vcf` |
| `POC_PHENOPACKET_PATH` | `apps/poc/fixtures/phenopackets/demo.json` |
| `POC_ELF_PATH` | **required** (image sets `/app/apps/poc/fixtures/guest/program.elf`) |
| `POC_VERBOSE` | unset (story mode); `1` / `true` shows raw CLI output |
| `POC_SWAP_SIZE_GB` | `32` — `apps/poc/run.sh` ensures this much swap (needs sudo) |
| `POC_SKIP_SWAP` | unset; `1` skips swap setup (same as `--no-swap`) |
| `POC_CLINICIAN_BIN` etc. | bare `clinician` / `client` / … on `PATH` |

SP1 core proving peaks around **14+ GiB RSS**. On a 16 GiB host with no swap the
kernel OOM-kills `client` (`exit null` / `SIGKILL`). `apps/poc/run.sh` creates
`/var/tmp/zeenome-poc.swap` when passwordless sudo is available. In Docker, enable
swap on the **host** (or pass sufficient `--memory` / `--memory-swap`).

## License

Licensed under either of **MIT** or **Apache-2.0** at your option. See [`LICENSE`](LICENSE), [`LICENSE-MIT`](LICENSE-MIT), and [`LICENSE-APACHE`](LICENSE-APACHE).
