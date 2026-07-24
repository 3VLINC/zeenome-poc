# zeenome-poc

Service-free proof-of-concept that walks the Zeenome trust chain with the four Rust CLIs — told in the same order as [zeenome.xyz/trust-chain](https://zeenome.xyz/trust-chain):

1. **Accreditor** — publishes a signed clinician allowlist
2. **Clinician** — reduces genome + phenotype to Merkle fingerprints
3. **Registry** — publishes epoch / registry roots and clinician seals
4. **Researcher** — publishes an inquiry pinning program hash + allowlist
5. **Patient** — runs real SP1 prove locally; genome never leaves
6. **Researcher** — verifies the succinct proof against the published program

Default console output is that story (human-readable values). Pass `--verbose` for raw CLI chatter.

## The trust chain, step by step

> The narrative from [zeenome.xyz/trust-chain](https://zeenome.xyz/trust-chain) — the same story the demo prints, one link at a time.

**From accreditation to a proof a researcher can trust.** A researcher never sees a patient's health information — yet they can trust that a result was computed from data a real, accredited clinician attested to. That trust is built one link at a time. Follow the chain from the top: each link's output becomes the next link's input, and the final proof only checks out if every link held.

**The cast**

| Actor | Role |
|-------|------|
| Accreditor | Vouches for which organizations are legitimate |
| Clinician | Collects the data under an organization's authority |
| Registry | Public, append-only record of attestations |
| Researcher | Publishes an inquiry and verifies the answer |
| Patient | Holds their own data and runs the job locally |

### 1. Accreditor — An accreditor publishes the list of organizations it trusts

*Vouches for which organizations are legitimate*

Before any genome is sequenced, someone has to answer a basic question: which labs and organizations are the real thing? An accreditor — a body that vets sequencing providers — answers it by publishing a signed allowlist of organization public keys.

This allowlist is a snapshot of every organization public key the accreditor stands behind. Researchers will later point at one of these snapshots to say "I only trust results signed by organizations on this list."

> **The cryptography** — The allowlisted public keys are hashed into a Merkle tree, and the accreditor signs the tree's root. Anyone can later prove a single organization is on the list without downloading the whole list.

### 2. Clinician — A clinician collects the data and reduces it to a fingerprint

*Collects the data under an organization's authority*

A clinician collects genotypic or phenotypic data on the authority of their organization – one vouched for by the accreditor in the last step. Instead of publishing the raw data, the organization will later commit to a fingerprint of it. This step only builds that fingerprint: canonicalize each field and merkleize it.

Both data types are canonicalized so the same data always yields the same fingerprint and any change is detectable. Logging, registry publication, and signing come next.

> **The cryptography** — Each data type is turned into leaves by its own canonical preimage. A genotype uses a fixed SNP record encoding; a phenotype uses canonical JSON — each leaf is a (JSON pointer, value) pair serialized deterministically so key order and formatting can't change the result. Those leaves combine into a Merkle tree whose root is the fingerprint published next — and the patient keeps the private inclusion path that proves their leaves sit under that fingerprint.

### 3. Registry — The organization batches the fingerprint, publishes the epoch root, and signs

*Organization batches, publishes, and endorses an epoch*

Three jobs: put staged fingerprints into an epoch batch, put that epoch root on the public registry, then sign so outsiders know who endorsed it. Orgs choose when to publish — hourly, daily, or whenever enough artifacts are ready.

Only fingerprints, epoch/registry roots, and signatures become public — never genotype or phenotype. The patient (or their care path) also receives a private inclusion proof that their fingerprint sits under those published roots.

> **The cryptography** — Each publish folds the staged fingerprints into an epoch batch, then that epoch root into the public registry. Anyone can recompute those roots; the org's signature is what proves who endorsed them. The patient keeps a private MMR inclusion proof that this fingerprint was in that batch — later the ZK guest checks that path against the public roots.

### 4. Researcher — A researcher publishes an inquiry and pins who they trust

*Publishes an inquiry and verifies the answer*

A researcher wants an answer to a question — say, which breast-cancer polygenic risk score generalizes better across ancestries — computed over many patients without ever collecting their genomes. They publish an inquiry: a small program plus the rules for whose data counts.

Crucially, the researcher publishes the exact program (by content hash) that will run, and pins which accreditor allowlist they accept. Tamper with the allowlist pin and the proof returned to the researcher won't verify.

> **The cryptography** — The inquiry publishes a content-addressed program (a hash of the exact ZK guest) and pins an accreditor allowlist root. The patient later supplies a private allowlist inclusion proof against that pin inside the guest — the researcher never sees the path, only whether the succinct proof verifies.

### 5. Patient — The job runs where the patient's data lives — and proves it was honest

*Keeps their data inside a trust boundary they control*

The genome never leaves the patient's control. The inquiry runs inside a zero-knowledge virtual machine somewhere the patient trusts — a trusted care provider acting on their behalf, or dedicated local hardware. Wherever it runs, the computation produces the answer the researcher asked for and a proof that it followed the rules.

This is where every earlier link is checked at once. The patient supplies private inclusion proofs — that their data sits under the signed fingerprint, that fingerprint sits in the published registry, and that the signing org is on the researcher's pinned allowlist — plus the org signature. Because only the patient holds those witnesses, only they can produce this proof.

> **The cryptography** — Private witnesses include a bundled inclusion_proof (data / registry / allowlist paths) and the org signature. Inside the ZK circuit those paths must verify against the public roots the researcher pinned and the org published. Only then does the program emit public outputs, a nullifier, and a succinct proof — the only values that leave.

### 6. Researcher — The researcher verifies the proof — trusting math, not a middleman

*Publishes an inquiry and verifies the answer*

The patient submits only the answer, a nullifier that prevents double-counting, and the proof. The researcher checks the proof against the program they published. If it verifies, they know the answer was computed correctly from properly attested data — without ever seeing the genome or the private inclusion proofs.

Verification happens in the researcher's own trust domain. The registry was only a transport and a public record; it never had the power to certify results. The guarantee comes from the cryptography, not from trusting any single party in the middle.

> **The cryptography** — The researcher verifies the succinct proof against the program they published. A valid proof implies every in-circuit check passed — including the private inclusion proofs the researcher never sees. The nullifier lets the researcher reject duplicate submissions without learning who the patient is.

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
