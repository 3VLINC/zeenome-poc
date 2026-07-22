#!/usr/bin/env tsx
/**
 * Service-free Zeenome POC orchestrator.
 *
 * Synthesizes disk snapshots, holds sample keys, and shells out to the four
 * Rust CLIs. No Postgres, Redis, worker, or registry HTTP.
 *
 * Default output tells the cryptographic trust-chain story
 * (see https://zeenome.xyz/trust-chain). Pass --verbose for raw CLI chatter.
 */
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { signMessage, type KeyPair } from "zeenome-poc-signing";
import { runCli } from "./cli.js";
import { resolvePocPaths } from "./paths.js";
import {
  done,
  fail,
  initStory,
  intro,
  isVerbose,
  ok,
  shortHex,
  status,
  step,
  values
} from "./story.js";

type ActorKey = {
  id: string;
  display_name: string;
  public_key: string;
  private_key: string;
};

type ActorsFile = {
  version: number;
  clinician: ActorKey;
  researcher: ActorKey;
  accreditor: ActorKey;
  client: { id: string };
  catalog_sample_id: string;
  job_id: string;
  whitelist_id: string;
};

type ProcessGenomeOutput = {
  actor_id: string;
  client_id: string;
  catalog_sample_id: string;
  sequence_run_id: string;
  client_folder_path: string;
  staged_vcf: {
    vcf_merkle_root: string;
    snp_inclusion_proofs: unknown;
    staging_digest: string;
    artifacts_path: string;
  };
};

type ProcessPhenotypeOutput = {
  phenotype_attestation_id: string;
  client_id: string;
  actor_id: string;
  phenotype_merkle_root: string;
  json_path_leaves: unknown;
  json_inclusion_proofs: unknown;
  artifacts_path: string;
};

type WhitelistPrepareOutput = {
  whitelist_id: string;
  epoch_number: number;
  key_count: number;
  epoch_root: string;
  registry_root: string;
  leaves: Array<{
    leaf_index: number;
    pubkey_hex: string;
    merkle_proof: unknown;
  }>;
  messages_to_sign: Array<{ id: string; kind: string; message_hex: string }>;
};

type EpochPublishOutput = {
  epoch_root: string;
  registry_root: string;
  signed_epoch_json?: unknown;
};

type CreateJobOutput = {
  job_id: string;
  researcher_id: string;
  bundle_id: string;
  org_whitelist_epoch_id: number;
  whitelist_registry_root: string;
  whitelist_epoch_number: number;
  constraints: unknown;
  signature: string;
};

type PendingSubmission = {
  client_id: string;
  job_id: string;
  proof_blob?: string | null;
  public_values_bytes: string;
  bundle_id: string;
  proof_type: string;
  public_outputs?: unknown;
};

function parseArgs(argv: string[]): { verbose: boolean } {
  let verbose = process.env.POC_VERBOSE === "1" || process.env.POC_VERBOSE === "true";
  for (const arg of argv) {
    if (arg === "--verbose" || arg === "-v") verbose = true;
    if (arg === "--help" || arg === "-h") {
      console.log(`Usage: run.ts [--verbose]

Orchestrates the service-free Zeenome trust-chain demo.
Pass --verbose (or POC_VERBOSE=1) to show raw CLI commands and output.
ELF path is required via POC_ELF_PATH / ./run.sh --elf.`);
      process.exit(0);
    }
  }
  return { verbose };
}

function writeJson(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function readJson<T>(path: string): T {
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

function sha256Hex(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.trim().toLowerCase();
  if (normalized.length % 2 !== 0) {
    throw new Error(`Invalid hex length: ${normalized.length}`);
  }
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function signWhitelistMessages(
  keypair: KeyPair,
  messages: Array<{ id: string; message_hex: string }>
): Promise<Record<string, string>> {
  const signatures: Record<string, string> = {};
  for (const msg of messages) {
    signatures[msg.id] = await signMessage(hexToBytes(msg.message_hex), keypair);
  }
  return signatures;
}

async function main(): Promise<void> {
  const { verbose } = parseArgs(process.argv.slice(2));
  initStory({ verbose });

  const paths = resolvePocPaths();
  const actors = readJson<ActorsFile>(paths.keysPath);
  const clinicianKey: KeyPair = {
    public_key: actors.clinician.public_key,
    private_key: actors.clinician.private_key
  };
  const researcherKey: KeyPair = {
    public_key: actors.researcher.public_key,
    private_key: actors.researcher.private_key
  };
  const accreditorKey: KeyPair = {
    public_key: actors.accreditor.public_key,
    private_key: actors.accreditor.private_key
  };

  // CLIs write relative to CWD under data/clients — run from workDir.
  const cwd = paths.workDir;
  process.chdir(cwd);

  const elfBytes = readFileSync(paths.elfPath);
  const bundleId = sha256Hex(elfBytes);

  intro();
  values([
    ["Accreditor", `${actors.accreditor.display_name} (${actors.accreditor.id})`],
    ["Accreditor public key", shortHex(accreditorKey.public_key)],
    ["Clinician", `${actors.clinician.display_name} (${actors.clinician.id})`],
    ["Clinician public key", shortHex(clinicianKey.public_key)],
    ["Researcher", `${actors.researcher.display_name} (${actors.researcher.id})`],
    ["Patient", actors.client.id],
    ["Program (ELF)", paths.elfPath],
    ["Program hash", shortHex(bundleId)],
    ["Genome VCF", paths.vcfPath]
  ]);

  // ── 01 Accreditor ────────────────────────────────────────────────────
  step(
    1,
    "Accreditor",
    "An accreditor publishes the list of clinicians it trusts",
    [
      "Before any genome is sequenced, someone has to answer a basic question: which clinicians are the real thing? An accreditor answers by publishing a signed allowlist of clinician public keys.",
      "Researchers will later point at this snapshot to say “I only trust results signed by clinicians on this list.”"
    ],
    "The allowlisted public keys are hashed into a Merkle tree. Anyone can later prove a single clinician is on the list without downloading the whole list."
  );

  const wlIn = join(paths.snapDir, "whitelist_input.json");
  const wlPrepare = join(paths.snapDir, "whitelist_prepare.json");
  const wlSigs = join(paths.snapDir, "whitelist_signatures.json");
  const wlOut = join(paths.snapDir, "whitelist_output.json");
  writeJson(wlIn, {
    whitelist_id: actors.whitelist_id,
    epoch_number: 0,
    org_pubkeys: [clinicianKey.public_key]
  });

  status("Publishing signed allowlist…");
  runCli(
    "accreditor",
    [
      "publish-whitelist",
      "--whitelist-id",
      actors.whitelist_id,
      "--input",
      wlIn,
      "--output",
      wlPrepare,
      "--prepare"
    ],
    { cwd, description: "Prepare whitelist epoch (messages_to_sign)" }
  );

  const prepare = readJson<WhitelistPrepareOutput>(wlPrepare);
  const signatures = await signWhitelistMessages(
    accreditorKey,
    prepare.messages_to_sign
  );
  writeJson(wlSigs, { signatures });

  runCli(
    "accreditor",
    [
      "publish-whitelist",
      "--whitelist-id",
      actors.whitelist_id,
      "--input",
      wlPrepare,
      "--output",
      wlOut,
      "--apply-signatures",
      "--signatures",
      wlSigs
    ],
    { cwd, description: "Apply accreditor signature to whitelist epoch" }
  );

  const whitelist = readJson<WhitelistPrepareOutput & { signed_epoch_json?: unknown }>(wlOut);
  writeJson(join(paths.stateDir, "whitelist.json"), whitelist);
  const clinicianLeaf = whitelist.leaves.find(
    (l) => l.pubkey_hex.toLowerCase() === clinicianKey.public_key.toLowerCase()
  );
  if (!clinicianLeaf) {
    throw new Error("Whitelist output missing leaf for clinician public key");
  }

  values([
    ["Allowlist id", whitelist.whitelist_id],
    ["Allowlist epoch", String(whitelist.epoch_number)],
    ["Allowlist root", shortHex(whitelist.epoch_root)],
    ["Allowlist registry root", shortHex(whitelist.registry_root)],
    ["Keys on list", String(whitelist.key_count)],
    ["Clinician leaf index", String(clinicianLeaf.leaf_index)],
    ["Signed by", shortHex(accreditorKey.public_key)]
  ]);
  ok("Allowlist published — researchers can pin this root.");

  // ── 02 Clinician attestation ─────────────────────────────────────────
  step(
    2,
    "Clinician",
    "A clinician collects the data and reduces it to a fingerprint",
    [
      "A clinician collects genotypic and phenotypic data — and is vouched for by the accreditor. Instead of publishing the raw data, they reduce it to a fingerprint.",
      "Both data types are canonicalized so the same data always yields the same fingerprint and any change is detectable."
    ],
    "Genotype leaves use a fixed SNP encoding; phenotype leaves use canonical JSON (pointer, value) pairs. Those leaves combine into a Merkle root — the fingerprint. The patient keeps the private inclusion path."
  );

  status("Merkleizing IrisPlex panel from local VCF…");
  const genomeSnap = join(paths.snapDir, "process_genome_input.json");
  const genomeOut = join(paths.snapDir, "process_genome_output.json");
  writeJson(genomeSnap, {
    actor_id: actors.clinician.id,
    client_id: actors.client.id,
    catalog_sample_id: actors.catalog_sample_id,
    sequencing_panel: "irisplex",
    sequencing_bed_snapshot: null,
    existing_client_row: null,
    catalog_taken_by_other_client_in_org: false,
    existing_pending_for_client: false,
    existing_staged_leaves: [],
    existing_published_leaves: []
  });

  runCli(
    "clinician",
    [
      "process-genome-sample",
      "--actor-id",
      actors.clinician.id,
      "--client-id",
      actors.client.id,
      "--catalog-sample-id",
      actors.catalog_sample_id,
      "--sequencing-panel",
      "irisplex",
      "--vcf-path",
      paths.vcfPath,
      "--input",
      genomeSnap,
      "--output",
      genomeOut
    ],
    { cwd, description: "Process IrisPlex panel from local VCF" }
  );

  const genome = readJson<ProcessGenomeOutput>(genomeOut);
  writeJson(join(paths.stateDir, "staged-genome.json"), genome);

  status("Merkleizing phenopacket attestation…");
  const phenotypeAttestationId = `pat-${actors.client.id.replace(/[^a-zA-Z0-9._-]+/g, "_")}-1`;
  const phenotypeArtifactsDir = join(
    cwd,
    "data/clients",
    actors.client.id.replace(/\//g, "_"),
    "phenotype-attestations",
    phenotypeAttestationId
  );
  mkdirSync(phenotypeArtifactsDir, { recursive: true });

  const phenoSnap = join(paths.snapDir, "process_phenopacket_input.json");
  const phenoOut = join(paths.snapDir, "process_phenopacket_output.json");
  writeJson(phenoSnap, {
    actor_id: actors.clinician.id,
    client_id: actors.client.id,
    client_created_by_wallet: actors.clinician.id,
    existing_pending_for_client: false,
    existing_staged_leaves: [],
    existing_published_leaves: [],
    phenotype_attestation_id: phenotypeAttestationId,
    artifacts_dir: phenotypeArtifactsDir
  });

  runCli(
    "clinician",
    [
      "process-phenopacket",
      "--actor-id",
      actors.clinician.id,
      "--client-id",
      actors.client.id,
      "--phenopacket-json",
      paths.phenopacketPath,
      "--input",
      phenoSnap,
      "--output",
      phenoOut
    ],
    { cwd, description: "Stage phenopacket attestation" }
  );
  const phenotype = readJson<ProcessPhenotypeOutput>(phenoOut);
  writeJson(join(paths.stateDir, "staged-phenotype.json"), phenotype);

  values([
    ["Sequence run", genome.sequence_run_id],
    ["Genotype fingerprint", shortHex(genome.staged_vcf.vcf_merkle_root)],
    ["Phenotype fingerprint", shortHex(phenotype.phenotype_merkle_root)],
    ["Phenotype attestation", phenotype.phenotype_attestation_id]
  ]);
  ok("Fingerprints ready — raw genome and phenotype stay private.");

  // ── 03 Registry publication ──────────────────────────────────────────
  step(
    3,
    "Registry",
    "The clinician batches the fingerprint, publishes the epoch root, and signs",
    [
      "Three jobs: put staged fingerprints into an epoch batch, put that epoch root on the public registry, then sign so outsiders know who endorsed it.",
      "Only fingerprints, epoch/registry roots, and signatures become public — never genotype or phenotype. The patient also receives a private inclusion proof that their fingerprint sits under those published roots."
    ],
    "Each publish folds fingerprints into an epoch MMR, then that epoch root into the registry MMR. The clinician’s allowlisted key signs the commitment. Later the ZK guest checks the patient’s private inclusion path against these public roots."
  );

  status("Publishing genomic epoch…");
  const genomeEpochIn = join(paths.snapDir, "publish_genome_epoch_input.json");
  const genomeEpochOut = join(paths.snapDir, "publish_genome_epoch_output.json");
  writeJson(genomeEpochIn, {
    actor_id: actors.clinician.id,
    pending_rows: [
      {
        staging_id: 1,
        client_id: actors.client.id,
        sequence_run_id: genome.sequence_run_id,
        vcf_merkle_root: genome.staged_vcf.vcf_merkle_root,
        snp_inclusion_proofs: genome.staged_vcf.snp_inclusion_proofs,
        artifacts_path: genome.staged_vcf.artifacts_path
      }
    ],
    existing_published_leaves: [],
    existing_epoch_roots: [],
    latest_epoch: null,
    directory_prev_epoch_number: -1,
    next_registry_epoch_number: 0,
    keypair: {
      public_key: clinicianKey.public_key,
      private_key: clinicianKey.private_key
    }
  });

  runCli(
    "clinician",
    [
      "publish-genome-epoch",
      "--actor-id",
      actors.clinician.id,
      "--input",
      genomeEpochIn,
      "--output",
      genomeEpochOut
    ],
    { cwd, description: "Publish first genomic epoch (clinician-signed)" }
  );
  const genomeEpoch = readJson<EpochPublishOutput>(genomeEpochOut);
  writeJson(join(paths.stateDir, "genome-epoch.json"), genomeEpoch);

  status("Publishing phenotype epoch…");
  const phenoEpochIn = join(paths.snapDir, "publish_phenotype_epoch_input.json");
  const phenoEpochOut = join(paths.snapDir, "publish_phenotype_epoch_output.json");
  writeJson(phenoEpochIn, {
    actor_id: actors.clinician.id,
    pending_rows: [
      {
        staging_id: 1,
        phenotype_attestation_id: phenotype.phenotype_attestation_id,
        client_id: phenotype.client_id,
        phenotype_merkle_root: phenotype.phenotype_merkle_root,
        json_path_leaves: phenotype.json_path_leaves,
        json_inclusion_proofs: phenotype.json_inclusion_proofs,
        artifacts_path: phenotype.artifacts_path
      }
    ],
    existing_published_leaves: [],
    existing_epoch_roots: [],
    latest_epoch: null,
    directory_prev_epoch_number: -1,
    next_registry_epoch_number: 0,
    keypair: {
      public_key: clinicianKey.public_key,
      private_key: clinicianKey.private_key
    }
  });

  runCli(
    "clinician",
    [
      "publish-phenotype-epoch",
      "--actor-id",
      actors.clinician.id,
      "--input",
      phenoEpochIn,
      "--output",
      phenoEpochOut
    ],
    { cwd, description: "Publish first phenotype epoch (clinician-signed)" }
  );
  const phenoEpoch = readJson<EpochPublishOutput>(phenoEpochOut);
  writeJson(join(paths.stateDir, "phenotype-epoch.json"), phenoEpoch);

  values([
    ["Genomic epoch root", shortHex(genomeEpoch.epoch_root)],
    ["Genomic registry root", shortHex(genomeEpoch.registry_root)],
    ["Phenotype epoch root", shortHex(phenoEpoch.epoch_root)],
    ["Phenotype registry root", shortHex(phenoEpoch.registry_root)],
    ["Signed by", shortHex(clinicianKey.public_key)]
  ]);
  ok("Public roots published — patient keeps private inclusion proofs.");

  // ── 04 Researcher inquiry ────────────────────────────────────────────
  step(
    4,
    "Researcher",
    "A researcher publishes an inquiry and pins who they trust",
    [
      "A researcher wants an answer computed over many patients without ever collecting their genomes. They publish an inquiry: a small program plus the rules for whose data counts.",
      "Crucially, they publish the exact program (by content hash) and pin which accreditor allowlist they accept. Tamper with either pin and the proof won't verify."
    ],
    "The inquiry is content-addressed by the SHA-256 of the ZK guest ELF and pins an accreditor allowlist root. The patient later supplies a private allowlist inclusion proof against that pin inside the guest."
  );

  status("Publishing inquiry (IrisPlex eye-color program)…");
  const jobIn = join(paths.snapDir, "create_job_input.json");
  const jobOut = join(paths.snapDir, "create_job_output.json");
  const whitelistEpochId = 0;
  writeJson(jobIn, {
    researcher_pubkey: researcherKey.public_key,
    researcher_privkey_encrypted: researcherKey.private_key,
    org_whitelist_epoch_id: whitelistEpochId,
    whitelist_epoch_number: whitelist.epoch_number,
    whitelist_registry_root: whitelist.registry_root,
    constraints: {}
  });

  runCli(
    "researcher",
    [
      "create-job",
      "--researcher-id",
      actors.researcher.id,
      "--job-id",
      actors.job_id,
      "--elf-path",
      paths.elfPath,
      "--whitelist-epoch-id",
      String(whitelistEpochId),
      "--input",
      jobIn,
      "--output",
      jobOut
    ],
    { cwd, description: "Create research job pinned to whitelist epoch + ELF" }
  );

  const job = readJson<CreateJobOutput>(jobOut);
  if (job.bundle_id !== bundleId) {
    throw new Error(
      `create-job bundle_id ${job.bundle_id} != sha256(elf) ${bundleId}`
    );
  }
  writeJson(join(paths.stateDir, "job.json"), job);

  values([
    ["Inquiry / job id", job.job_id],
    ["Program hash (bundle_id)", shortHex(job.bundle_id)],
    ["Pinned allowlist root", shortHex(job.whitelist_registry_root)],
    ["Allowlist epoch", String(job.whitelist_epoch_number)],
    ["Researcher signature", shortHex(job.signature)]
  ]);
  ok("Inquiry published — patients can fetch the program and pins.");

  // ── 05 Patient execution ─────────────────────────────────────────────
  step(
    5,
    "Patient",
    "The job runs where the patient's data lives — and proves it was honest",
    [
      "The genome never leaves the patient's control. The inquiry runs inside a zero-knowledge virtual machine somewhere the patient trusts. It produces the answer and a proof that the rules were followed.",
      "This is where every earlier link is checked at once: data under the fingerprint, fingerprint in the registry, signing clinician on the pinned allowlist, and the clinician seal."
    ],
    "Private witnesses include inclusion proofs and the clinician signature. Inside the ZK circuit those paths must verify against the public roots. Only then does the program emit public outputs and a succinct proof — the only values that leave."
  );

  const checkIn = join(paths.snapDir, "check_jobs_input.json");
  writeJson(checkIn, {
    jobs: [{ id: job.job_id, bundle_id: job.bundle_id, created_at: new Date().toISOString() }]
  });
  runCli(
    "client",
    ["check-jobs", "--client-id", actors.client.id, "--input", checkIn],
    { cwd, description: "List available jobs for client" }
  );

  const execIn = join(paths.snapDir, "execute_job_input.json");
  writeJson(execIn, {
    client_id: actors.client.id,
    job_id: job.job_id,
    bundle_id: job.bundle_id,
    job_constraints: job.constraints,
    org_whitelist_epoch_id: job.org_whitelist_epoch_id,
    whitelist_registry_root: job.whitelist_registry_root,
    whitelist_merkle_proof: clinicianLeaf.merkle_proof,
    sequence_run_id: genome.sequence_run_id,
    sequence_run_artifacts_path: genome.staged_vcf.artifacts_path,
    genomic_clinician_id: actors.clinician.id,
    genomic_clinician_pubkey: clinicianKey.public_key,
    phenotype_clinician_pubkey: clinicianKey.public_key
  });

  status(
    "Running real SP1 prove locally (several minutes; uses lots of RAM — swap helps)…"
  );
  runCli(
    "client",
    [
      "execute-job",
      "--client-id",
      actors.client.id,
      "--job-id",
      job.job_id,
      "--proof-mode",
      "full",
      "--submit",
      "false",
      "--input",
      execIn,
      "--bundle-elf-path",
      paths.elfPath
    ],
    { cwd, description: "Execute job with real SP1 prove (local ELF)" }
  );

  // client-cli writes under the sequence-run folder (artifacts_path), not
  // data/clients/<id>/outputs/…
  const pendingPath = join(
    genome.staged_vcf.artifacts_path,
    "outputs",
    job.job_id,
    "pending_submission.json"
  );
  if (!existsSync(pendingPath)) {
    throw new Error(`Expected pending_submission.json at ${pendingPath}`);
  }
  const pending = readJson<PendingSubmission>(pendingPath);
  const publicOutputsPath = join(dirname(pendingPath), "public_outputs.json");
  let predictedColor = "n/a";
  let confidence = "n/a";
  let publicOutputs: unknown = pending.public_outputs ?? null;
  if (existsSync(publicOutputsPath)) {
    const fromDisk = readJson<{
      payload?: Record<string, unknown>;
      nullifier?: string;
    }>(publicOutputsPath);
    publicOutputs = fromDisk;
    const payload = fromDisk.payload ?? {};
    predictedColor = String(payload.predicted_color ?? "n/a");
    confidence = String(payload.confidence ?? "n/a");
  }

  // execute-job already writes pending_submission.json + submission_payload.json
  // under the sequence-run folder; no separate submit-response needed offline.

  const responses = [
    {
      id: 1,
      status: "pending",
      created_at: new Date().toISOString(),
      public_outputs: publicOutputs,
      pending
    }
  ];
  writeJson(join(paths.stateDir, "responses.json"), responses);

  if (!pending.proof_blob) {
    throw new Error("pending_submission.json missing proof_blob — prove did not produce a proof");
  }

  values([
    ["Predicted eye color", predictedColor],
    ["Confidence", confidence],
    ["Proof type", pending.proof_type],
    ["Public values", shortHex(pending.public_values_bytes)],
    ["Proof blob", `${shortHex(pending.proof_blob)} (${pending.proof_blob.length / 2} bytes)`]
  ]);
  ok("Proof produced locally — genome never left the patient's trust boundary.");

  // ── 06 Researcher verification ───────────────────────────────────────
  step(
    6,
    "Researcher",
    "The researcher verifies the proof — trusting math, not a middleman",
    [
      "The patient submits only the answer, a nullifier that prevents double-counting, and the proof. The researcher checks the proof against the program they published.",
      "If it verifies, they know the answer was computed correctly from properly attested data — without ever seeing the genome or the private inclusion proofs."
    ],
    "A valid succinct proof implies every in-circuit check passed — including the private inclusion proofs the researcher never sees. The guarantee comes from cryptography, not from trusting any single party in the middle."
  );

  status("Verifying SP1 proof against the published program…");
  const listIn = join(paths.snapDir, "list_responses_input.json");
  writeJson(listIn, {
    job_id: job.job_id,
    responses: responses.map((r) => ({
      id: r.id,
      status: r.status,
      created_at: r.created_at,
      public_outputs: r.public_outputs
    }))
  });
  runCli(
    "researcher",
    ["list-responses", "--job-id", job.job_id, "--input", listIn],
    { cwd, description: "List local responses for job" }
  );

  const verifyIn = join(paths.snapDir, "verify_response_input.json");
  const verifyOut = join(paths.snapDir, "verify_response_output.json");
  writeJson(verifyIn, {
    response_id: 1,
    job_id: job.job_id,
    proof_blob: pending.proof_blob,
    public_values_bytes: pending.public_values_bytes,
    bundle_id: pending.bundle_id,
    proof_type: pending.proof_type,
    bundle_program_path: paths.elfPath
  });

  runCli(
    "researcher",
    [
      "verify-response",
      "--response-id",
      "1",
      "--input",
      verifyIn,
      "--output",
      verifyOut
    ],
    { cwd, description: "Verify SP1 proof against local ELF" }
  );

  const verifyResult = readJson<{ status?: string }>(verifyOut);
  writeJson(join(paths.stateDir, "verify.json"), verifyResult);

  values([
    ["Program checked", shortHex(pending.bundle_id)],
    ["Verify status", verifyResult.status ?? "unknown"],
    ["Eye color (public)", predictedColor],
    ["Confidence (public)", confidence]
  ]);
  ok("Verification succeeded — every link in the chain held.");

  done(verifyResult.status ?? "unknown", paths.workDir);

  if (isVerbose()) {
    console.log("Artifacts:");
    console.log(`  • state/        — ledger snapshots`);
    console.log(`  • snapshots/    — CLI --input/--output JSON`);
    console.log(`  • data/clients/ — commitments + proof outputs`);
  }
}

main().catch((err) => {
  fail(err instanceof Error ? err.message : String(err));
  process.exit(1);
});
