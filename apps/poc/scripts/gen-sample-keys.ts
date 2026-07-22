#!/usr/bin/env tsx
/**
 * Generate deterministic sample actors.json for zeenome-poc.
 * Seeds are fixed so the committed fixture is stable across regenerations.
 */
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { keyPairFromSeed } from "zeenome-poc-signing";

const here = dirname(fileURLToPath(import.meta.url));
const outPath = join(here, "../fixtures/keys/actors.json");

function seed(byte: number): Uint8Array {
  const out = new Uint8Array(32);
  out.fill(byte);
  return out;
}

async function main(): Promise<void> {
  const clinician = await keyPairFromSeed(seed(0x01));
  const researcher = await keyPairFromSeed(seed(0x02));
  const accreditor = await keyPairFromSeed(seed(0x03));

  const actors = {
    version: 2,
    clinician: {
      id: "poc-clinician",
      display_name: "POC Clinician",
      public_key: clinician.public_key,
      private_key: clinician.private_key
    },
    researcher: {
      id: "poc-researcher",
      display_name: "POC Researcher",
      public_key: researcher.public_key,
      private_key: researcher.private_key
    },
    accreditor: {
      id: "poc-accreditor",
      display_name: "POC Accreditor",
      public_key: accreditor.public_key,
      private_key: accreditor.private_key
    },
    client: {
      id: "cli-poc-001"
    },
    catalog_sample_id: "ERR3239292/NA11894",
    job_id: "poc-job-001",
    whitelist_id: "poc-wl-bootstrap"
  };

  mkdirSync(dirname(outPath), { recursive: true });
  writeFileSync(outPath, `${JSON.stringify(actors, null, 2)}\n`);
  console.log(`Wrote ${outPath}`);
  console.log(`  clinician.public_key  = ${clinician.public_key}`);
  console.log(`  researcher.public_key = ${researcher.public_key}`);
  console.log(`  accreditor.public_key = ${accreditor.public_key}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
