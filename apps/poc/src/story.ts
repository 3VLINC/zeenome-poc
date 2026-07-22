/**
 * Human-readable trust-chain narrative for the POC.
 * Inspired by https://zeenome.xyz/trust-chain
 */

export type StoryOpts = {
  verbose: boolean;
};

let verbose = false;

export function initStory(opts: StoryOpts): void {
  verbose = opts.verbose;
}

export function isVerbose(): boolean {
  return verbose;
}

/** Shorten a hex / hash for display: `abcdef012345…89ab`. */
export function shortHex(value: string, head = 12, tail = 4): string {
  const v = value.trim().replace(/^0x/i, "");
  if (v.length <= head + tail + 1) return v;
  return `${v.slice(0, head)}…${v.slice(-tail)}`;
}

export function rule(char = "─", width = 64): void {
  console.log(char.repeat(width));
}

export function blank(): void {
  console.log("");
}

export function intro(): void {
  blank();
  rule("═");
  console.log("  ZEENOME — trust chain (live)");
  rule("═");
  blank();
  console.log("  From accreditation to a proof a researcher can trust.");
  blank();
  console.log(
    "  A researcher never sees a patient's health information — yet they can"
  );
  console.log(
    "  trust that a result was computed from data a real, accredited clinician"
  );
  console.log(
    "  attested to. Each link's output becomes the next link's input."
  );
  blank();
  console.log("  Cast");
  kv("Accreditor", "Vouches for which clinicians are legitimate");
  kv("Clinician", "Collects data and signs attestations");
  kv("Registry", "Public, append-only record of attestations");
  kv("Researcher", "Publishes an inquiry and verifies the answer");
  kv("Patient", "Holds their own data and runs the job locally");
  blank();
  if (!verbose) {
    console.log("  (CLI chatter hidden — pass --verbose to see raw commands)");
    blank();
  }
}

export function step(
  index: number,
  actor: string,
  title: string,
  narrative: string[],
  cryptoInContext: string
): void {
  blank();
  rule();
  console.log(`  ${String(index).padStart(2, "0")}  ${actor}`);
  console.log(`  ${title}`);
  rule();
  blank();
  for (const paragraph of narrative) {
    wrap(paragraph, 2);
    blank();
  }
  console.log("  The cryptography");
  wrap(cryptoInContext, 4);
  blank();
}

export function values(rows: Array<[string, string]>): void {
  console.log("  Values");
  for (const [label, value] of rows) {
    kv(label, value, 4);
  }
  blank();
}

export function status(message: string): void {
  console.log(`  … ${message}`);
}

export function ok(message: string): void {
  console.log(`  ✓ ${message}`);
  blank();
}

export function done(statusLabel: string, workDir: string): void {
  blank();
  rule("═");
  console.log("  Trust chain complete");
  rule("═");
  blank();
  values([
    ["Verification", statusLabel],
    ["Artifacts", workDir]
  ]);
  console.log("  Every link held: allowlist → attestation → registry →");
  console.log("  inquiry pins → local ZK proof → researcher verification.");
  blank();
}

export function fail(message: string): void {
  blank();
  console.error(`  ✗ ${message}`);
  blank();
}

function kv(label: string, value: string, indent = 4): void {
  const pad = " ".repeat(indent);
  const labelWidth = 22;
  const padded = label.padEnd(labelWidth);
  console.log(`${pad}${padded}${value}`);
}

function wrap(text: string, indent: number, width = 72): void {
  const pad = " ".repeat(indent);
  const max = Math.max(24, width - indent);
  const words = text.split(/\s+/);
  let line = "";
  for (const word of words) {
    if (!line) {
      line = word;
      continue;
    }
    if (`${line} ${word}`.length > max) {
      console.log(`${pad}${line}`);
      line = word;
    } else {
      line = `${line} ${word}`;
    }
  }
  if (line) console.log(`${pad}${line}`);
}
