import { existsSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const POC_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

export type PocPaths = {
  pocRoot: string;
  workDir: string;
  stateDir: string;
  snapDir: string;
  keysPath: string;
  vcfPath: string;
  phenopacketPath: string;
  elfPath: string;
};

function requireFile(path: string, label: string): string {
  if (!existsSync(path)) {
    throw new Error(`${label} not found at ${path}`);
  }
  return path;
}

/**
 * Resolve the zk-irisplex guest ELF. Requires an explicit `POC_ELF_PATH`
 * (set via env or `./run.sh --elf PATH`). No auto-detect / fixture fallback.
 */
export function resolveGuestElfPath(): string {
  const fromEnv = process.env.POC_ELF_PATH?.trim();
  if (!fromEnv) {
    throw new Error(
      `Guest ELF path required (POC_ELF_PATH / --elf).\n` +
        `Build the guest then pass the artifact, e.g.:\n` +
        `  cargo build --release -p zk-irisplex\n` +
        `  ./apps/poc/run.sh --elf target/cargo/elf-compilation/riscv64im-succinct-zkvm-elf/release/zk-irisplex-program`
    );
  }
  // Relative paths are vs the caller's cwd (POC_WORK_DIR), not process.cwd()
  // — run.sh cds to the repo root before starting Node.
  const base = process.env.POC_WORK_DIR?.trim() || process.cwd();
  const resolved = resolve(base, fromEnv);
  if (!existsSync(resolved)) {
    throw new Error(`POC_ELF_PATH does not exist: ${resolved}`);
  }
  return resolved;
}

export function resolvePocPaths(): PocPaths {
  // Prefer POC_WORK_DIR from run.sh (caller's cwd). Fallback: process.cwd().
  const fromEnv = process.env.POC_WORK_DIR?.trim();
  const workDir = resolve(fromEnv && fromEnv.length > 0 ? fromEnv : process.cwd());
  const stateDir = join(workDir, "state");
  const snapDir = join(workDir, "snapshots");
  mkdirSync(stateDir, { recursive: true });
  mkdirSync(snapDir, { recursive: true });
  mkdirSync(join(workDir, "data"), { recursive: true });

  const keysPath = resolve(
    process.env.POC_KEYS_PATH?.trim() || join(POC_ROOT, "fixtures/keys/actors.json")
  );
  const vcfPath = resolve(
    process.env.POC_VCF_PATH?.trim() ||
      join(POC_ROOT, "fixtures/genomes/ERR3239292_NA11894_irisplex.vcf")
  );
  const phenopacketPath = resolve(
    process.env.POC_PHENOPACKET_PATH?.trim() ||
      join(POC_ROOT, "fixtures/phenopackets/demo.json")
  );

  return {
    pocRoot: POC_ROOT,
    workDir,
    stateDir,
    snapDir,
    keysPath: requireFile(keysPath, "Actors keys file"),
    vcfPath: requireFile(vcfPath, "Genome VCF fixture"),
    phenopacketPath: requireFile(phenopacketPath, "Phenopacket fixture"),
    elfPath: resolveGuestElfPath()
  };
}

export { POC_ROOT };
