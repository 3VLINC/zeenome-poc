import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { isVerbose } from "./story.js";

export type CliName = "clinician" | "accreditor" | "researcher" | "client";

const DEFAULT_BIN: Record<CliName, string> = {
  clinician: "clinician",
  accreditor: "accreditor",
  researcher: "researcher",
  client: "client"
};

function resolveBinary(name: CliName): string {
  const envKey = `POC_${name.toUpperCase()}_BIN`;
  const fromEnv = process.env[envKey]?.trim();
  if (fromEnv) return fromEnv;
  return DEFAULT_BIN[name];
}

export function runCli(
  name: CliName,
  args: string[],
  opts: { cwd: string; description: string; repoRoot?: string }
): { stdout: string; stderr: string } {
  const bin = resolveBinary(name);
  const repoRoot =
    opts.repoRoot?.trim() ||
    process.env.POC_REPO_ROOT?.trim() ||
    process.cwd();
  const verbose = isVerbose();

  // Prefer PATH / explicit binaries. Fall back to cargo run when the bare name
  // is not on PATH (source checkout). Manifest path is absolute so cargo can
  // run with cwd=workDir (where data/clients artifacts should land).
  const useCargo =
    process.env.POC_USE_CARGO === "1" ||
    (!bin.includes("/") && !existsSync(bin) && !commandOnPath(bin));

  let result: ReturnType<typeof spawnSync>;
  let commandLabel: string;
  if (useCargo) {
    const manifest = join(repoRoot, `apps/${name}-cli/Cargo.toml`);
    const cargoArgs = [
      "run",
      "--release",
      "--manifest-path",
      manifest,
      "--",
      ...args
    ];
    commandLabel = `cargo ${cargoArgs.join(" ")}`;
    if (verbose) {
      console.log(`\n▸ ${opts.description}`);
      console.log(`  $ ${commandLabel}`);
      console.log(`    (cwd ${opts.cwd})`);
    }
    result = spawnSync("cargo", cargoArgs, {
      cwd: opts.cwd,
      encoding: "utf8",
      env: process.env
    });
  } else {
    commandLabel = `${bin} ${args.join(" ")}`;
    if (verbose) {
      console.log(`\n▸ ${opts.description}`);
      console.log(`  $ ${commandLabel}`);
    }
    result = spawnSync(bin, args, {
      cwd: opts.cwd,
      encoding: "utf8",
      env: process.env
    });
  }

  const stdout = result.stdout ?? "";
  const stderr = result.stderr ?? "";

  if (verbose) {
    if (stdout.trim()) {
      process.stdout.write(stdout.endsWith("\n") ? stdout : `${stdout}\n`);
    }
    if (stderr.trim()) {
      process.stderr.write(stderr.endsWith("\n") ? stderr : `${stderr}\n`);
    }
  }

  if (result.error) {
    throw new Error(`${opts.description} failed to spawn ${bin}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    if (!verbose) {
      console.error(`\n▸ ${opts.description} failed`);
      console.error(`  $ ${commandLabel}`);
      if (stdout.trim()) process.stderr.write(stdout.endsWith("\n") ? stdout : `${stdout}\n`);
      if (stderr.trim()) process.stderr.write(stderr.endsWith("\n") ? stderr : `${stderr}\n`);
    }
    const signal = result.signal ? ` signal ${result.signal}` : "";
    const exitLabel =
      result.status === null
        ? `killed${signal || " (no exit code)"}`
        : `exit ${result.status}${signal}`;
    const oomHint =
      result.status === null || result.signal === "SIGKILL"
        ? " Likely out-of-memory during SP1 prove — ensure swap is enabled (./run.sh ensures it when sudo is available)."
        : "";
    throw new Error(
      `${opts.description} failed (${exitLabel}).${oomHint}${
        verbose ? " See CLI output above." : " Re-run with --verbose for full logs."
      }`
    );
  }
  return { stdout, stderr };
}

function commandOnPath(name: string): boolean {
  const result = spawnSync("sh", ["-c", `command -v ${JSON.stringify(name)}`], {
    encoding: "utf8"
  });
  return result.status === 0 && Boolean(result.stdout?.trim());
}
