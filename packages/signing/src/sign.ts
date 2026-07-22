import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "./hex";
import type { KeyPair } from "./types";

ed.etc.sha512Sync = (...messages: Uint8Array[]) => sha512(ed.etc.concatBytes(...messages));

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function signingSeedFromKeyPair(keypair: KeyPair): Promise<Uint8Array> {
  const raw = base64ToBytes(keypair.private_key);
  if (raw.length === 64) return raw.slice(0, 32);
  if (raw.length === 32) return raw;
  throw new Error(`Invalid private_key length: ${raw.length}`);
}

/** Matches `zeenome_core::crypto::sign_message` (hex-encoded 64-byte signature). */
export async function signMessage(message: Uint8Array, keypair: KeyPair): Promise<string> {
  const seed = await signingSeedFromKeyPair(keypair);
  const sig = await ed.sign(message, seed);
  return bytesToHex(sig);
}
