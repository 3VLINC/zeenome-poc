import * as ed from "@noble/ed25519";
import { bytesToHex } from "./hex";
import type { KeyPair } from "./types";

function bytesToBase64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes));
}

/** Build `KeyPair` from a 32-byte Ed25519 seed (matches Rust `SigningKey::from_bytes`). */
export async function keyPairFromSeed(seed32: Uint8Array): Promise<KeyPair> {
  if (seed32.length !== 32) {
    throw new Error(`Ed25519 seed must be 32 bytes, got ${seed32.length}`);
  }
  const publicKeyBytes = await ed.getPublicKeyAsync(seed32);
  const keypairBytes = new Uint8Array(64);
  keypairBytes.set(seed32, 0);
  keypairBytes.set(publicKeyBytes, 32);
  return {
    public_key: bytesToHex(publicKeyBytes),
    private_key: bytesToBase64(keypairBytes)
  };
}

/** Random Ed25519 keypair (matches `KeyPair::generate()` in Rust). */
export async function generateKeyPair(): Promise<KeyPair> {
  const seed = crypto.getRandomValues(new Uint8Array(32));
  return keyPairFromSeed(seed);
}
