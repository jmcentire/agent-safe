/**
 * Real crypto implementations for SPL token verification.
 * Uses only node:crypto (zero external deps).
 */

import { createHash, verify as cryptoVerify, hkdfSync, generateKeyPairSync, createPrivateKey, createPublicKey } from 'node:crypto';

function toHex(buf: Uint8Array): string {
  return Buffer.from(buf).toString('hex');
}

function concat(...bufs: Uint8Array[]): Uint8Array {
  return Buffer.concat(bufs);
}

/**
 * Verify an Ed25519 signature over a message.
 * @param message - The signed bytes (e.g. canonical SPL policy)
 * @param signatureHex - Hex-encoded Ed25519 signature (64 bytes)
 * @param publicKeyHex - Hex-encoded Ed25519 public key (32 bytes)
 * @returns true if signature is valid
 */
export function verifyEd25519(
  message: Uint8Array | string,
  signatureHex: string,
  publicKeyHex: string,
): boolean {
  try {
    const msgBuf = typeof message === 'string' ? Buffer.from(message, 'utf8') : Buffer.from(message);
    const sigBuf = Buffer.from(signatureHex, 'hex');
    const pubBuf = Buffer.from(publicKeyHex, 'hex');

    const keyObj = {
      key: Buffer.concat([
        // Ed25519 SPKI prefix (DER header for 32-byte public key)
        Buffer.from('302a300506032b6570032100', 'hex'),
        pubBuf,
      ]),
      format: 'der' as const,
      type: 'spki' as const,
    };

    return cryptoVerify(null, msgBuf, keyObj, sigBuf);
  } catch {
    return false;
  }
}

/**
 * SHA-256 hash of data.
 */
export function sha256(data: Uint8Array | string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

/**
 * Verify a Merkle proof against a root hash.
 * @param leafData - The leaf data (will be SHA-256 hashed)
 * @param proof - Array of {hash: hex, position: 'left'|'right'}
 * @param rootHex - Expected root hash in hex
 * @returns true if proof is valid
 */
export function verifyMerkleProof(
  leafData: string,
  proof: Array<{ hash: string; position: 'left' | 'right' }>,
  rootHex: string,
): boolean {
  try {
    let current = sha256(leafData);

    for (const step of proof) {
      const sibling = new Uint8Array(Buffer.from(step.hash, 'hex'));
      if (step.position === 'right') {
        current = sha256(concat(current, sibling));
      } else {
        current = sha256(concat(sibling, current));
      }
    }

    return toHex(current) === rootHex;
  } catch {
    return false;
  }
}

/**
 * Hash a tuple (array of values) by JSON-serializing then SHA-256.
 */
export function hashTuple(tuple: any[]): string {
  const serialized = JSON.stringify(tuple);
  return toHex(sha256(serialized));
}

/**
 * Derive a service-specific Ed25519 keypair using HKDF-SHA256.
 * Provides unlinkability: different services see different public keys.
 *
 * @param masterKeyHex - 32-byte master private key seed (hex)
 * @param serviceDomain - Service identifier (e.g. "api.example.com")
 * @returns { publicKey: hex, privateKey: hex }
 */
export function deriveServiceKey(
  masterKeyHex: string,
  serviceDomain: string,
): { publicKey: string; privateKey: string } {
  const masterKey = Buffer.from(masterKeyHex, 'hex');
  const salt = Buffer.from('agent-safe-v1', 'utf8');
  const info = Buffer.from(serviceDomain, 'utf8');

  const derived = hkdfSync('sha256', masterKey, salt, info, 32);
  const seed = Buffer.from(derived);

  // Build Ed25519 private key from derived seed
  const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privDer = Buffer.concat([pkcs8Prefix, seed]);
  const keyObj = createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
  const pubKey = createPublicKey(keyObj);
  const pubDer = pubKey.export({ type: 'spki', format: 'der' });
  const pubRaw = pubDer.subarray(12);

  return {
    publicKey: Buffer.from(pubRaw).toString('hex'),
    privateKey: seed.toString('hex'),
  };
}

/**
 * Verify a hash chain receipt.
 * Hashes preimage (chainLength - index) times and checks it equals commitment.
 */
export function verifyHashChain(
  commitment: string,
  preimageHex: string,
  index: number,
  chainLength: number,
): boolean {
  try {
    let current: Uint8Array = new Uint8Array(Buffer.from(preimageHex, 'hex'));
    const steps = chainLength - index;

    for (let i = 0; i < steps; i++) {
      current = sha256(current);
    }

    return toHex(current) === commitment;
  } catch {
    return false;
  }
}
