/**
 * Token minting and verification for Agent-Safe capability tokens.
 * Uses Ed25519 for signing via node:crypto (zero deps).
 */

import { createPrivateKey, createPublicKey, sign, generateKeyPairSync, createHash } from 'node:crypto';
import { parseSExpr, evalPolicy } from './spl.js';
import { verifyEd25519, sha256 } from './crypto.js';

export interface Token {
  version: string;
  policy: string;
  merkle_root?: string;
  hash_chain_commitment?: string;
  sealed: boolean;
  expires?: string;
  public_key: string;
  signature: string;
  pop_key?: string;
}

export interface MintOptions {
  merkleRoot?: string;
  hashChainCommitment?: string;
  sealed?: boolean;
  expires?: string;
  popKey?: string;
}

export interface VerifyTokenOptions {
  vars?: Record<string, any>;
  per_day_count?: (action: string, day: string) => number;
  crypto?: {
    dpop_ok?: () => boolean;
    merkle_ok?: (tuple: any[]) => boolean;
    vrf_ok?: (day: string, amount: number) => boolean;
    thresh_ok?: () => boolean;
  };
  now?: string;
  presentationSignature?: string;
}

/**
 * Generate an Ed25519 keypair.
 * @returns { publicKey: hex, privateKey: hex }
 */
export function generateKeypair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const pubRaw = publicKey.export({ type: 'spki', format: 'der' }).subarray(12); // strip DER prefix
  const privRaw = privateKey.export({ type: 'pkcs8', format: 'der' }).subarray(16); // strip DER prefix
  return {
    publicKey: Buffer.from(pubRaw).toString('hex'),
    privateKey: Buffer.from(privRaw).toString('hex'),
  };
}

/**
 * Build the canonical signing payload for a token.
 * Covers all security-relevant fields so sealed, expires, merkle_root, and
 * hash_chain_commitment cannot be tampered with after signing.
 */
export function signingPayload(
  policy: string,
  merkleRoot?: string,
  hashChainCommitment?: string,
  sealed?: boolean,
  expires?: string,
): Buffer {
  const parts = [
    policy.trim(),
    merkleRoot ?? '',
    hashChainCommitment ?? '',
    sealed ? '1' : '0',
    expires ?? '',
  ];
  return Buffer.from(parts.join('\0'), 'utf8');
}

/**
 * Create a PoP presentation signature for a token.
 * The agent signs SHA-256(signing_payload) with its own Ed25519 key.
 * @param token - Token to present
 * @param agentPrivateKeyHex - Agent's Ed25519 private key (32 bytes seed, hex)
 * @returns Hex-encoded presentation signature
 */
export function createPresentationSignature(token: Token, agentPrivateKeyHex: string): string {
  const payload = signingPayload(
    token.policy, token.merkle_root, token.hash_chain_commitment, token.sealed, token.expires,
  );
  const popPayload = sha256(payload);

  const privSeed = Buffer.from(agentPrivateKeyHex, 'hex');
  const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privDer = Buffer.concat([pkcs8Prefix, privSeed]);
  const keyObj = createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });

  const sig = sign(null, Buffer.from(popPayload), keyObj);
  return Buffer.from(sig).toString('hex');
}

/**
 * Mint a signed capability token.
 * @param policy - SPL policy source string
 * @param privateKeyHex - Hex-encoded Ed25519 private key (32 bytes seed)
 * @param options - Optional token metadata
 * @returns Signed token object
 */
export function mint(policy: string, privateKeyHex: string, options: MintOptions = {}): Token {
  const sealedVal = options.sealed ?? false;
  const payload = signingPayload(
    policy, options.merkleRoot, options.hashChainCommitment, sealedVal, options.expires,
  );

  // Reconstruct DER-encoded PKCS8 private key
  const privSeed = Buffer.from(privateKeyHex, 'hex');
  const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privDer = Buffer.concat([pkcs8Prefix, privSeed]);

  const keyObj = createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
  const signature = sign(null, payload, keyObj);

  // Derive public key
  const pubKey = createPublicKey(keyObj);
  const pubDer = pubKey.export({ type: 'spki', format: 'der' });
  const pubRaw = pubDer.subarray(12);

  const token: Token = {
    version: '0.1.0',
    policy: policy.trim(),
    merkle_root: options.merkleRoot,
    hash_chain_commitment: options.hashChainCommitment,
    sealed: sealedVal,
    expires: options.expires,
    public_key: Buffer.from(pubRaw).toString('hex'),
    signature: Buffer.from(signature).toString('hex'),
  };
  if (options.popKey) token.pop_key = options.popKey;
  return token;
}

/**
 * Verify a token and evaluate its policy against a request.
 * @param token - Token object or JSON string
 * @param req - Request object
 * @param options - Verification options (vars, crypto callbacks, etc.)
 * @returns { allow: boolean, token: Token }
 */
export function verifyToken(
  token: Token | string,
  req: Record<string, any>,
  options: VerifyTokenOptions = {},
): { allow: boolean; sealed: boolean; error?: string } {
  const t: Token = typeof token === 'string' ? JSON.parse(token) : token;

  // Check expiration
  if (t.expires && new Date(t.expires) < new Date(options.now ?? new Date().toISOString())) {
    return { allow: false, sealed: t.sealed, error: 'token expired' };
  }

  // Verify signature over full token envelope
  const payload = signingPayload(
    t.policy, t.merkle_root, t.hash_chain_commitment, t.sealed, t.expires,
  );
  if (!verifyEd25519(payload, t.signature, t.public_key)) {
    return { allow: false, sealed: t.sealed, error: 'invalid signature' };
  }

  // PoP binding: if token has pop_key, require and verify presentation signature
  if (t.pop_key) {
    if (!options.presentationSignature) {
      return { allow: false, sealed: t.sealed, error: 'PoP binding requires presentation signature' };
    }
    const popPayload = sha256(payload);
    if (!verifyEd25519(popPayload, options.presentationSignature, t.pop_key)) {
      return { allow: false, sealed: t.sealed, error: 'invalid presentation signature' };
    }
  }

  // If sealed, token is valid but cannot be attenuated — evaluate normally
  // (Sealing prevents attenuation, not verification)

  // Parse and evaluate
  const ast = parseSExpr(t.policy);
  const ctx = {
    req,
    vars: options.vars ?? {},
    now: options.now ?? new Date().toISOString(),
    per_day_count: options.per_day_count ?? (() => 0),
    crypto: {
      dpop_ok: options.crypto?.dpop_ok ?? (() => false),
      merkle_ok: options.crypto?.merkle_ok ?? (() => false),
      vrf_ok: options.crypto?.vrf_ok ?? (() => false),
      thresh_ok: options.crypto?.thresh_ok ?? (() => false),
    },
  };
  const allow = !!evalPolicy(ast, ctx);

  return { allow, sealed: t.sealed };
}
