/**
 * Token minting and verification for Agent-Safe capability tokens.
 * Uses Ed25519 for signing via node:crypto (zero deps).
 */

import { createPrivateKey, createPublicKey, sign, generateKeyPairSync } from 'node:crypto';
import { parseSExpr, evalPolicy } from './spl.js';
import { verifyEd25519 } from './crypto.js';

export interface Token {
  version: string;
  policy: string;
  merkle_root?: string;
  hash_chain_commitment?: string;
  sealed: boolean;
  expires?: string;
  public_key: string;
  signature: string;
}

export interface MintOptions {
  merkleRoot?: string;
  hashChainCommitment?: string;
  sealed?: boolean;
  expires?: string;
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
 * Mint a signed capability token.
 * @param policy - SPL policy source string
 * @param privateKeyHex - Hex-encoded Ed25519 private key (32 bytes seed)
 * @param options - Optional token metadata
 * @returns Signed token object
 */
export function mint(policy: string, privateKeyHex: string, options: MintOptions = {}): Token {
  const policyBytes = Buffer.from(policy.trim(), 'utf8');

  // Reconstruct DER-encoded PKCS8 private key
  const privSeed = Buffer.from(privateKeyHex, 'hex');
  const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privDer = Buffer.concat([pkcs8Prefix, privSeed]);

  const keyObj = createPrivateKey({ key: privDer, format: 'der', type: 'pkcs8' });
  const signature = sign(null, policyBytes, keyObj);

  // Derive public key
  const pubKey = createPublicKey(keyObj);
  const pubDer = pubKey.export({ type: 'spki', format: 'der' });
  const pubRaw = pubDer.subarray(12);

  return {
    version: '0.1.0',
    policy: policy.trim(),
    merkle_root: options.merkleRoot,
    hash_chain_commitment: options.hashChainCommitment,
    sealed: options.sealed ?? false,
    expires: options.expires,
    public_key: Buffer.from(pubRaw).toString('hex'),
    signature: Buffer.from(signature).toString('hex'),
  };
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

  // Verify signature
  const policyBytes = Buffer.from(t.policy, 'utf8');
  if (!verifyEd25519(policyBytes, t.signature, t.public_key)) {
    return { allow: false, sealed: t.sealed, error: 'invalid signature' };
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
      dpop_ok: options.crypto?.dpop_ok ?? (() => true),
      merkle_ok: options.crypto?.merkle_ok ?? (() => true),
      vrf_ok: options.crypto?.vrf_ok ?? (() => true),
      thresh_ok: options.crypto?.thresh_ok ?? (() => true),
    },
  };
  const allow = !!evalPolicy(ast, ctx);

  return { allow, sealed: t.sealed };
}
