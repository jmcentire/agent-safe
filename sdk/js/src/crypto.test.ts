import { describe, it } from 'node:test';
import * as assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { verifyEd25519, verifyMerkleProof, verifyHashChain, sha256 } from './crypto.js';

function toHex(buf: Uint8Array): string {
  return Buffer.from(buf).toString('hex');
}

const vectorsDir = resolve(import.meta.dirname!, '../../../examples/crypto');

function loadVectors(name: string) {
  return JSON.parse(readFileSync(resolve(vectorsDir, name), 'utf8'));
}

describe('Ed25519 crypto', () => {
  const v = loadVectors('ed25519_vectors.json');

  it('verifies valid signature', () => {
    assert.equal(
      verifyEd25519(v.message, v.signature_hex, v.public_key_hex),
      true,
    );
  });

  it('rejects tampered message', () => {
    assert.equal(
      verifyEd25519(v.tampered_message, v.signature_hex, v.public_key_hex),
      false,
    );
  });
});

describe('Merkle proof', () => {
  const v = loadVectors('merkle_vectors.json');

  for (const tc of v.cases) {
    it(tc.name, () => {
      const leafHash = toHex(sha256(tc.leaf));
      assert.equal(leafHash, tc.leaf_hash);
      assert.equal(
        verifyMerkleProof(tc.leaf, tc.proof, v.root),
        tc.expected,
      );
    });
  }
});

describe('Hash chain', () => {
  const v = loadVectors('hashchain_vectors.json');

  for (const tc of v.cases) {
    it(tc.name, () => {
      assert.equal(
        verifyHashChain(v.commitment, tc.preimage, tc.index, v.chain_length),
        tc.expected,
      );
    });
  }
});
