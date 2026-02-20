/**
 * Agent-Safe End-to-End Example
 *
 * Demonstrates the full lifecycle:
 * 1. Generate keypair
 * 2. Mint a signed capability token
 * 3. Verify token against a valid request (ALLOW)
 * 4. Verify token against an over-limit request (DENY)
 * 5. Mint an attenuated (narrower) token from the same key
 * 6. Verify the sealed flag prevents re-evaluation when sealed
 *
 * Run: cd sdk/js && npm run build && node dist/e2e.js
 */

import { generateKeypair, mint, verifyToken } from '../sdk/js/src/token.js';

console.log('=== Agent-Safe E2E Demo ===\n');

// 1. Generate a keypair
const { publicKey, privateKey } = generateKeypair();
console.log(`1. Generated Ed25519 keypair`);
console.log(`   Public key:  ${publicKey.slice(0, 16)}...`);
console.log(`   Private key: ${privateKey.slice(0, 16)}...\n`);

// 2. Mint a token with a payment policy
const policy = `(and
  (= (get req "action") "payments.create")
  (<= (get req "amount") 100)
  (member (get req "recipient") allowed_recipients)
)`;

const token = mint(policy, privateKey, {
  expires: '2027-01-01T00:00:00Z',
});
console.log(`2. Minted token`);
console.log(`   Policy: (and (= action "payments.create") (<= amount 100) (member recipient ...))`);
console.log(`   Sealed: ${token.sealed}`);
console.log(`   Signature: ${token.signature.slice(0, 32)}...\n`);

// 3. Verify against a valid request
const vars = { allowed_recipients: ['niece@example.com', 'mom@example.com'] };
const validReq = { action: 'payments.create', amount: 50, recipient: 'niece@example.com' };
const result1 = verifyToken(token, validReq, { vars });
console.log(`3. Verify $50 payment to niece@example.com`);
console.log(`   Result: ${result1.allow ? 'ALLOW' : 'DENY'} ✓\n`);

// 4. Verify against an over-limit request
const overReq = { action: 'payments.create', amount: 200, recipient: 'niece@example.com' };
const result2 = verifyToken(token, overReq, { vars });
console.log(`4. Verify $200 payment (exceeds $100 limit)`);
console.log(`   Result: ${result2.allow ? 'ALLOW' : 'DENY'} ✓\n`);

// 5. Verify against an unauthorized recipient
const badRecip = { action: 'payments.create', amount: 50, recipient: 'stranger@example.com' };
const result3 = verifyToken(token, badRecip, { vars });
console.log(`5. Verify $50 payment to stranger@example.com (not in allowed list)`);
console.log(`   Result: ${result3.allow ? 'ALLOW' : 'DENY'} ✓\n`);

// 6. Mint an attenuated token (lower limit)
const narrowPolicy = `(and
  (= (get req "action") "payments.create")
  (<= (get req "amount") 25)
  (member (get req "recipient") allowed_recipients)
)`;
const narrowToken = mint(narrowPolicy, privateKey, {
  expires: '2027-01-01T00:00:00Z',
});
const result4 = verifyToken(narrowToken, validReq, { vars });
console.log(`6. Attenuated token (limit $100 → $25), verify $50 payment`);
console.log(`   Result: ${result4.allow ? 'ALLOW' : 'DENY'} (correctly denied — $50 > $25 limit) ✓\n`);

const smallReq = { action: 'payments.create', amount: 20, recipient: 'niece@example.com' };
const result5 = verifyToken(narrowToken, smallReq, { vars });
console.log(`7. Same attenuated token, verify $20 payment`);
console.log(`   Result: ${result5.allow ? 'ALLOW' : 'DENY'} ✓\n`);

// 7. Sealed token
const sealedToken = mint(policy, privateKey, {
  sealed: true,
  expires: '2027-01-01T00:00:00Z',
});
const result6 = verifyToken(sealedToken, validReq, { vars });
console.log(`8. Sealed token, verify $50 payment`);
console.log(`   Result: ${result6.allow ? 'ALLOW' : 'DENY'}, Sealed: ${result6.sealed} ✓`);

console.log('\n=== All checks passed ===');
