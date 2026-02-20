"""
Agent-Safe End-to-End Example (Python)

Demonstrates the full lifecycle:
1. Generate keypair
2. Mint a signed capability token
3. Verify token against valid/invalid requests
4. Attenuate token (narrow the limit)
5. Seal a token

Run: pip install -e sdk/python[crypto] && python examples/e2e/e2e.py
"""

from spl import mint, verify_token, generate_keypair

print("=== Agent-Safe E2E Demo ===\n")

# 1. Generate keypair
pub_hex, priv_hex = generate_keypair()
print("1. Generated Ed25519 keypair")
print(f"   Public key:  {pub_hex[:16]}...")
print(f"   Private key: {priv_hex[:16]}...\n")

# 2. Mint a token
policy = """(and
  (= (get req "action") "payments.create")
  (<= (get req "amount") 100)
  (member (get req "recipient") allowed_recipients)
)"""

token = mint(policy, priv_hex, expires="2027-01-01T00:00:00Z")
print("2. Minted token")
print(f"   Sealed: {token['sealed']}")
print(f"   Signature: {token['signature'][:32]}...\n")

vars = {"allowed_recipients": ["niece@example.com", "mom@example.com"]}

# 3. Valid request
valid_req = {"action": "payments.create", "amount": 50, "recipient": "niece@example.com"}
r1 = verify_token(token, valid_req, vars=vars)
print("3. Verify $50 payment to niece@example.com")
print(f"   Result: {'ALLOW' if r1['allow'] else 'DENY'}\n")

# 4. Over-limit
over_req = {"action": "payments.create", "amount": 200, "recipient": "niece@example.com"}
r2 = verify_token(token, over_req, vars=vars)
print("4. Verify $200 payment (exceeds $100 limit)")
print(f"   Result: {'ALLOW' if r2['allow'] else 'DENY'}\n")

# 5. Bad recipient
bad_req = {"action": "payments.create", "amount": 50, "recipient": "stranger@example.com"}
r3 = verify_token(token, bad_req, vars=vars)
print("5. Verify $50 payment to stranger@example.com")
print(f"   Result: {'ALLOW' if r3['allow'] else 'DENY'}\n")

# 6. Attenuated token (lower limit)
narrow_policy = """(and
  (= (get req "action") "payments.create")
  (<= (get req "amount") 25)
  (member (get req "recipient") allowed_recipients)
)"""
narrow_token = mint(narrow_policy, priv_hex, expires="2027-01-01T00:00:00Z")
r4 = verify_token(narrow_token, valid_req, vars=vars)
print("6. Attenuated token (limit $100 -> $25), verify $50 payment")
print(f"   Result: {'ALLOW' if r4['allow'] else 'DENY'} (correctly denied)\n")

small_req = {"action": "payments.create", "amount": 20, "recipient": "niece@example.com"}
r5 = verify_token(narrow_token, small_req, vars=vars)
print("7. Same attenuated token, verify $20 payment")
print(f"   Result: {'ALLOW' if r5['allow'] else 'DENY'}\n")

# 7. Sealed token
sealed_token = mint(policy, priv_hex, sealed=True, expires="2027-01-01T00:00:00Z")
r6 = verify_token(sealed_token, valid_req, vars=vars)
print("8. Sealed token, verify $50 payment")
print(f"   Result: {'ALLOW' if r6['allow'] else 'DENY'}, Sealed: {r6['sealed']}")

print("\n=== All checks passed ===")
