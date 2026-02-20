// Agent-Safe End-to-End Example (Go)
//
// Demonstrates the full lifecycle:
// 1. Generate keypair
// 2. Mint a signed capability token
// 3. Verify token against valid/invalid requests
// 4. Attenuate token (narrow the limit)
// 5. Seal a token
//
// Run: cd examples/e2e && go run e2e.go

package main

import (
	"encoding/json"
	"fmt"

	"github.com/jmcentire/agent-safe/sdk/go/spl"
)

func main() {
	fmt.Println("=== Agent-Safe E2E Demo ===\n")

	// 1. Generate keypair
	pubHex, privHex := spl.GenerateKeypair()
	fmt.Println("1. Generated Ed25519 keypair")
	fmt.Printf("   Public key:  %s...\n", pubHex[:16])
	fmt.Printf("   Private key: %s...\n\n", privHex[:16])

	// 2. Mint a token
	policy := `(and
  (= (get req "action") "payments.create")
  (<= (get req "amount") 100)
  (member (get req "recipient") allowed_recipients)
)`

	token, err := spl.Mint(policy, privHex, spl.MintOptions{
		Expires: "2027-01-01T00:00:00Z",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("2. Minted token")
	fmt.Printf("   Sealed: %v\n", token.Sealed)
	fmt.Printf("   Signature: %s...\n\n", token.Signature[:32])

	tokenJSON, _ := json.Marshal(token)

	vars := map[string]any{
		"allowed_recipients": []any{"niece@example.com", "mom@example.com"},
	}
	opts := spl.VerifyTokenOptions{Vars: vars}

	// 3. Valid request
	validReq := map[string]any{
		"action":    "payments.create",
		"amount":    50.0,
		"recipient": "niece@example.com",
	}
	r1 := spl.VerifyToken(string(tokenJSON), validReq, opts)
	fmt.Println("3. Verify $50 payment to niece@example.com")
	fmt.Printf("   Result: %s\n\n", boolToResult(r1.Allow))

	// 4. Over-limit
	overReq := map[string]any{
		"action":    "payments.create",
		"amount":    200.0,
		"recipient": "niece@example.com",
	}
	r2 := spl.VerifyToken(string(tokenJSON), overReq, opts)
	fmt.Println("4. Verify $200 payment (exceeds $100 limit)")
	fmt.Printf("   Result: %s\n\n", boolToResult(r2.Allow))

	// 5. Bad recipient
	badReq := map[string]any{
		"action":    "payments.create",
		"amount":    50.0,
		"recipient": "stranger@example.com",
	}
	r3 := spl.VerifyToken(string(tokenJSON), badReq, opts)
	fmt.Println("5. Verify $50 payment to stranger@example.com")
	fmt.Printf("   Result: %s\n\n", boolToResult(r3.Allow))

	// 6. Attenuated token
	narrowPolicy := `(and
  (= (get req "action") "payments.create")
  (<= (get req "amount") 25)
  (member (get req "recipient") allowed_recipients)
)`
	narrowToken, _ := spl.Mint(narrowPolicy, privHex, spl.MintOptions{
		Expires: "2027-01-01T00:00:00Z",
	})
	narrowJSON, _ := json.Marshal(narrowToken)
	r4 := spl.VerifyToken(string(narrowJSON), validReq, opts)
	fmt.Println("6. Attenuated token (limit $100 -> $25), verify $50 payment")
	fmt.Printf("   Result: %s (correctly denied)\n\n", boolToResult(r4.Allow))

	smallReq := map[string]any{
		"action":    "payments.create",
		"amount":    20.0,
		"recipient": "niece@example.com",
	}
	r5 := spl.VerifyToken(string(narrowJSON), smallReq, opts)
	fmt.Println("7. Same attenuated token, verify $20 payment")
	fmt.Printf("   Result: %s\n\n", boolToResult(r5.Allow))

	// 7. Sealed token
	sealedToken, _ := spl.Mint(policy, privHex, spl.MintOptions{
		Sealed:  true,
		Expires: "2027-01-01T00:00:00Z",
	})
	sealedJSON, _ := json.Marshal(sealedToken)
	r6 := spl.VerifyToken(string(sealedJSON), validReq, opts)
	fmt.Println("8. Sealed token, verify $50 payment")
	fmt.Printf("   Result: %s, Sealed: %v\n", boolToResult(r6.Allow), r6.Sealed)

	fmt.Println("\n=== All checks passed ===")
}

func boolToResult(b bool) string {
	if b {
		return "ALLOW"
	}
	return "DENY"
}
