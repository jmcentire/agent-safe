package spl

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Token represents a signed Agent-Safe capability token.
type Token struct {
	Version              string `json:"version"`
	Policy               string `json:"policy"`
	MerkleRoot           string `json:"merkle_root,omitempty"`
	HashChainCommitment  string `json:"hash_chain_commitment,omitempty"`
	Sealed               bool   `json:"sealed"`
	Expires              string `json:"expires,omitempty"`
	PublicKey            string `json:"public_key"`
	Signature            string `json:"signature"`
}

// GenerateKeypair creates a new Ed25519 keypair.
// Returns (publicKeyHex, privateKeyHex).
func GenerateKeypair() (string, string) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return hex.EncodeToString(pub), hex.EncodeToString(priv.Seed())
}

// MintOptions configures token minting.
type MintOptions struct {
	MerkleRoot          string
	HashChainCommitment string
	Sealed              bool
	Expires             string
}

// Mint creates a signed capability token.
func Mint(policy string, privateKeyHex string, opts MintOptions) (*Token, error) {
	seed, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("private key must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	policyBytes := []byte(policy)
	sig := ed25519.Sign(priv, policyBytes)

	return &Token{
		Version:             "0.1.0",
		Policy:              policy,
		MerkleRoot:          opts.MerkleRoot,
		HashChainCommitment: opts.HashChainCommitment,
		Sealed:              opts.Sealed,
		Expires:             opts.Expires,
		PublicKey:           hex.EncodeToString(pub),
		Signature:           hex.EncodeToString(sig),
	}, nil
}

// VerifyTokenOptions configures token verification.
type VerifyTokenOptions struct {
	Vars        map[string]any
	PerDayCount func(action, day string) int
	Crypto      struct {
		DPoPOk   func() bool
		MerkleOk func(tuple []any) bool
		VRFOk    func(day string, amount float64) bool
		ThreshOk func() bool
	}
	Now string
}

// VerifyTokenResult is the result of token verification.
type VerifyTokenResult struct {
	Allow  bool
	Sealed bool
	Error  string
}

// VerifyToken verifies a token's signature and evaluates its policy.
func VerifyToken(tokenJSON string, req map[string]any, opts VerifyTokenOptions) VerifyTokenResult {
	var t Token
	if err := json.Unmarshal([]byte(tokenJSON), &t); err != nil {
		return VerifyTokenResult{Allow: false, Error: "invalid token JSON: " + err.Error()}
	}

	return VerifyTokenObj(&t, req, opts)
}

// VerifyTokenObj verifies a token object and evaluates its policy.
func VerifyTokenObj(t *Token, req map[string]any, opts VerifyTokenOptions) VerifyTokenResult {
	// Check expiration
	if t.Expires != "" {
		exp, err := time.Parse(time.RFC3339, t.Expires)
		if err == nil {
			now := time.Now()
			if opts.Now != "" {
				if n, err := time.Parse(time.RFC3339, opts.Now); err == nil {
					now = n
				}
			}
			if now.After(exp) {
				return VerifyTokenResult{Allow: false, Sealed: t.Sealed, Error: "token expired"}
			}
		}
	}

	// Verify signature
	if !VerifyEd25519([]byte(t.Policy), t.Signature, t.PublicKey) {
		return VerifyTokenResult{Allow: false, Sealed: t.Sealed, Error: "invalid signature"}
	}

	// Parse policy
	ast, err := Parse(t.Policy)
	if err != nil {
		return VerifyTokenResult{Allow: false, Sealed: t.Sealed, Error: "parse error: " + err.Error()}
	}

	// Set up defaults
	perDayCount := opts.PerDayCount
	if perDayCount == nil {
		perDayCount = func(_, _ string) int { return 0 }
	}
	dpopOk := opts.Crypto.DPoPOk
	if dpopOk == nil {
		dpopOk = func() bool { return true }
	}
	merkleOk := opts.Crypto.MerkleOk
	if merkleOk == nil {
		merkleOk = func(_ []any) bool { return true }
	}
	vrfOk := opts.Crypto.VRFOk
	if vrfOk == nil {
		vrfOk = func(_ string, _ float64) bool { return true }
	}
	threshOk := opts.Crypto.ThreshOk
	if threshOk == nil {
		threshOk = func() bool { return true }
	}

	vars := opts.Vars
	if vars == nil {
		vars = map[string]any{}
	}
	if opts.Now != "" {
		vars["now"] = opts.Now
	}

	env := Env{
		Req:         req,
		Vars:        vars,
		PerDayCount: perDayCount,
		Crypto: struct {
			DPoPOk   func() bool
			MerkleOk func(tuple []any) bool
			VRFOk    func(day string, amount float64) bool
			ThreshOk func() bool
		}{
			DPoPOk:   dpopOk,
			MerkleOk: merkleOk,
			VRFOk:    vrfOk,
			ThreshOk: threshOk,
		},
	}

	allow, err := Verify(ast, env)
	if err != nil {
		return VerifyTokenResult{Allow: false, Sealed: t.Sealed, Error: err.Error()}
	}

	return VerifyTokenResult{Allow: allow, Sealed: t.Sealed}
}
