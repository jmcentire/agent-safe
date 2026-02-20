package spl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func loadVectors(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile("../../../examples/crypto/" + name)
	if err != nil {
		t.Skipf("skipping crypto test: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

func TestEd25519ValidSignature(t *testing.T) {
	v := loadVectors(t, "ed25519_vectors.json")
	msg := v["message"].(string)
	sig := v["signature_hex"].(string)
	pub := v["public_key_hex"].(string)

	if !VerifyEd25519([]byte(msg), sig, pub) {
		t.Fatal("expected valid signature to verify")
	}
}

func TestEd25519TamperedMessage(t *testing.T) {
	v := loadVectors(t, "ed25519_vectors.json")
	tampered := v["tampered_message"].(string)
	sig := v["signature_hex"].(string)
	pub := v["public_key_hex"].(string)

	if VerifyEd25519([]byte(tampered), sig, pub) {
		t.Fatal("expected tampered message to fail verification")
	}
}

func TestMerkleProofValid(t *testing.T) {
	v := loadVectors(t, "merkle_vectors.json")
	root := v["root"].(string)
	cases := v["cases"].([]any)

	for _, c := range cases {
		tc := c.(map[string]any)
		name := tc["name"].(string)
		leaf := tc["leaf"].(string)
		leafHashExpected := tc["leaf_hash"].(string)
		expected := tc["expected"].(bool)

		// Verify leaf hash
		h := sha256.Sum256([]byte(leaf))
		if hex.EncodeToString(h[:]) != leafHashExpected {
			t.Fatalf("%s: leaf hash mismatch", name)
		}

		proofRaw := tc["proof"].([]any)
		var proof []MerkleProofStep
		for _, p := range proofRaw {
			pm := p.(map[string]any)
			proof = append(proof, MerkleProofStep{
				Hash:     pm["hash"].(string),
				Position: pm["position"].(string),
			})
		}

		result := VerifyMerkleProof(leaf, proof, root)
		if result != expected {
			t.Fatalf("%s: expected %v, got %v", name, expected, result)
		}
	}
}

func TestHashChainValid(t *testing.T) {
	v := loadVectors(t, "hashchain_vectors.json")
	commitment := v["commitment"].(string)
	chainLength := int(v["chain_length"].(float64))
	cases := v["cases"].([]any)

	for _, c := range cases {
		tc := c.(map[string]any)
		name := tc["name"].(string)
		preimage := tc["preimage"].(string)
		index := int(tc["index"].(float64))
		expected := tc["expected"].(bool)

		result := VerifyHashChain(commitment, preimage, index, chainLength)
		if result != expected {
			t.Fatalf("%s: expected %v, got %v", name, expected, result)
		}
	}
}
