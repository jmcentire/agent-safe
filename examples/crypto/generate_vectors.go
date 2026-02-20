// +build ignore

// Generates shared crypto test vectors for all SDKs.
// Run: go run generate_vectors.go
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	generateEd25519Vectors()
	generateMerkleVectors()
	generateHashChainVectors()
	fmt.Println("All vectors generated.")
}

func generateEd25519Vectors() {
	// Deterministic seed for reproducibility
	seed := sha256.Sum256([]byte("agent-safe-test-vector-seed-ed25519"))
	privKey := ed25519.NewKeyFromSeed(seed[:])
	pubKey := privKey.Public().(ed25519.PublicKey)

	message := []byte(`(and (= (get req "action") "read") (<= (get req "amount") 100))`)
	signature := ed25519.Sign(privKey, message)

	// Tampered message
	tampered := make([]byte, len(message))
	copy(tampered, message)
	tampered[5] = 'o' // change '=' to 'o'

	vectors := map[string]any{
		"description": "Ed25519 test vectors for SPL policy signing",
		"private_key_hex": hex.EncodeToString(privKey.Seed()),
		"public_key_hex":  hex.EncodeToString([]byte(pubKey)),
		"message":         string(message),
		"signature_hex":   hex.EncodeToString(signature),
		"tampered_message": string(tampered),
		"cases": []map[string]any{
			{
				"name":     "valid_signature",
				"message":  string(message),
				"expected": true,
			},
			{
				"name":     "tampered_message",
				"message":  string(tampered),
				"expected": false,
			},
		},
	}

	writeJSON("ed25519_vectors.json", vectors)
}

func generateMerkleVectors() {
	// 4-leaf Merkle tree
	leaves := []string{
		"alice@example.com",
		"bob@example.com",
		"carol@example.com",
		"dave@example.com",
	}

	// Hash each leaf
	leafHashes := make([][]byte, len(leaves))
	leafHashHexes := make([]string, len(leaves))
	for i, l := range leaves {
		h := sha256.Sum256([]byte(l))
		leafHashes[i] = h[:]
		leafHashHexes[i] = hex.EncodeToString(h[:])
	}

	// Build tree: level 1 (pairs of leaves)
	n01 := hashPair(leafHashes[0], leafHashes[1])
	n23 := hashPair(leafHashes[2], leafHashes[3])
	root := hashPair(n01, n23)

	// Proof for leaf 0 (alice): sibling=leaf1_hash, then n23
	proof0 := []map[string]any{
		{"hash": hex.EncodeToString(leafHashes[1]), "position": "right"},
		{"hash": hex.EncodeToString(n23), "position": "right"},
	}

	// Proof for leaf 2 (carol): sibling=leaf3_hash (right), then n01 (left)
	proof2 := []map[string]any{
		{"hash": hex.EncodeToString(leafHashes[3]), "position": "right"},
		{"hash": hex.EncodeToString(n01), "position": "left"},
	}

	vectors := map[string]any{
		"description": "SHA-256 Merkle tree test vectors (4 leaves)",
		"leaves":      leaves,
		"leaf_hashes": leafHashHexes,
		"root":        hex.EncodeToString(root),
		"cases": []map[string]any{
			{
				"name":      "valid_proof_leaf_0",
				"leaf":      leaves[0],
				"leaf_hash": leafHashHexes[0],
				"proof":     proof0,
				"expected":  true,
			},
			{
				"name":      "valid_proof_leaf_2",
				"leaf":      leaves[2],
				"leaf_hash": leafHashHexes[2],
				"proof":     proof2,
				"expected":  true,
			},
			{
				"name":      "invalid_proof_wrong_leaf",
				"leaf":      "eve@example.com",
				"leaf_hash": hex.EncodeToString(sha256Bytes([]byte("eve@example.com"))),
				"proof":     proof0,
				"expected":  false,
			},
		},
	}

	writeJSON("merkle_vectors.json", vectors)
}

func generateHashChainVectors() {
	// Seed -> hash 5 times to produce chain
	// chain[0] = seed, chain[i] = SHA256(chain[i-1])
	// Commitment = chain[5] (the end)
	// To prove step i, reveal chain[i] and verifier hashes (5-i) times to reach commitment
	seed := sha256.Sum256([]byte("agent-safe-hash-chain-seed"))

	chain := make([]string, 6) // chain[0]=seed, chain[1..5]=hashes
	chain[0] = hex.EncodeToString(seed[:])
	current := seed[:]
	for i := 1; i <= 5; i++ {
		h := sha256.Sum256(current)
		current = h[:]
		chain[i] = hex.EncodeToString(h[:])
	}

	// Commitment is chain[5]
	commitment := chain[5]

	vectors := map[string]any{
		"description": "SHA-256 hash chain test vectors (5-step chain)",
		"seed_hex":    chain[0],
		"chain":       chain,
		"commitment":  commitment,
		"chain_length": 5,
		"cases": []map[string]any{
			{
				"name":       "valid_receipt_step_3",
				"preimage":   chain[3],
				"index":      3,
				"expected":   true,
				"note":       "Hash preimage (5-3)=2 times to reach commitment",
			},
			{
				"name":       "valid_receipt_step_0",
				"preimage":   chain[0],
				"index":      0,
				"expected":   true,
				"note":       "Hash seed 5 times to reach commitment",
			},
			{
				"name":       "valid_receipt_step_5",
				"preimage":   chain[5],
				"index":      5,
				"expected":   true,
				"note":       "Preimage IS the commitment (0 hashes)",
			},
			{
				"name":       "invalid_receipt_wrong_preimage",
				"preimage":   hex.EncodeToString(sha256Bytes([]byte("wrong"))),
				"index":      3,
				"expected":   false,
			},
		},
	}

	writeJSON("hashchain_vectors.json", vectors)
}

func hashPair(a, b []byte) []byte {
	h := sha256.New()
	h.Write(a)
	h.Write(b)
	sum := h.Sum(nil)
	return sum
}

func sha256Bytes(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func writeJSON(filename string, data any) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		panic(err)
	}
	err = os.WriteFile(filename, b, 0644)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Wrote %s\n", filename)
}
