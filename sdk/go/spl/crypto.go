package spl

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// VerifyEd25519 checks an Ed25519 signature over a message.
func VerifyEd25519(message []byte, signatureHex, publicKeyHex string) bool {
	sig, err := hex.DecodeString(signatureHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	pub, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), message, sig)
}

// SHA256Hash returns the SHA-256 hash of data.
func SHA256Hash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// MerkleProofStep represents one step in a Merkle proof.
type MerkleProofStep struct {
	Hash     string `json:"hash"`
	Position string `json:"position"` // "left" or "right"
}

// VerifyMerkleProof checks a Merkle proof for leafData against rootHex.
func VerifyMerkleProof(leafData string, proof []MerkleProofStep, rootHex string) bool {
	current := SHA256Hash([]byte(leafData))

	for _, step := range proof {
		sibling, err := hex.DecodeString(step.Hash)
		if err != nil {
			return false
		}
		h := sha256.New()
		if step.Position == "right" {
			h.Write(current)
			h.Write(sibling)
		} else {
			h.Write(sibling)
			h.Write(current)
		}
		current = h.Sum(nil)
	}

	return hex.EncodeToString(current) == rootHex
}

// HashTuple hashes a slice of values by JSON-serializing then SHA-256.
func HashTuple(tuple []any) string {
	b, err := json.Marshal(tuple)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// hkdfSHA256 implements HKDF-SHA256 (RFC 5869) extract-and-expand.
// Zero external dependencies.
func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	// Extract: PRK = HMAC-SHA256(salt, ikm)
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	prk := mac.Sum(nil)

	// Expand: output = T(1) || T(2) || ...
	var out []byte
	var prev []byte
	for i := 1; len(out) < length; i++ {
		mac = hmac.New(sha256.New, prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{byte(i)})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}

// DeriveServiceKey derives a service-specific Ed25519 keypair using HKDF-SHA256.
// Provides unlinkability: different services see different public keys.
func DeriveServiceKey(masterKeyHex, serviceDomain string) (publicKeyHex, privateKeyHex string, err error) {
	masterKey, err := hex.DecodeString(masterKeyHex)
	if err != nil {
		return "", "", err
	}
	salt := []byte("agent-safe-v1")
	info := []byte(serviceDomain)
	seed := hkdfSHA256(masterKey, salt, info, ed25519.SeedSize)

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub), hex.EncodeToString(seed), nil
}

// VerifyHashChain checks that hashing preimageHex (chainLength - index) times
// produces the commitment.
func VerifyHashChain(commitment, preimageHex string, index, chainLength int) bool {
	current, err := hex.DecodeString(preimageHex)
	if err != nil {
		return false
	}
	steps := chainLength - index
	for i := 0; i < steps; i++ {
		h := sha256.Sum256(current)
		current = h[:]
	}
	return hex.EncodeToString(current) == commitment
}
