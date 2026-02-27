package io.agentsafe.spl;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Token minting and verification for Agent-Safe capability tokens.
 */
public final class Token {
    public String version;
    public String policy;
    public String merkleRoot;
    public String hashChainCommitment;
    public boolean sealed;
    public String expires;
    public String publicKey;
    public String signature;
    public String popKey;

    /**
     * Generate an Ed25519 keypair.
     * @return [publicKeyHex, privateKeyHex]
     */
    public static String[] generateKeypair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            KeyPair kp = kpg.generateKeyPair();

            byte[] pubDer = kp.getPublic().getEncoded();
            byte[] pubRaw = new byte[32];
            System.arraycopy(pubDer, pubDer.length - 32, pubRaw, 0, 32);

            byte[] privDer = kp.getPrivate().getEncoded();
            byte[] privSeed = new byte[32];
            System.arraycopy(privDer, privDer.length - 32, privSeed, 0, 32);

            return new String[]{
                Crypto.bytesToHex(pubRaw),
                Crypto.bytesToHex(privSeed)
            };
        } catch (Exception e) {
            throw new SplException("Failed to generate keypair: " + e.getMessage());
        }
    }

    /**
     * Mint a signed capability token.
     */
    public static Token mint(String policy, String privateKeyHex) {
        return mint(policy, privateKeyHex, false, null);
    }

    /**
     * Build the canonical signing payload for a token.
     * Covers all security-relevant fields so sealed, expires, merkle_root, and
     * hash_chain_commitment cannot be tampered with after signing.
     */
    public static byte[] signingPayload(String policy, String merkleRoot, String hashChainCommitment,
                                         boolean sealed, String expires) {
        String joined = policy.trim() + "\0" +
            (merkleRoot != null ? merkleRoot : "") + "\0" +
            (hashChainCommitment != null ? hashChainCommitment : "") + "\0" +
            (sealed ? "1" : "0") + "\0" +
            (expires != null ? expires : "");
        return joined.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    /**
     * Mint a signed capability token with options.
     */
    public static Token mint(String policy, String privateKeyHex, boolean sealed, String expires) {
        try {
            byte[] seed = Crypto.hexToBytes(privateKeyHex);

            // Build PKCS8 DER for Ed25519 private key from seed
            byte[] pkcs8Prefix = Crypto.hexToBytes("302e020100300506032b657004220420");
            byte[] privDer = new byte[pkcs8Prefix.length + seed.length];
            System.arraycopy(pkcs8Prefix, 0, privDer, 0, pkcs8Prefix.length);
            System.arraycopy(seed, 0, privDer, pkcs8Prefix.length, seed.length);

            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            PrivateKey privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privDer));

            byte[] payload = signingPayload(policy, null, null, sealed, expires);

            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(privKey);
            sig.update(payload);
            byte[] sigBytes = sig.sign();

            // Derive public key from private key
            // Re-encode as DER and extract public key
            byte[] derPrefix = Crypto.hexToBytes("302a300506032b6570032100");
            // Get public key by signing a test message and extracting from the keypair
            // Actually, use the KeyFactory approach
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
            // Alternative: reconstruct from the PKCS8 private key
            // The public key bytes are derivable from the private key
            // Use Ed25519 math: pubkey = seed * G
            // Simplest: re-create keypair from the seed by re-importing

            // Actually in JDK, we can get the public key from private key via signature verification
            // Easier: encode private to PKCS8, import, get associated public key
            // JDK doesn't expose this directly. Use a workaround:
            // Sign and verify approach - we already have the signature.
            // Let's derive public key bytes using EdDSA math

            // Best approach: construct a minimal keypair generator with the seed
            // JDK 17+ doesn't have a direct way to derive pub from priv seed
            // Workaround: use the DER-encoded private key which contains the public key
            // In Ed25519 PKCS8 v2, the public key is embedded

            // For Ed25519, the simplest approach: generate public from crypto operations
            // Actually, the JDK PrivateKey object can derive the PublicKey
            // through EdECPrivateKeySpec

            // Let's use the approach of extracting from a generated keypair
            // This requires us to sign test data and find the matching public key
            // OR we can use the Edwards curve math directly

            // Simplest: just use bouncy castle... but we want zero deps.
            // Next simplest: use JDK's ability to extract the public key

            // Actually in JDK 21, we can do this:
            java.security.interfaces.EdECPrivateKey edPriv =
                (java.security.interfaces.EdECPrivateKey) privKey;
            java.security.spec.EdECPoint pubPoint = computePublicPoint(edPriv);
            java.security.spec.EdECPublicKeySpec pubSpec =
                new java.security.spec.EdECPublicKeySpec(
                    java.security.spec.NamedParameterSpec.ED25519, pubPoint);
            PublicKey pubKey = kf.generatePublic(pubSpec);
            byte[] pubDer2 = pubKey.getEncoded();
            byte[] pubRaw = new byte[32];
            System.arraycopy(pubDer2, pubDer2.length - 32, pubRaw, 0, 32);

            Token t = new Token();
            t.version = "0.2.0";
            t.policy = policy.trim();
            t.sealed = sealed;
            t.expires = expires;
            t.publicKey = Crypto.bytesToHex(pubRaw);
            t.signature = Crypto.bytesToHex(sigBytes);
            return t;
        } catch (Exception e) {
            throw new SplException("Failed to mint token: " + e.getMessage());
        }
    }

    private static java.security.spec.EdECPoint computePublicPoint(
            java.security.interfaces.EdECPrivateKey privKey) {
        // JDK doesn't provide a direct way to compute public from private.
        // Use the test-sign-verify pattern: sign with private, then extract public from DER.
        // Actually, the simplest is: re-import the PKCS8 bytes and get the public key
        // from the KeyFactory by generating a new keypair... but that won't work.

        // Alternative: Use the PKCS8 v2 format which embeds the public key.
        // The private key DER from JDK includes the public key in the optional field.
        byte[] encoded = privKey.getEncoded();
        // PKCS8 v2 for Ed25519 with public key:
        // 30 51 02 01 01 30 05 06 03 2b 65 70 04 22 04 20 <32 seed bytes> a1 23 03 21 00 <32 pub bytes>
        // Look for the a1 23 tag
        for (int i = 0; i < encoded.length - 33; i++) {
            if (encoded[i] == (byte) 0xa1 && encoded[i + 1] == (byte) 0x23
                && encoded[i + 2] == (byte) 0x03 && encoded[i + 3] == (byte) 0x21
                && encoded[i + 4] == (byte) 0x00) {
                byte[] pubBytes = new byte[32];
                System.arraycopy(encoded, i + 5, pubBytes, 0, 32);
                // Ed25519 point: the MSB of the last byte determines the sign
                boolean xOdd = (pubBytes[31] & 0x80) != 0;
                pubBytes[31] &= 0x7f; // clear the sign bit
                // Reverse byte order (little-endian to big-endian)
                byte[] reversed = new byte[32];
                for (int j = 0; j < 32; j++) reversed[j] = pubBytes[31 - j];
                java.math.BigInteger y = new java.math.BigInteger(1, reversed);
                return new java.security.spec.EdECPoint(xOdd, y);
            }
        }
        throw new SplException("Could not extract public key from private key DER encoding");
    }

    /**
     * Create a PoP presentation signature for a token.
     * The agent signs SHA-256(signing_payload) with its own Ed25519 key.
     */
    public static String createPresentationSignature(Token t, String agentPrivateKeyHex) {
        try {
            byte[] seed = Crypto.hexToBytes(agentPrivateKeyHex);
            byte[] pkcs8Prefix = Crypto.hexToBytes("302e020100300506032b657004220420");
            byte[] privDer = new byte[pkcs8Prefix.length + seed.length];
            System.arraycopy(pkcs8Prefix, 0, privDer, 0, pkcs8Prefix.length);
            System.arraycopy(seed, 0, privDer, pkcs8Prefix.length, seed.length);

            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            PrivateKey privKey = kf.generatePrivate(new PKCS8EncodedKeySpec(privDer));

            byte[] payload = signingPayload(t.policy, t.merkleRoot, t.hashChainCommitment, t.sealed, t.expires);
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] popPayload = md.digest(payload);

            Signature sig = Signature.getInstance("Ed25519");
            sig.initSign(privKey);
            sig.update(popPayload);
            return Crypto.bytesToHex(sig.sign());
        } catch (Exception e) {
            throw new SplException("Failed to create presentation signature: " + e.getMessage());
        }
    }

    /**
     * Verify a token's signature and evaluate its policy.
     */
    public static Verifier.Result verifyToken(Token t, Env env) {
        return verifyToken(t, env, null);
    }

    /**
     * Verify a token's signature and evaluate its policy, with optional PoP.
     */
    public static Verifier.Result verifyToken(Token t, Env env, String presentationSignature) {
        // Verify signature over full token envelope
        byte[] payload = signingPayload(t.policy, t.merkleRoot, t.hashChainCommitment, t.sealed, t.expires);
        if (!Crypto.verifyEd25519(payload, t.signature, t.publicKey)) {
            throw new SplException("invalid signature");
        }

        // PoP binding: if token has pop_key, require and verify presentation signature
        if (t.popKey != null && !t.popKey.isEmpty()) {
            if (presentationSignature == null || presentationSignature.isEmpty()) {
                throw new SplException("PoP binding requires presentation signature");
            }
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] popPayload = md.digest(payload);
                if (!Crypto.verifyEd25519(popPayload, presentationSignature, t.popKey)) {
                    throw new SplException("invalid presentation signature");
                }
            } catch (java.security.NoSuchAlgorithmException e) {
                throw new SplException("SHA-256 not available");
            }
        }

        // Parse and evaluate
        Node ast = Parser.parse(t.policy);
        return Verifier.verify(ast, env);
    }
}
