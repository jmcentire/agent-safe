package io.agentsafe.spl;

import java.security.*;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Arrays;

/**
 * Crypto implementations for SPL token verification.
 * Ed25519 via java.security.Signature (EdDSA, JDK 17+).
 * SHA-256 via MessageDigest.
 */
public final class Crypto {
    private Crypto() {}

    /**
     * Verify an Ed25519 signature over a message.
     */
    public static boolean verifyEd25519(byte[] message, String signatureHex, String publicKeyHex) {
        try {
            byte[] sigBytes = hexToBytes(signatureHex);
            byte[] pubBytes = hexToBytes(publicKeyHex);
            if (sigBytes.length != 64 || pubBytes.length != 32) return false;

            // Construct the public key using EdDSA
            KeyFactory kf = KeyFactory.getInstance("EdDSA");
            // Ed25519 public key from raw bytes
            // Use X509EncodedKeySpec with DER prefix
            byte[] derPrefix = hexToBytes("302a300506032b6570032100");
            byte[] encoded = new byte[derPrefix.length + pubBytes.length];
            System.arraycopy(derPrefix, 0, encoded, 0, derPrefix.length);
            System.arraycopy(pubBytes, 0, encoded, derPrefix.length, pubBytes.length);

            PublicKey publicKey = kf.generatePublic(new java.security.spec.X509EncodedKeySpec(encoded));
            Signature sig = Signature.getInstance("EdDSA");
            sig.initVerify(publicKey);
            sig.update(message);
            return sig.verify(sigBytes);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * SHA-256 hash of data.
     */
    public static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * SHA-256 hash of data as hex string.
     */
    public static String sha256Hex(byte[] data) {
        return bytesToHex(sha256(data));
    }

    /**
     * Verify a Merkle proof.
     */
    public static boolean verifyMerkleProof(String leafData, String[][] proof, String rootHex) {
        try {
            byte[] current = sha256(leafData.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            for (String[] step : proof) {
                String hash = step[0];
                String position = step[1];
                byte[] sibling = hexToBytes(hash);
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                if (position.equals("right")) {
                    md.update(current);
                    md.update(sibling);
                } else {
                    md.update(sibling);
                    md.update(current);
                }
                current = md.digest();
            }
            return bytesToHex(current).equals(rootHex);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Verify a hash chain receipt.
     */
    public static boolean verifyHashChain(String commitment, String preimageHex, int index, int chainLength) {
        try {
            byte[] current = hexToBytes(preimageHex);
            int steps = chainLength - index;
            for (int i = 0; i < steps; i++) {
                current = sha256(current);
            }
            return bytesToHex(current).equals(commitment);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * HMAC-SHA256.
     */
    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 not available", e);
        }
    }

    /**
     * HKDF-SHA256 (RFC 5869) extract-and-expand. Zero external dependencies.
     */
    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) {
        // Extract
        if (salt == null || salt.length == 0) salt = new byte[32];
        byte[] prk = hmacSha256(salt, ikm);

        // Expand
        byte[] out = new byte[0];
        byte[] prev = new byte[0];
        for (int i = 1; out.length < length; i++) {
            byte[] input = new byte[prev.length + info.length + 1];
            System.arraycopy(prev, 0, input, 0, prev.length);
            System.arraycopy(info, 0, input, prev.length, info.length);
            input[input.length - 1] = (byte) i;
            prev = hmacSha256(prk, input);
            byte[] newOut = new byte[out.length + prev.length];
            System.arraycopy(out, 0, newOut, 0, out.length);
            System.arraycopy(prev, 0, newOut, out.length, prev.length);
            out = newOut;
        }
        return java.util.Arrays.copyOf(out, length);
    }

    /**
     * Derive a service-specific Ed25519 keypair using HKDF-SHA256.
     * Provides unlinkability: different services see different public keys.
     *
     * @return [publicKeyHex, privateKeyHex]
     */
    public static String[] deriveServiceKey(String masterKeyHex, String serviceDomain) {
        try {
            byte[] masterKey = hexToBytes(masterKeyHex);
            byte[] salt = "agent-safe-v1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] info = serviceDomain.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] seed = hkdfSha256(masterKey, salt, info, 32);

            // Build PKCS8 DER for Ed25519 private key from seed
            byte[] pkcs8Prefix = hexToBytes("302e020100300506032b657004220420");
            byte[] privDer = new byte[pkcs8Prefix.length + seed.length];
            System.arraycopy(pkcs8Prefix, 0, privDer, 0, pkcs8Prefix.length);
            System.arraycopy(seed, 0, privDer, pkcs8Prefix.length, seed.length);

            KeyFactory kf = KeyFactory.getInstance("Ed25519");
            java.security.PrivateKey privKey = kf.generatePrivate(
                new java.security.spec.PKCS8EncodedKeySpec(privDer));

            // Extract public key
            java.security.interfaces.EdECPrivateKey edPriv =
                (java.security.interfaces.EdECPrivateKey) privKey;
            byte[] encoded = edPriv.getEncoded();
            // Look for public key in PKCS8 v2 encoding
            for (int i = 0; i < encoded.length - 33; i++) {
                if (encoded[i] == (byte) 0xa1 && encoded[i + 1] == (byte) 0x23
                    && encoded[i + 2] == (byte) 0x03 && encoded[i + 3] == (byte) 0x21
                    && encoded[i + 4] == (byte) 0x00) {
                    byte[] pubBytes = new byte[32];
                    System.arraycopy(encoded, i + 5, pubBytes, 0, 32);

                    boolean xOdd = (pubBytes[31] & 0x80) != 0;
                    pubBytes[31] &= 0x7f;
                    byte[] reversed = new byte[32];
                    for (int j = 0; j < 32; j++) reversed[j] = pubBytes[31 - j];
                    java.math.BigInteger y = new java.math.BigInteger(1, reversed);
                    java.security.spec.EdECPoint pubPoint =
                        new java.security.spec.EdECPoint(xOdd, y);
                    java.security.spec.EdECPublicKeySpec pubSpec =
                        new java.security.spec.EdECPublicKeySpec(
                            java.security.spec.NamedParameterSpec.ED25519, pubPoint);
                    java.security.PublicKey pubKey = kf.generatePublic(pubSpec);
                    byte[] pubDer = pubKey.getEncoded();
                    byte[] pubRaw = new byte[32];
                    System.arraycopy(pubDer, pubDer.length - 32, pubRaw, 0, 32);
                    return new String[]{bytesToHex(pubRaw), bytesToHex(seed)};
                }
            }
            throw new SplException("Could not extract public key from derived private key");
        } catch (SplException e) {
            throw e;
        } catch (Exception e) {
            throw new SplException("Failed to derive service key: " + e.getMessage());
        }
    }

    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}
