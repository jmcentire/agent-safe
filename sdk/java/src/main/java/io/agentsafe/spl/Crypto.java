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
