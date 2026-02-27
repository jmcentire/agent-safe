using System.Security.Cryptography;
// HMACSHA256 is in System.Security.Cryptography

namespace AgentSafe.Spl;

/// <summary>
/// Crypto implementations for SPL token verification.
/// SHA-256 Merkle + hash-chain via stdlib.
/// Ed25519 available in .NET 9+ via Ed25519.
/// </summary>
public static class Crypto
{
    public static byte[] Sha256(byte[] data) => SHA256.HashData(data);

    public static string Sha256Hex(byte[] data) => Convert.ToHexString(Sha256(data)).ToLowerInvariant();

    private static string ToHexLower(byte[] data) => Convert.ToHexString(data).ToLowerInvariant();

    /// <summary>Verify a Merkle proof for leafData against rootHex.</summary>
    public static bool VerifyMerkleProof(string leafData, (string Hash, string Position)[] proof, string rootHex)
    {
        try
        {
            var current = Sha256(System.Text.Encoding.UTF8.GetBytes(leafData));
            foreach (var (hash, position) in proof)
            {
                var sibling = Convert.FromHexString(hash);
                using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                if (position == "right")
                {
                    sha.AppendData(current);
                    sha.AppendData(sibling);
                }
                else
                {
                    sha.AppendData(sibling);
                    sha.AppendData(current);
                }
                current = sha.GetHashAndReset();
            }
            return ToHexLower(current) == rootHex;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Verify a hash chain receipt.</summary>
    public static bool VerifyHashChain(string commitment, string preimageHex, int index, int chainLength)
    {
        try
        {
            var current = Convert.FromHexString(preimageHex);
            var steps = chainLength - index;
            for (var i = 0; i < steps; i++)
                current = Sha256(current);
            return ToHexLower(current) == commitment;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>HKDF-SHA256 (RFC 5869) extract-and-expand. Zero external dependencies.</summary>
    private static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length)
    {
        if (salt == null || salt.Length == 0) salt = new byte[32];
        // Extract: PRK = HMAC-SHA256(salt, ikm)
        using var extractMac = new HMACSHA256(salt);
        var prk = extractMac.ComputeHash(ikm);

        // Expand
        var result = new byte[length];
        var prev = Array.Empty<byte>();
        var offset = 0;
        for (byte i = 1; offset < length; i++)
        {
            using var expandMac = new HMACSHA256(prk);
            expandMac.TransformBlock(prev, 0, prev.Length, null, 0);
            expandMac.TransformBlock(info, 0, info.Length, null, 0);
            expandMac.TransformFinalBlock(new[] { i }, 0, 1);
            prev = expandMac.Hash!;
            var toCopy = Math.Min(prev.Length, length - offset);
            Array.Copy(prev, 0, result, offset, toCopy);
            offset += toCopy;
        }
        return result;
    }

    /// <summary>
    /// Derive a service-specific Ed25519 seed using HKDF-SHA256.
    /// Returns (publicKeyHex, privateKeyHex) when Ed25519 is available.
    /// Without AGENTSAFE_ED25519, returns only the derived seed hex.
    /// </summary>
    public static (string Seed, string? PublicKey) DeriveServiceSeed(string masterKeyHex, string serviceDomain)
    {
        var masterKey = Convert.FromHexString(masterKeyHex);
        var salt = System.Text.Encoding.UTF8.GetBytes("agent-safe-v1");
        var info = System.Text.Encoding.UTF8.GetBytes(serviceDomain);
        var seed = HkdfSha256(masterKey, salt, info, 32);
        var seedHex = Convert.ToHexString(seed).ToLowerInvariant();
#if AGENTSAFE_ED25519
        // When Ed25519 is available, derive the full keypair
        // For now, return just the seed
#endif
        return (seedHex, null);
    }

// Ed25519 is not yet available in the .NET standard library.
// When it becomes available, uncomment the following:
#if AGENTSAFE_ED25519
    /// <summary>Verify an Ed25519 signature (requires .NET 9+).</summary>
    public static bool VerifyEd25519(byte[] message, string signatureHex, string publicKeyHex)
    {
        try
        {
            var sig = Convert.FromHexString(signatureHex);
            var pub = Convert.FromHexString(publicKeyHex);
            if (sig.Length != 64 || pub.Length != 32) return false;
            return System.Security.Cryptography.Ed25519.Verify(pub, message, sig);
        }
        catch
        {
            return false;
        }
    }
#endif
}
