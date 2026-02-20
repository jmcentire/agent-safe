using System.Security.Cryptography;

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
