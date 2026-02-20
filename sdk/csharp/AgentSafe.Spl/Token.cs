using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AgentSafe.Spl;

/// <summary>
/// A signed Agent-Safe capability token.
/// </summary>
public class Token
{
    [JsonPropertyName("version")]
    public string Version { get; set; } = "0.1.0";

    [JsonPropertyName("policy")]
    public string Policy { get; set; } = "";

    [JsonPropertyName("merkle_root")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? MerkleRoot { get; set; }

    [JsonPropertyName("hash_chain_commitment")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? HashChainCommitment { get; set; }

    [JsonPropertyName("sealed")]
    public bool Sealed { get; set; }

    [JsonPropertyName("expires")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Expires { get; set; }

    [JsonPropertyName("public_key")]
    public string PublicKey { get; set; } = "";

    [JsonPropertyName("signature")]
    public string Signature { get; set; } = "";

    /// <summary>
    /// Serialize this token to JSON.
    /// </summary>
    public string ToJson() => JsonSerializer.Serialize(this);

    /// <summary>
    /// Deserialize a token from JSON.
    /// </summary>
    public static Token FromJson(string json) =>
        JsonSerializer.Deserialize<Token>(json) ?? throw new SplException("invalid token JSON");

    /// <summary>
    /// Verify a token's signature using the Crypto module, then parse and evaluate its policy.
    /// Note: Ed25519 signature verification requires the AGENTSAFE_ED25519 build flag.
    /// Without it, signature verification is skipped and only policy evaluation is performed.
    /// </summary>
    public static VerifyTokenResult VerifyToken(Token token, Env env)
    {
#if AGENTSAFE_ED25519
        var policyBytes = Encoding.UTF8.GetBytes(token.Policy);
        if (!Crypto.VerifyEd25519(policyBytes, token.Signature, token.PublicKey))
            return new VerifyTokenResult(false, token.Sealed, "invalid signature");
#endif

        // Check expiration
        if (token.Expires != null)
        {
            if (DateTime.TryParse(token.Expires, out var exp) && DateTime.UtcNow > exp)
                return new VerifyTokenResult(false, token.Sealed, "token expired");
        }

        var ast = Parser.Parse(token.Policy);
        var evaluator = new Evaluator(env);
        var result = evaluator.Eval(ast);
        return new VerifyTokenResult(result.IsTruthy(), token.Sealed, null);
    }
}

public record VerifyTokenResult(bool Allow, bool Sealed, string? Error);
