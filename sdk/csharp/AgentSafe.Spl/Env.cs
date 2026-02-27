namespace AgentSafe.Spl;

public class CryptoCallbacks
{
    public Func<bool> DpopOk { get; set; } = () => false;
    public Func<List<Node>, bool> MerkleOk { get; set; } = _ => false;
    public Func<string, double, bool> VrfOk { get; set; } = (_, _) => false;
    /// <summary>
    /// thresh_ok — Threshold co-signature verification.
    /// Expected protocol: k-of-n co-signatures where the verifier checks each
    /// signature against its corresponding public key and confirms count >= threshold.
    /// Not implemented in v0.1 — remains an interface stub.
    /// </summary>
    public Func<bool> ThreshOk { get; set; } = () => false;
}

public class Env
{
    public Dictionary<string, Node> Req { get; set; } = new();
    public Dictionary<string, Node> Vars { get; set; } = new();
    public Func<string, string, int> PerDayCount { get; set; } = (_, _) => 0;
    public CryptoCallbacks Crypto { get; set; } = new();
    public int MaxGas { get; set; } = 10_000;
    public bool Sealed { get; set; } = false;
    public bool Strict { get; set; } = false;
}
