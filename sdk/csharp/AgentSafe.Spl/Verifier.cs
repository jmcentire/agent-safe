namespace AgentSafe.Spl;

public static class Verifier
{
    public record VerifyResult(bool Allow);

    public static VerifyResult Verify(Node policyAst, Env env)
    {
        var evaluator = new Evaluator(env);
        var result = evaluator.Eval(policyAst);
        return new VerifyResult(result.IsTruthy());
    }
}
