package io.agentsafe.spl;

/**
 * Top-level SPL policy verification.
 */
public final class Verifier {
    private Verifier() {}

    public record Result(boolean allow) {}

    /**
     * Evaluate an SPL policy AST against a request within an environment.
     */
    public static Result verify(Node policyAst, Env env) {
        Evaluator evaluator = new Evaluator(env);
        Node result = evaluator.eval(policyAst);
        return new Result(result.isTruthy());
    }
}
