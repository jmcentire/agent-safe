using AgentSafe.Spl;
using Xunit;

namespace AgentSafe.Spl.Tests;

public class SplTests
{
    static Env MakeEnv()
    {
        var env = new Env();
        env.Req["actor_pub"] = Node.Str("K_ai");
        env.Req["action"] = Node.Str("payments.create");
        env.Req["recipient"] = Node.Str("niece@example.com");
        env.Req["purpose"] = Node.Str("giftcard");
        env.Req["amount"] = Node.Num(50.0);
        env.Req["day"] = Node.Str("2025-09-29");
        env.Req["device_attested"] = Node.Bool(true);
        env.Vars["allowed_recipients"] = Node.List(new List<Node>
        {
            Node.Str("niece@example.com"), Node.Str("mom@example.com")
        });
        env.Vars["now"] = Node.Str("2025-10-01T00:00:00Z");
        return env;
    }

    bool EvalExpr(string src, Env? env = null)
    {
        var ast = Parser.Parse(src);
        return Verifier.Verify(ast, env ?? MakeEnv()).Allow;
    }

    // --- Parser tests ---
    [Fact] public void ParseInteger() => Assert.Equal(Node.Num(42), Parser.Parse("42"));
    [Fact] public void ParseNegativeFloat() => Assert.Equal(Node.Num(-3.14), Parser.Parse("-3.14"));
    [Fact] public void ParseString() => Assert.Equal(Node.Str("hello"), Parser.Parse("\"hello\""));
    [Fact] public void ParseBoolTrue() => Assert.Equal(Node.Bool(true), Parser.Parse("#t"));
    [Fact] public void ParseBoolFalse() => Assert.Equal(Node.Bool(false), Parser.Parse("#f"));
    [Fact] public void ParseSymbol() => Assert.Equal(Node.Sym("foo"), Parser.Parse("foo"));

    [Fact]
    public void ParseList()
    {
        var ast = Parser.Parse("(and #t #f)");
        var ln = Assert.IsType<Node.ListNode>(ast);
        Assert.Equal(3, ln.Items.Count);
    }

    [Fact]
    public void ParseNested()
    {
        var ast = Parser.Parse("(and (= 1 2) (> 3 1))");
        var ln = Assert.IsType<Node.ListNode>(ast);
        Assert.IsType<Node.ListNode>(ln.Items[1]);
    }

    [Fact]
    public void ParseStringsWithSpaces()
    {
        var ast = Parser.Parse("(= \"hello world\" \"hello world\")");
        var ln = Assert.IsType<Node.ListNode>(ast);
        Assert.Equal(Node.Str("hello world"), ln.Items[1]);
    }

    [Fact] public void UnterminatedParen() => Assert.Throws<SplException>(() => Parser.Parse("(and #t"));
    [Fact] public void UnexpectedClose() => Assert.Throws<SplException>(() => Parser.Parse(")"));
    [Fact] public void ExtraTokens() => Assert.Throws<SplException>(() => Parser.Parse("#t #f"));

    // --- Eval tests ---
    [Fact] public void AndAllTrue() => Assert.True(EvalExpr("(and #t #t #t)"));
    [Fact] public void AndOneFalse() => Assert.False(EvalExpr("(and #t #f #t)"));
    [Fact] public void OrOneTrue() => Assert.True(EvalExpr("(or #f #t #f)"));
    [Fact] public void OrAllFalse() => Assert.False(EvalExpr("(or #f #f)"));
    [Fact] public void NotFalse() => Assert.True(EvalExpr("(not #f)"));
    [Fact] public void NotTrue() => Assert.False(EvalExpr("(not #t)"));
    [Fact] public void EqualStrings() => Assert.True(EvalExpr("(= \"hello\" \"hello\")"));
    [Fact] public void EqualStringsFalse() => Assert.False(EvalExpr("(= \"hello\" \"world\")"));

    [Fact]
    public void LessEqual()
    {
        Assert.True(EvalExpr("(<= 5 10)"));
        Assert.True(EvalExpr("(<= 10 10)"));
        Assert.False(EvalExpr("(<= 11 10)"));
    }

    [Fact]
    public void LessThan()
    {
        Assert.True(EvalExpr("(< 5 10)"));
        Assert.False(EvalExpr("(< 5 5)"));
    }

    [Fact]
    public void GreaterEqual()
    {
        Assert.True(EvalExpr("(>= 10 10)"));
        Assert.False(EvalExpr("(>= 9 10)"));
    }

    [Fact]
    public void GreaterThan()
    {
        Assert.True(EvalExpr("(> 10 5)"));
        Assert.False(EvalExpr("(> 5 5)"));
    }

    [Fact]
    public void Member()
    {
        Assert.True(EvalExpr("(member \"niece@example.com\" allowed_recipients)"));
        Assert.False(EvalExpr("(member \"stranger@example.com\" allowed_recipients)"));
    }

    [Fact] public void InAlias() => Assert.True(EvalExpr("(in \"mom@example.com\" allowed_recipients)"));

    [Fact]
    public void Subset()
    {
        var env = MakeEnv();
        env.Vars["small"] = Node.List(new List<Node> { Node.Str("a"), Node.Str("b") });
        env.Vars["big"] = Node.List(new List<Node> { Node.Str("a"), Node.Str("b"), Node.Str("c") });
        Assert.True(EvalExpr("(subset? small big)", env));
        var env2 = MakeEnv();
        env2.Vars["small"] = Node.List(new List<Node> { Node.Str("a"), Node.Str("b") });
        env2.Vars["big"] = Node.List(new List<Node> { Node.Str("a"), Node.Str("b"), Node.Str("c") });
        Assert.False(EvalExpr("(subset? big small)", env2));
    }

    [Fact]
    public void Before()
    {
        Assert.True(EvalExpr("(before now \"2026-01-01T00:00:00Z\")"));
        Assert.False(EvalExpr("(before now \"2025-01-01T00:00:00Z\")"));
    }

    [Fact] public void Get() => Assert.True(EvalExpr("(= (get req \"actor_pub\") \"K_ai\")"));
    [Fact] public void CryptoStubs() { Assert.True(EvalExpr("(dpop_ok?)")); Assert.True(EvalExpr("(thresh_ok?)")); }
    [Fact] public void UnknownOp() => Assert.Throws<SplException>(() => EvalExpr("(bogus 1 2)"));

    // --- Gas budget tests ---
    [Fact]
    public void GasBudgetExceeded()
    {
        var env = MakeEnv();
        env.MaxGas = 3;
        Assert.Throws<SplException>(() => EvalExpr("(and #t #t #t #t #t #t #t #t)", env));
    }

    [Fact]
    public void GasBudgetSufficient()
    {
        var env = MakeEnv();
        env.MaxGas = 100;
        Assert.True(EvalExpr("(and #t #t)", env));
    }

    // --- Integration tests ---
    [Fact]
    public void FamilyGiftsAllow()
    {
        var policyPath = Path.Combine("..", "..", "..", "..", "..", "..", "examples", "policies", "family_gifts.spl");
        if (!File.Exists(policyPath)) return;
        var ast = Parser.Parse(File.ReadAllText(policyPath).Trim());
        var env = MakeEnv();
        Assert.True(Verifier.Verify(ast, env).Allow);
    }

    [Fact]
    public void FamilyGiftsDeny()
    {
        var policyPath = Path.Combine("..", "..", "..", "..", "..", "..", "examples", "policies", "family_gifts.spl");
        if (!File.Exists(policyPath)) return;
        var ast = Parser.Parse(File.ReadAllText(policyPath).Trim());
        var env = MakeEnv();
        env.Req["amount"] = Node.Num(100.0);
        Assert.False(Verifier.Verify(ast, env).Allow);
    }
}
