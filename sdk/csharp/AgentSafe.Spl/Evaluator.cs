namespace AgentSafe.Spl;

public class Evaluator
{
    private const int MaxDepth = 64;
    private int _gas;
    private int _depth;
    private readonly Env _env;

    public Evaluator(Env env)
    {
        _env = env;
        _gas = env.MaxGas;
        _depth = 0;
    }

    public Node Eval(Node node)
    {
        _gas--;
        if (_gas < 0) throw new SplException("gas budget exceeded");
        _depth++;
        if (_depth > MaxDepth)
        {
            _depth--;
            throw new SplException("max nesting depth exceeded");
        }
        try
        {
            return EvalInner(node);
        }
        finally
        {
            _depth--;
        }
    }

    private Node EvalInner(Node node) => node switch
    {
        Node.ListNode ln when ln.Items.Count == 0 => Node.Nil(),
        Node.ListNode ln => ln.Items[0] is Node.SymNode sym
            ? EvalOp(sym.Name, ln.Items.GetRange(1, ln.Items.Count - 1))
            : throw new SplException("operator must be a symbol"),
        Node.SymNode sym => ResolveSymbol(sym.Name),
        _ => node
    };

    private Node EvalOp(string op, List<Node> args) => op switch
    {
        "and" => EvalAnd(args),
        "or" => EvalOr(args),
        "not" => Node.Bool(!Eval(args[0]).IsTruthy()),
        "=" => Node.Bool(Node.NodeEq(Eval(args[0]), Eval(args[1]))),
        "<=" or "<" or ">=" or ">" => EvalCmp(op, args),
        "member" or "in" => EvalMember(args),
        "subset?" => EvalSubset(args),
        "before" => Node.Bool(string.Compare(Eval(args[0]).AsString(), Eval(args[1]).AsString(), StringComparison.Ordinal) < 0),
        "get" => EvalGet(args),
        "tuple" => Node.List(args.Select(a => Eval(a)).ToList()),
        "per-day-count" => Node.Num(_env.PerDayCount(Eval(args[0]).AsString(), Eval(args[1]).AsString())),
        "dpop_ok?" => Node.Bool(_env.Crypto.DpopOk()),
        "merkle_ok?" => Node.Bool(_env.Crypto.MerkleOk(args.Select(a => Eval(a)).ToList())),
        "vrf_ok?" => Node.Bool(_env.Crypto.VrfOk(Eval(args[0]).AsString(), Eval(args[1]).AsDouble())),
        "thresh_ok?" => Node.Bool(_env.Crypto.ThreshOk()),
        _ => throw new SplException($"Unknown op: {op}")
    };

    private Node EvalAnd(List<Node> args)
    {
        foreach (var a in args)
            if (!Eval(a).IsTruthy()) return Node.Bool(false);
        return Node.Bool(true);
    }

    private Node EvalOr(List<Node> args)
    {
        foreach (var a in args)
            if (Eval(a).IsTruthy()) return Node.Bool(true);
        return Node.Bool(false);
    }

    private Node EvalCmp(string op, List<Node> args)
    {
        var a = Eval(args[0]).AsDouble();
        var b = Eval(args[1]).AsDouble();
        return Node.Bool(op switch
        {
            "<=" => a <= b,
            "<" => a < b,
            ">=" => a >= b,
            ">" => a > b,
            _ => false
        });
    }

    private Node EvalMember(List<Node> args)
    {
        var val = Eval(args[0]);
        var lst = Eval(args[1]);
        if (lst is Node.ListNode ln)
            return Node.Bool(ln.Items.Any(item => Node.NodeEq(item, val)));
        return Node.Bool(false);
    }

    private Node EvalSubset(List<Node> args)
    {
        var a = Eval(args[0]);
        var b = Eval(args[1]);
        if (a is Node.ListNode la && b is Node.ListNode lb)
            return Node.Bool(la.Items.All(item => lb.Items.Any(c => Node.NodeEq(item, c))));
        return Node.Bool(false);
    }

    private Node EvalGet(List<Node> args)
    {
        var key = Eval(args[1]).AsString();
        if (args[0] is Node.SymNode sym && sym.Name == "req")
            return _env.Req.TryGetValue(key, out var v) ? v : Node.Nil();
        if (args[0] is Node.SymNode sym2 && _env.Vars.ContainsKey(sym2.Name))
            return Node.Nil(); // Can't get from a list by string key
        return Node.Nil();
    }

    private Node ResolveSymbol(string name) => name switch
    {
        "#t" => Node.Bool(true),
        "#f" => Node.Bool(false),
        "req" => Node.Str("__req__"),
        "now" => _env.Vars.TryGetValue("now", out var v) ? v
            : _env.Strict ? throw new SplException($"Unresolved symbol: {name}")
            : Node.Sym(name),
        _ => _env.Vars.TryGetValue(name, out var val) ? val
            : _env.Strict ? throw new SplException($"Unresolved symbol: {name}")
            : Node.Sym(name)
    };
}
