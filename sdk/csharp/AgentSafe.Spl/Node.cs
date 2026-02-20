namespace AgentSafe.Spl;

/// <summary>AST node for SPL S-expressions.</summary>
public abstract record Node
{
    public sealed record BoolNode(bool Value) : Node;
    public sealed record NumNode(double Value) : Node;
    public sealed record StrNode(string Value) : Node;
    public sealed record SymNode(string Name) : Node;
    public sealed record ListNode(List<Node> Items) : Node;
    public sealed record NilNode() : Node;

    public static Node Bool(bool b) => new BoolNode(b);
    public static Node Num(double n) => new NumNode(n);
    public static Node Str(string s) => new StrNode(s);
    public static Node Sym(string s) => new SymNode(s);
    public static Node List(List<Node> items) => new ListNode(items);
    public static Node Nil() => new NilNode();

    public bool IsTruthy() => this switch
    {
        BoolNode b => b.Value,
        NilNode => false,
        NumNode n => n.Value != 0.0,
        _ => true
    };

    public double AsDouble() => this switch
    {
        NumNode n => n.Value,
        _ => 0.0
    };

    public string AsString() => this switch
    {
        StrNode s => s.Value,
        SymNode s => s.Name,
        BoolNode b => b.Value.ToString().ToLower(),
        NumNode n => n.Value.ToString(),
        NilNode => "nil",
        ListNode l => $"({string.Join(" ", l.Items)})",
        _ => ""
    };

    public static bool NodeEq(Node a, Node b)
    {
        if (a is StrNode sa && b is StrNode sb) return sa.Value == sb.Value;
        if (a is SymNode ya && b is SymNode yb) return ya.Name == yb.Name;
        if (a is StrNode s1 && b is SymNode y1) return s1.Value == y1.Name;
        if (a is SymNode y2 && b is StrNode s2) return y2.Name == s2.Value;
        if (a is NumNode na && b is NumNode nb) return na.Value == nb.Value;
        if (a is BoolNode ba && b is BoolNode bb) return ba.Value == bb.Value;
        if (a is NilNode && b is NilNode) return true;
        return a.AsString() == b.AsString();
    }
}
