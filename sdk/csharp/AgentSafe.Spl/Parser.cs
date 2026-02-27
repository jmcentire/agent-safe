namespace AgentSafe.Spl;

public static class Parser
{
    private const int MaxPolicyBytes = 65536; // 64 KB

    public static Node Parse(string src)
    {
        if (System.Text.Encoding.UTF8.GetByteCount(src) > MaxPolicyBytes)
            throw new SplException($"policy exceeds maximum size of {MaxPolicyBytes} bytes");
        var tokens = Tokenize(src.Trim());
        if (tokens.Count == 0) throw new SplException("unexpected EOF");
        var pos = new int[] { 0 };
        var result = ParseExpr(tokens, pos);
        if (pos[0] != tokens.Count) throw new SplException("extra tokens");
        return result;
    }

    private static Node ParseExpr(List<string> tokens, int[] pos)
    {
        if (pos[0] >= tokens.Count) throw new SplException("unexpected EOF");
        var tok = tokens[pos[0]++];

        if (tok == "(")
        {
            var items = new List<Node>();
            while (true)
            {
                if (pos[0] >= tokens.Count) throw new SplException("unterminated (");
                if (tokens[pos[0]] == ")")
                {
                    pos[0]++;
                    break;
                }
                items.Add(ParseExpr(tokens, pos));
            }
            return Node.List(items);
        }
        if (tok == ")") throw new SplException("unexpected )");
        return ParseAtom(tok);
    }

    private static Node ParseAtom(string tok)
    {
        if (tok == "#t") return Node.Bool(true);
        if (tok == "#f") return Node.Bool(false);
        if (double.TryParse(tok, System.Globalization.NumberStyles.Any,
            System.Globalization.CultureInfo.InvariantCulture, out var d))
            return Node.Num(d);
        if (tok.StartsWith('"') && tok.EndsWith('"') && tok.Length >= 2)
            return Node.Str(tok[1..^1]);
        return Node.Sym(tok);
    }

    private static List<string> Tokenize(string src)
    {
        var tokens = new List<string>();
        var buf = new System.Text.StringBuilder();
        bool inStr = false;

        foreach (var ch in src)
        {
            if (inStr)
            {
                buf.Append(ch);
                if (ch == '"')
                {
                    inStr = false;
                    tokens.Add(buf.ToString());
                    buf.Clear();
                }
                continue;
            }

            switch (ch)
            {
                case '"':
                    FlushBuf(buf, tokens);
                    buf.Append('"');
                    inStr = true;
                    break;
                case '(' or ')':
                    FlushBuf(buf, tokens);
                    tokens.Add(ch.ToString());
                    break;
                case ' ' or '\n' or '\t' or '\r':
                    FlushBuf(buf, tokens);
                    break;
                default:
                    buf.Append(ch);
                    break;
            }
        }
        FlushBuf(buf, tokens);
        return tokens;
    }

    private static void FlushBuf(System.Text.StringBuilder buf, List<string> tokens)
    {
        var s = buf.ToString().Trim();
        if (s.Length > 0)
        {
            foreach (var word in s.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                tokens.Add(word);
        }
        buf.Clear();
    }
}
