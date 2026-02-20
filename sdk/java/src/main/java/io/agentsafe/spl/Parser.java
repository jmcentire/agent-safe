package io.agentsafe.spl;

import java.util.ArrayList;
import java.util.List;

/**
 * Tokenizer and recursive-descent parser for SPL S-expressions.
 */
public final class Parser {
    private Parser() {}

    public static Node parse(String src) {
        List<String> tokens = tokenize(src.trim());
        if (tokens.isEmpty()) throw new SplException("unexpected EOF");
        int[] pos = {0};
        Node result = parseExpr(tokens, pos);
        if (pos[0] != tokens.size()) throw new SplException("extra tokens");
        return result;
    }

    private static Node parseExpr(List<String> tokens, int[] pos) {
        if (pos[0] >= tokens.size()) throw new SplException("unexpected EOF");
        String tok = tokens.get(pos[0]++);

        if (tok.equals("(")) {
            List<Node> items = new ArrayList<>();
            while (true) {
                if (pos[0] >= tokens.size()) throw new SplException("unterminated (");
                if (tokens.get(pos[0]).equals(")")) {
                    pos[0]++;
                    break;
                }
                items.add(parseExpr(tokens, pos));
            }
            return Node.list(items);
        }
        if (tok.equals(")")) throw new SplException("unexpected )");
        return parseAtom(tok);
    }

    private static Node parseAtom(String tok) {
        if (tok.equals("#t")) return Node.bool_(true);
        if (tok.equals("#f")) return Node.bool_(false);
        // Try number
        try {
            double d = Double.parseDouble(tok);
            return Node.num(d);
        } catch (NumberFormatException ignored) {}
        // Quoted string
        if (tok.startsWith("\"") && tok.endsWith("\"") && tok.length() >= 2) {
            return Node.str(tok.substring(1, tok.length() - 1));
        }
        // Symbol
        return Node.sym(tok);
    }

    static List<String> tokenize(String src) {
        List<String> tokens = new ArrayList<>();
        StringBuilder buf = new StringBuilder();
        boolean inStr = false;

        for (int i = 0; i < src.length(); i++) {
            char ch = src.charAt(i);
            if (inStr) {
                buf.append(ch);
                if (ch == '"') {
                    inStr = false;
                    tokens.add(buf.toString());
                    buf.setLength(0);
                }
                continue;
            }
            switch (ch) {
                case '"' -> {
                    flushBuf(buf, tokens);
                    buf.append('"');
                    inStr = true;
                }
                case '(', ')' -> {
                    flushBuf(buf, tokens);
                    tokens.add(String.valueOf(ch));
                }
                case ' ', '\n', '\t', '\r' -> flushBuf(buf, tokens);
                default -> buf.append(ch);
            }
        }
        flushBuf(buf, tokens);
        return tokens;
    }

    private static void flushBuf(StringBuilder buf, List<String> tokens) {
        String s = buf.toString().trim();
        if (!s.isEmpty()) {
            for (String word : s.split("\\s+")) {
                tokens.add(word);
            }
        }
        buf.setLength(0);
    }
}
