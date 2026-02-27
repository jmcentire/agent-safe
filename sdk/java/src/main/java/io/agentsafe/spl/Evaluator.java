package io.agentsafe.spl;

import java.util.ArrayList;
import java.util.List;

/**
 * Tree-walk evaluator for SPL ASTs. All 20 built-ins, gas/depth metering.
 */
public final class Evaluator {
    private static final int MAX_DEPTH = 64;

    private int gas;
    private int depth;
    private final Env env;

    public Evaluator(Env env) {
        this.env = env;
        this.gas = env.maxGas;
        this.depth = 0;
    }

    public Node eval(Node node) {
        gas--;
        if (gas < 0) throw new SplException("gas budget exceeded");
        depth++;
        if (depth > MAX_DEPTH) {
            depth--;
            throw new SplException("max nesting depth exceeded");
        }
        try {
            return evalInner(node);
        } finally {
            depth--;
        }
    }

    private Node evalInner(Node node) {
        return switch (node) {
            case Node.ListNode ln -> {
                List<Node> items = ln.items();
                if (items.isEmpty()) yield Node.nil();
                Node first = items.getFirst();
                if (!(first instanceof Node.SymNode sym))
                    throw new SplException("operator must be a symbol");
                yield evalOp(sym.name(), items.subList(1, items.size()));
            }
            case Node.SymNode sym -> resolveSymbol(sym.name());
            default -> node;
        };
    }

    private Node evalOp(String op, List<Node> args) {
        return switch (op) {
            case "and" -> {
                for (Node a : args) {
                    if (!eval(a).isTruthy()) yield Node.bool_(false);
                }
                yield Node.bool_(true);
            }
            case "or" -> {
                for (Node a : args) {
                    if (eval(a).isTruthy()) yield Node.bool_(true);
                }
                yield Node.bool_(false);
            }
            case "not" -> Node.bool_(!eval(args.getFirst()).isTruthy());
            case "=" -> Node.bool_(Node.nodeEq(eval(args.get(0)), eval(args.get(1))));
            case "<=", "<", ">=", ">" -> {
                double a = eval(args.get(0)).asDouble();
                double b = eval(args.get(1)).asDouble();
                yield Node.bool_(switch (op) {
                    case "<=" -> a <= b;
                    case "<" -> a < b;
                    case ">=" -> a >= b;
                    case ">" -> a > b;
                    default -> false;
                });
            }
            case "member", "in" -> {
                Node val = eval(args.get(0));
                Node lst = eval(args.get(1));
                if (lst instanceof Node.ListNode ln) {
                    yield Node.bool_(ln.items().stream().anyMatch(item -> Node.nodeEq(item, val)));
                }
                yield Node.bool_(false);
            }
            case "subset?" -> {
                Node a = eval(args.get(0));
                Node b = eval(args.get(1));
                if (a instanceof Node.ListNode la && b instanceof Node.ListNode lb) {
                    yield Node.bool_(la.items().stream().allMatch(item ->
                        lb.items().stream().anyMatch(c -> Node.nodeEq(item, c))
                    ));
                }
                yield Node.bool_(false);
            }
            case "before" -> {
                String a = eval(args.get(0)).asString();
                String b = eval(args.get(1)).asString();
                yield Node.bool_(a.compareTo(b) < 0);
            }
            case "get" -> {
                Node keyNode = eval(args.get(1));
                String key = keyNode.asString();
                // Check if first arg is "req"
                if (args.getFirst() instanceof Node.SymNode sym && sym.name().equals("req")) {
                    Node val = env.req.get(key);
                    yield val != null ? val : Node.nil();
                }
                // Otherwise resolve symbol
                if (args.getFirst() instanceof Node.SymNode sym) {
                    Node val = env.vars.get(sym.name());
                    if (val != null) {
                        // Can't get from a list by string key
                        yield Node.nil();
                    }
                }
                yield Node.nil();
            }
            case "tuple" -> {
                List<Node> result = new ArrayList<>();
                for (Node a : args) result.add(eval(a));
                yield Node.list(result);
            }
            case "per-day-count" -> {
                String action = eval(args.get(0)).asString();
                String day = eval(args.get(1)).asString();
                int count = env.perDayCount.apply(action, day);
                yield Node.num(count);
            }
            case "dpop_ok?" -> Node.bool_(env.crypto.dpopOk.get());
            case "merkle_ok?" -> {
                List<Node> evaluated = new ArrayList<>();
                for (Node a : args) evaluated.add(eval(a));
                yield Node.bool_(env.crypto.merkleOk.apply(evaluated));
            }
            case "vrf_ok?" -> {
                String day = eval(args.get(0)).asString();
                double amount = eval(args.get(1)).asDouble();
                yield Node.bool_(env.crypto.vrfOk.apply(day, amount));
            }
            case "thresh_ok?" -> Node.bool_(env.crypto.threshOk.get());
            default -> throw new SplException("Unknown op: " + op);
        };
    }

    private Node resolveSymbol(String name) {
        return switch (name) {
            case "#t" -> Node.bool_(true);
            case "#f" -> Node.bool_(false);
            case "req" -> Node.str("__req__");
            case "now" -> {
                Node v = env.vars.get("now");
                if (v != null) yield v;
                if (env.strict) throw new SplException("Unresolved symbol: " + name);
                yield Node.sym(name);
            }
            default -> {
                Node v = env.vars.get(name);
                if (v != null) yield v;
                if (env.strict) throw new SplException("Unresolved symbol: " + name);
                yield Node.sym(name);
            }
        };
    }
}
