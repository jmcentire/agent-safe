package io.agentsafe.spl;

import java.util.List;
import java.util.Objects;

/**
 * AST node for SPL S-expressions. Sealed interface with record variants.
 */
public sealed interface Node {
    record BoolNode(boolean value) implements Node {}
    record NumNode(double value) implements Node {}
    record StrNode(String value) implements Node {}
    record SymNode(String name) implements Node {}
    record ListNode(List<Node> items) implements Node {}
    record NilNode() implements Node {}

    static Node bool_(boolean b) { return new BoolNode(b); }
    static Node num(double n) { return new NumNode(n); }
    static Node str(String s) { return new StrNode(s); }
    static Node sym(String s) { return new SymNode(s); }
    static Node list(List<Node> items) { return new ListNode(items); }
    static Node nil() { return new NilNode(); }

    default boolean isTruthy() {
        return switch (this) {
            case BoolNode b -> b.value();
            case NilNode n -> false;
            case NumNode n -> n.value() != 0.0;
            default -> true;
        };
    }

    default double asDouble() {
        return switch (this) {
            case NumNode n -> n.value();
            default -> 0.0;
        };
    }

    default String asString() {
        return switch (this) {
            case StrNode s -> s.value();
            case SymNode s -> s.name();
            case BoolNode b -> String.valueOf(b.value());
            case NumNode n -> String.valueOf(n.value());
            case NilNode ignored -> "nil";
            case ListNode l -> l.toString();
        };
    }

    static boolean nodeEq(Node a, Node b) {
        if (a instanceof StrNode s1 && b instanceof StrNode s2) return s1.value().equals(s2.value());
        if (a instanceof SymNode s1 && b instanceof SymNode s2) return s1.name().equals(s2.name());
        if (a instanceof StrNode s && b instanceof SymNode y) return s.value().equals(y.name());
        if (a instanceof SymNode s && b instanceof StrNode y) return s.name().equals(y.value());
        if (a instanceof NumNode n1 && b instanceof NumNode n2) return n1.value() == n2.value();
        if (a instanceof BoolNode b1 && b instanceof BoolNode b2) return b1.value() == b2.value();
        if (a instanceof NilNode && b instanceof NilNode) return true;
        return a.asString().equals(b.asString());
    }
}
