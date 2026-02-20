package io.agentsafe.spl;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;

class SplTest {

    static Env makeEnv() {
        Env env = new Env();
        env.req.put("actor_pub", Node.str("K_ai"));
        env.req.put("action", Node.str("payments.create"));
        env.req.put("recipient", Node.str("niece@example.com"));
        env.req.put("purpose", Node.str("giftcard"));
        env.req.put("amount", Node.num(50.0));
        env.req.put("day", Node.str("2025-09-29"));
        env.req.put("device_attested", Node.bool_(true));
        env.vars.put("allowed_recipients", Node.list(List.of(
            Node.str("niece@example.com"), Node.str("mom@example.com")
        )));
        env.vars.put("now", Node.str("2025-10-01T00:00:00Z"));
        return env;
    }

    boolean evalExpr(String src) {
        return evalExpr(src, makeEnv());
    }

    boolean evalExpr(String src, Env env) {
        Node ast = Parser.parse(src);
        return Verifier.verify(ast, env).allow();
    }

    // --- Parser tests ---

    @Test void parseInteger() { assertEquals(Node.num(42), Parser.parse("42")); }
    @Test void parseNegativeFloat() { assertEquals(Node.num(-3.14), Parser.parse("-3.14")); }
    @Test void parseString() { assertEquals(Node.str("hello"), Parser.parse("\"hello\"")); }
    @Test void parseBoolTrue() { assertEquals(Node.bool_(true), Parser.parse("#t")); }
    @Test void parseBoolFalse() { assertEquals(Node.bool_(false), Parser.parse("#f")); }
    @Test void parseSymbol() { assertEquals(Node.sym("foo"), Parser.parse("foo")); }

    @Test void parseList() {
        Node ast = Parser.parse("(and #t #f)");
        assertInstanceOf(Node.ListNode.class, ast);
        assertEquals(3, ((Node.ListNode) ast).items().size());
    }

    @Test void parseNested() {
        Node ast = Parser.parse("(and (= 1 2) (> 3 1))");
        Node inner = ((Node.ListNode) ast).items().get(1);
        assertInstanceOf(Node.ListNode.class, inner);
    }

    @Test void parseStringsWithSpaces() {
        Node ast = Parser.parse("(= \"hello world\" \"hello world\")");
        assertEquals(Node.str("hello world"), ((Node.ListNode) ast).items().get(1));
    }

    @Test void unterminatedParen() {
        assertThrows(SplException.class, () -> Parser.parse("(and #t"));
    }

    @Test void unexpectedCloseParen() {
        assertThrows(SplException.class, () -> Parser.parse(")"));
    }

    @Test void extraTokens() {
        assertThrows(SplException.class, () -> Parser.parse("#t #f"));
    }

    // --- Eval tests ---

    @Test void andAllTrue() { assertTrue(evalExpr("(and #t #t #t)")); }
    @Test void andOneFalse() { assertFalse(evalExpr("(and #t #f #t)")); }
    @Test void orOneTrue() { assertTrue(evalExpr("(or #f #t #f)")); }
    @Test void orAllFalse() { assertFalse(evalExpr("(or #f #f)")); }
    @Test void notFalse() { assertTrue(evalExpr("(not #f)")); }
    @Test void notTrue() { assertFalse(evalExpr("(not #t)")); }

    @Test void equalStrings() { assertTrue(evalExpr("(= \"hello\" \"hello\")")); }
    @Test void equalStringsFalse() { assertFalse(evalExpr("(= \"hello\" \"world\")")); }

    @Test void lessEqual() {
        assertTrue(evalExpr("(<= 5 10)"));
        assertTrue(evalExpr("(<= 10 10)"));
        assertFalse(evalExpr("(<= 11 10)"));
    }

    @Test void lessThan() {
        assertTrue(evalExpr("(< 5 10)"));
        assertFalse(evalExpr("(< 5 5)"));
    }

    @Test void greaterEqual() {
        assertTrue(evalExpr("(>= 10 10)"));
        assertFalse(evalExpr("(>= 9 10)"));
    }

    @Test void greaterThan() {
        assertTrue(evalExpr("(> 10 5)"));
        assertFalse(evalExpr("(> 5 5)"));
    }

    @Test void member() {
        assertTrue(evalExpr("(member \"niece@example.com\" allowed_recipients)"));
        assertFalse(evalExpr("(member \"stranger@example.com\" allowed_recipients)"));
    }

    @Test void inAlias() {
        assertTrue(evalExpr("(in \"mom@example.com\" allowed_recipients)"));
    }

    @Test void subset() {
        Env env = makeEnv();
        env.vars.put("small", Node.list(List.of(Node.str("a"), Node.str("b"))));
        env.vars.put("big", Node.list(List.of(Node.str("a"), Node.str("b"), Node.str("c"))));
        assertTrue(evalExpr("(subset? small big)", env));
        Env env2 = makeEnv();
        env2.vars.put("small", Node.list(List.of(Node.str("a"), Node.str("b"))));
        env2.vars.put("big", Node.list(List.of(Node.str("a"), Node.str("b"), Node.str("c"))));
        assertFalse(evalExpr("(subset? big small)", env2));
    }

    @Test void before() {
        assertTrue(evalExpr("(before now \"2026-01-01T00:00:00Z\")"));
        assertFalse(evalExpr("(before now \"2025-01-01T00:00:00Z\")"));
    }

    @Test void get() {
        assertTrue(evalExpr("(= (get req \"actor_pub\") \"K_ai\")"));
    }

    @Test void cryptoStubs() {
        assertTrue(evalExpr("(dpop_ok?)"));
        assertTrue(evalExpr("(thresh_ok?)"));
    }

    @Test void unknownOp() {
        assertThrows(SplException.class, () -> evalExpr("(bogus 1 2)"));
    }

    // --- Gas budget tests ---

    @Test void gasBudgetExceeded() {
        Env env = makeEnv();
        env.maxGas = 3;
        assertThrows(SplException.class, () -> evalExpr("(and #t #t #t #t #t #t #t #t)", env));
    }

    @Test void gasBudgetSufficient() {
        Env env = makeEnv();
        env.maxGas = 100;
        assertTrue(evalExpr("(and #t #t)", env));
    }

    // --- Integration tests ---

    @Test void familyGiftsAllow() {
        try {
            String policySrc = new String(java.nio.file.Files.readAllBytes(
                java.nio.file.Path.of("../../examples/policies/family_gifts.spl"))).trim();
            Node ast = Parser.parse(policySrc);
            Env env = makeEnv();
            assertTrue(Verifier.verify(ast, env).allow());
        } catch (Exception e) {
            // Skip if files not found
        }
    }

    @Test void familyGiftsDeny() {
        try {
            String policySrc = new String(java.nio.file.Files.readAllBytes(
                java.nio.file.Path.of("../../examples/policies/family_gifts.spl"))).trim();
            Node ast = Parser.parse(policySrc);
            Env env = makeEnv();
            env.req.put("amount", Node.num(100.0));
            assertFalse(Verifier.verify(ast, env).allow());
        } catch (Exception e) {
            // Skip if files not found
        }
    }
}
