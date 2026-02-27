package spl

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// --- Parser tests ---

func TestParseNumber(t *testing.T) {
	n, err := Parse("42")
	if err != nil {
		t.Fatal(err)
	}
	if n != 42.0 {
		t.Fatalf("expected 42, got %v", n)
	}
}

func TestParseNegativeNumber(t *testing.T) {
	n, err := Parse("-3.14")
	if err != nil {
		t.Fatal(err)
	}
	if n != -3.14 {
		t.Fatalf("expected -3.14, got %v", n)
	}
}

func TestParseString(t *testing.T) {
	n, err := Parse(`"hello"`)
	if err != nil {
		t.Fatal(err)
	}
	if n != "hello" {
		t.Fatalf("expected hello, got %v", n)
	}
}

func TestParseBoolTrue(t *testing.T) {
	n, err := Parse("#t")
	if err != nil {
		t.Fatal(err)
	}
	if n != true {
		t.Fatalf("expected true, got %v", n)
	}
}

func TestParseBoolFalse(t *testing.T) {
	n, err := Parse("#f")
	if err != nil {
		t.Fatal(err)
	}
	if n != false {
		t.Fatalf("expected false, got %v", n)
	}
}

func TestParseSymbol(t *testing.T) {
	n, err := Parse("foo")
	if err != nil {
		t.Fatal(err)
	}
	if n != "foo" {
		t.Fatalf("expected foo, got %v", n)
	}
}

func TestParseList(t *testing.T) {
	n, err := Parse(`(and #t #f)`)
	if err != nil {
		t.Fatal(err)
	}
	arr, ok := n.([]Node)
	if !ok {
		t.Fatalf("expected list, got %T", n)
	}
	if len(arr) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(arr))
	}
	if arr[0] != "and" {
		t.Fatalf("expected and, got %v", arr[0])
	}
}

func TestParseNested(t *testing.T) {
	n, err := Parse(`(and (= 1 2) (> 3 1))`)
	if err != nil {
		t.Fatal(err)
	}
	arr := n.([]Node)
	if len(arr) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(arr))
	}
	inner := arr[1].([]Node)
	if inner[0] != "=" {
		t.Fatalf("expected =, got %v", inner[0])
	}
}

func TestParseUnterminatedParen(t *testing.T) {
	_, err := Parse("(and #t")
	if err == nil {
		t.Fatal("expected error for unterminated (")
	}
}

func TestParseUnexpectedCloseParen(t *testing.T) {
	_, err := Parse(")")
	if err == nil {
		t.Fatal("expected error for unexpected )")
	}
}

func TestParseEmptyInput(t *testing.T) {
	_, err := Parse("")
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestParseStringWithSpaces(t *testing.T) {
	n, err := Parse(`(= "hello world" "hello world")`)
	if err != nil {
		t.Fatal(err)
	}
	arr := n.([]Node)
	if arr[1] != "hello world" {
		t.Fatalf("expected 'hello world', got %v", arr[1])
	}
}

// --- Eval tests ---

func makeEnv() Env {
	env := Env{
		Req: map[string]any{
			"actor_pub":       "K_ai",
			"action":          "payments.create",
			"recipient":       "niece@example.com",
			"purpose":         "giftcard",
			"amount":          50.0,
			"day":             "2025-09-29",
			"device_attested": true,
		},
		Vars: map[string]any{
			"allowed_recipients": []any{"niece@example.com", "mom@example.com"},
			"now":                "2025-10-01T00:00:00Z",
		},
		PerDayCount: func(action, day string) int { return 0 },
	}
	env.Crypto.DPoPOk = func() bool { return true }
	env.Crypto.MerkleOk = func(tuple []any) bool { return true }
	env.Crypto.VRFOk = func(day string, amount float64) bool { return true }
	env.Crypto.ThreshOk = func() bool { return true }
	return env
}

func evalExpr(t *testing.T, src string, env Env) (bool, error) {
	t.Helper()
	ast, err := Parse(src)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	return Verify(ast, env)
}

func TestEvalAndTrue(t *testing.T) {
	ok, err := evalExpr(t, "(and #t #t #t)", makeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestEvalAndFalse(t *testing.T) {
	ok, err := evalExpr(t, "(and #t #f #t)", makeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected false")
	}
}

func TestEvalOrTrue(t *testing.T) {
	ok, err := evalExpr(t, "(or #f #t #f)", makeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestEvalOrFalse(t *testing.T) {
	ok, err := evalExpr(t, "(or #f #f)", makeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected false")
	}
}

func TestEvalNot(t *testing.T) {
	ok, err := evalExpr(t, "(not #f)", makeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestEvalEqual(t *testing.T) {
	ok, err := evalExpr(t, `(= "hello" "hello")`, makeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestEvalEqualFalse(t *testing.T) {
	ok, err := evalExpr(t, `(= "hello" "world")`, makeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected false")
	}
}

func TestEvalLessEqual(t *testing.T) {
	ok, err := evalExpr(t, "(<= 5 10)", makeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestEvalLessThan(t *testing.T) {
	ok, err := evalExpr(t, "(< 5 5)", makeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected false for 5 < 5")
	}
}

func TestEvalGreaterEqual(t *testing.T) {
	ok, err := evalExpr(t, "(>= 10 10)", makeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestEvalGreaterThan(t *testing.T) {
	ok, err := evalExpr(t, "(> 10 5)", makeEnv())
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestEvalMember(t *testing.T) {
	env := makeEnv()
	ok, err := evalExpr(t, `(member "niece@example.com" allowed_recipients)`, env)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestEvalMemberFalse(t *testing.T) {
	env := makeEnv()
	ok, err := evalExpr(t, `(member "stranger@example.com" allowed_recipients)`, env)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected false")
	}
}

func TestEvalIn(t *testing.T) {
	env := makeEnv()
	ok, err := evalExpr(t, `(in "mom@example.com" allowed_recipients)`, env)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestEvalSubsetTrue(t *testing.T) {
	env := makeEnv()
	env.Vars["small"] = []any{"a", "b"}
	env.Vars["big"] = []any{"a", "b", "c"}
	ok, err := evalExpr(t, `(subset? small big)`, env)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestEvalSubsetFalse(t *testing.T) {
	env := makeEnv()
	env.Vars["small"] = []any{"a", "d"}
	env.Vars["big"] = []any{"a", "b", "c"}
	ok, err := evalExpr(t, `(subset? small big)`, env)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected false")
	}
}

func TestEvalBefore(t *testing.T) {
	env := makeEnv()
	ok, err := evalExpr(t, `(before now "2026-01-01T00:00:00Z")`, env)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true: now is before 2026-01-01")
	}
}

func TestEvalBeforeFalse(t *testing.T) {
	env := makeEnv()
	ok, err := evalExpr(t, `(before now "2025-01-01T00:00:00Z")`, env)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected false: now is after 2025-01-01")
	}
}

func TestEvalGet(t *testing.T) {
	env := makeEnv()
	ok, err := evalExpr(t, `(= (get req "actor_pub") "K_ai")`, env)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

func TestEvalPerDayCount(t *testing.T) {
	env := makeEnv()
	ok, err := evalExpr(t, `(<= (per-day-count "payments.create" "2025-09-29") 1)`, env)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true: count 0 <= 1")
	}
}

func TestEvalCryptoStubs(t *testing.T) {
	env := makeEnv()
	for _, expr := range []string{
		"(dpop_ok?)",
		`(merkle_ok? (tuple "a" "b"))`,
		`(vrf_ok? "2025-09-29" 50)`,
		"(thresh_ok?)",
	} {
		ok, err := evalExpr(t, expr, env)
		if err != nil {
			t.Fatalf("expr %q: %v", expr, err)
		}
		if !ok {
			t.Fatalf("expr %q: expected true", expr)
		}
	}
}

func TestEvalUnknownOp(t *testing.T) {
	env := makeEnv()
	_, err := evalExpr(t, `(bogus 1 2)`, env)
	if err == nil {
		t.Fatal("expected error for unknown op")
	}
	if !strings.Contains(err.Error(), "unknown op") {
		t.Fatalf("expected 'unknown op' error, got: %v", err)
	}
}

// --- Gas budget tests ---

func TestGasBudgetExceeded(t *testing.T) {
	env := makeEnv()
	env.MaxGas = 5
	// This policy has more operations than the gas budget
	_, err := evalExpr(t, "(and #t #t #t #t #t #t #t #t #t #t)", env)
	if err == nil {
		t.Fatal("expected gas budget exceeded error")
	}
	if !strings.Contains(err.Error(), "gas budget exceeded") {
		t.Fatalf("expected 'gas budget exceeded', got: %v", err)
	}
}

func TestGasBudgetSufficient(t *testing.T) {
	env := makeEnv()
	env.MaxGas = 100
	ok, err := evalExpr(t, "(and #t #t)", env)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected true")
	}
}

// --- Error propagation tests ---

func TestErrorPropagationInAnd(t *testing.T) {
	env := makeEnv()
	_, err := evalExpr(t, `(and #t (bogus))`, env)
	if err == nil {
		t.Fatal("expected error to propagate through and")
	}
}

func TestErrorPropagationInOr(t *testing.T) {
	env := makeEnv()
	_, err := evalExpr(t, `(or #f (bogus))`, env)
	if err == nil {
		t.Fatal("expected error to propagate through or")
	}
}

func TestErrorPropagationInGet(t *testing.T) {
	env := makeEnv()
	// get with non-map first arg should return nil, not panic
	ok, err := evalExpr(t, `(= (get "notamap" "key") "value")`, env)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected false")
	}
}

// --- Fail-closed crypto defaults ---

func TestCryptoDefaultsFailClosed(t *testing.T) {
	// Env with NO crypto callbacks set — should default to false
	env := Env{
		Req:         map[string]any{},
		Vars:        map[string]any{},
		PerDayCount: func(_, _ string) int { return 0 },
	}
	ok, err := evalExpr(t, "(dpop_ok?)", env)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected false: crypto defaults should be fail-closed")
	}
}

// --- Strict mode tests ---

func TestStrictModeRejectsUnresolved(t *testing.T) {
	env := makeEnv()
	env.Strict = true
	_, err := evalExpr(t, `(= "foo" unbound_var)`, env)
	if err == nil {
		t.Fatal("expected error for unresolved symbol in strict mode")
	}
	if !strings.Contains(err.Error(), "unresolved symbol") {
		t.Fatalf("expected 'unresolved symbol' error, got: %v", err)
	}
}

func TestNonStrictAllowsUnresolved(t *testing.T) {
	env := makeEnv()
	ok, err := evalExpr(t, `(= "foo" unbound_var)`, env)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected false: unresolved symbol should not match string")
	}
}

// --- Type-aware equality tests ---

func TestEqualityTypeAware(t *testing.T) {
	env := makeEnv()
	// Number 50 should NOT equal string "50"
	env.Vars["str_fifty"] = "50"
	ok, err := evalExpr(t, `(= 50 str_fifty)`, env)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected false: number 50 should not equal string '50'")
	}
}

// --- Integration test ---

func TestFamilyGiftsPolicy(t *testing.T) {
	policyBytes, err := os.ReadFile("../../../examples/policies/family_gifts.spl")
	if err != nil {
		t.Skipf("skipping integration test: %v", err)
	}
	reqBytes, err := os.ReadFile("../../../examples/requests/gift_50_niece.json")
	if err != nil {
		t.Skipf("skipping integration test: %v", err)
	}

	ast, err := Parse(string(policyBytes))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	var req map[string]any
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		t.Fatalf("json error: %v", err)
	}

	env := makeEnv()
	env.Req = req

	allow, err := Verify(ast, env)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if !allow {
		t.Fatal("expected ALLOW for gift_50_niece")
	}
}

func TestFamilyGiftsDeny(t *testing.T) {
	policyBytes, err := os.ReadFile("../../../examples/policies/family_gifts.spl")
	if err != nil {
		t.Skipf("skipping integration test: %v", err)
	}
	reqBytes, err := os.ReadFile("../../../examples/requests/gift_50_niece.json")
	if err != nil {
		t.Skipf("skipping integration test: %v", err)
	}

	ast, err := Parse(string(policyBytes))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	var req map[string]any
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		t.Fatalf("json error: %v", err)
	}

	// Change amount to exceed limit
	req["amount"] = 100.0

	env := makeEnv()
	env.Req = req

	allow, err := Verify(ast, env)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}
	if allow {
		t.Fatal("expected DENY for amount=100")
	}
}
