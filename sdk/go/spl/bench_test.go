package spl

import (
	"testing"
)

const benchPolicy = `(and
  (= (get req "actor_pub") "K_ai")
  (= (get req "action") "payments.create")
  (<= (get req "amount") 50)
  (member (get req "recipient") allowed_recipients)
  (= (get req "purpose") "giftcard")
  (<= (per-day-count "payments.create" (get req "day")) 1)
  (get req "device_attested")
  (dpop_ok?)
  (merkle_ok? (tuple (get req "actor_pub") (get req "action") (get req "recipient") 50 "giftcard" (get req "day")))
  (vrf_ok? (get req "day") (get req "amount"))
)`

func benchEnv() Env {
	return Env{
		Req: map[string]any{
			"actor_pub":       "K_ai",
			"action":          "payments.create",
			"amount":          50.0,
			"recipient":       "niece@example.com",
			"purpose":         "giftcard",
			"day":             "2025-01-15",
			"device_attested": true,
		},
		Vars: map[string]any{
			"allowed_recipients": []any{"niece@example.com", "mom@example.com"},
			"now":                "2025-06-01T00:00:00Z",
		},
		PerDayCount: func(action, day string) int { return 0 },
		Crypto: struct {
			DPoPOk   func() bool
			MerkleOk func(tuple []any) bool
			VRFOk    func(day string, amount float64) bool
			ThreshOk func() bool
		}{
			DPoPOk:   func() bool { return true },
			MerkleOk: func(tuple []any) bool { return true },
			VRFOk:    func(day string, amount float64) bool { return true },
			ThreshOk: func() bool { return true },
		},
	}
}

func BenchmarkParseAndEval(b *testing.B) {
	env := benchEnv()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ast, err := Parse(benchPolicy)
		if err != nil {
			b.Fatal(err)
		}
		_, err = Verify(ast, env)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEvalOnly(b *testing.B) {
	ast, err := Parse(benchPolicy)
	if err != nil {
		b.Fatal(err)
	}
	env := benchEnv()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err = Verify(ast, env)
		if err != nil {
			b.Fatal(err)
		}
	}
}
