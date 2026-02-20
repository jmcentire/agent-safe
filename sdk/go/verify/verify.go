package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jmcentire/agent-safe/sdk/go/spl"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: verify <policy.spl> <request.json>")
		os.Exit(1)
	}
	policyBytes, err := os.ReadFile(filepath.Clean(os.Args[1]))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading policy: %v\n", err)
		os.Exit(1)
	}
	reqBytes, err := os.ReadFile(filepath.Clean(os.Args[2]))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading request: %v\n", err)
		os.Exit(1)
	}
	var req map[string]any
	if err := json.Unmarshal(reqBytes, &req); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing request JSON: %v\n", err)
		os.Exit(1)
	}

	ast, err := spl.Parse(string(policyBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing policy: %v\n", err)
		os.Exit(1)
	}

	env := spl.Env{
		Req: req,
		Vars: map[string]any{
			"allowed_recipients": []any{"niece@example.com", "mom@example.com"},
		},
		PerDayCount: func(action, day string) int { return 0 },
	}
	env.Crypto.DPoPOk = func() bool { return true }
	env.Crypto.MerkleOk = func(tuple []any) bool { return true }
	env.Crypto.VRFOk = func(day string, amount float64) bool { return true }
	env.Crypto.ThreshOk = func() bool { return true }

	allow, err := spl.Verify(ast, env)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error evaluating policy: %v\n", err)
		os.Exit(1)
	}
	if allow {
		fmt.Println("ALLOW")
	} else {
		fmt.Println("DENY")
	}
}
