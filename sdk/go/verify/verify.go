package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"github.com/agent-safe-iam/spl/spl"
)

func main(){
	if len(os.Args) < 3 {
		fmt.Println("usage: verify <policy.spl> <request.json>")
		os.Exit(1)
	}
	policyBytes, _ := os.ReadFile(filepath.Clean(os.Args[1]))
	reqBytes, _ := os.ReadFile(filepath.Clean(os.Args[2]))
	var req map[string]any
	json.Unmarshal(reqBytes, &req)

	ast, err := spl.Parse(string(policyBytes))
	if err != nil { panic(err) }

	env := spl.Env{
		Req: req,
		AllowedRecipients: []string{"niece@example.com","mom@example.com"},
		PerDayCount: func(action, day string) int { return 0 },
	}
	env.Crypto.DPoPOk = func() bool { return true }
	env.Crypto.MerkleOk = func(tuple []any) bool { return true }
	env.Crypto.VRFOk = func(day string, amount float64) bool { return true }

	allow, err := spl.Verify(ast, env)
	if err != nil { panic(err) }
	if allow { fmt.Println("ALLOW") } else { fmt.Println("DENY") }
}
