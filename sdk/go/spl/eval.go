package spl

import (
	"fmt"
)

type Env struct {
	Req    map[string]any
	Vars   map[string]any
	Gas    int
	MaxGas int
	Depth  int
	Sealed bool
	Strict bool

	PerDayCount func(action, day string) int
	Crypto      struct {
		DPoPOk    func() bool
		MerkleOk  func(tuple []any) bool
		VRFOk     func(day string, amount float64) bool
		ThreshOk  func() bool
	}
}

const DefaultMaxGas = 10000
const MaxDepth = 64

func Verify(ast Node, env Env) (bool, error) {
	if env.Sealed {
		return false, fmt.Errorf("token is sealed and cannot be attenuated")
	}
	if env.MaxGas == 0 {
		env.MaxGas = DefaultMaxGas
	}
	env.Gas = env.MaxGas
	// Ensure crypto callbacks are never nil (fail-closed defaults)
	if env.Crypto.DPoPOk == nil {
		env.Crypto.DPoPOk = func() bool { return false }
	}
	if env.Crypto.MerkleOk == nil {
		env.Crypto.MerkleOk = func(_ []any) bool { return false }
	}
	if env.Crypto.VRFOk == nil {
		env.Crypto.VRFOk = func(_ string, _ float64) bool { return false }
	}
	if env.Crypto.ThreshOk == nil {
		env.Crypto.ThreshOk = func() bool { return false }
	}
	val, err := eval(ast, &env)
	if err != nil {
		return false, err
	}
	b, ok := val.(bool)
	if !ok {
		return false, fmt.Errorf("policy did not return boolean")
	}
	return b, nil
}

func eval(n Node, env *Env) (any, error) {
	env.Gas--
	if env.Gas < 0 {
		return nil, fmt.Errorf("gas budget exceeded")
	}
	env.Depth++
	if env.Depth > MaxDepth {
		env.Depth--
		return nil, fmt.Errorf("max nesting depth exceeded")
	}
	defer func() { env.Depth-- }()

	switch v := n.(type) {
	case []Node:
		if len(v) == 0 {
			return nil, nil
		}
		op, ok := v[0].(string)
		if !ok {
			return nil, fmt.Errorf("operator must be a symbol")
		}
		switch op {
		case "and":
			for _, a := range v[1:] {
				res, err := eval(a, env)
				if err != nil {
					return nil, err
				}
				if !truthy(res) {
					return false, nil
				}
			}
			return true, nil
		case "or":
			for _, a := range v[1:] {
				res, err := eval(a, env)
				if err != nil {
					return nil, err
				}
				if truthy(res) {
					return true, nil
				}
			}
			return false, nil
		case "not":
			if len(v) < 2 {
				return nil, fmt.Errorf("not requires 1 argument")
			}
			res, err := eval(v[1], env)
			if err != nil {
				return nil, err
			}
			return !truthy(res), nil
		case "=":
			if len(v) < 3 {
				return nil, fmt.Errorf("= requires 2 arguments")
			}
			a, err := eval(v[1], env)
			if err != nil {
				return nil, err
			}
			b, err := eval(v[2], env)
			if err != nil {
				return nil, err
			}
			return eq(a, b), nil
		case "<=", "<", ">=", ">":
			if len(v) < 3 {
				return nil, fmt.Errorf("%s requires 2 arguments", op)
			}
			return cmp(v[1:], env, op)
		case "member", "in":
			if len(v) < 3 {
				return nil, fmt.Errorf("%s requires 2 arguments", op)
			}
			x, err := eval(v[1], env)
			if err != nil {
				return nil, err
			}
			lst, err := eval(v[2], env)
			if err != nil {
				return nil, err
			}
			if arr, ok := lst.([]any); ok {
				for _, e := range arr {
					if eq(e, x) {
						return true, nil
					}
				}
			}
			return false, nil
		case "subset?":
			if len(v) < 3 {
				return nil, fmt.Errorf("subset? requires 2 arguments")
			}
			a, err := eval(v[1], env)
			if err != nil {
				return nil, err
			}
			b, err := eval(v[2], env)
			if err != nil {
				return nil, err
			}
			listA, okA := a.([]any)
			listB, okB := b.([]any)
			if !okA || !okB {
				return false, nil
			}
			for _, item := range listA {
				found := false
				for _, candidate := range listB {
					if eq(item, candidate) {
						found = true
						break
					}
				}
				if !found {
					return false, nil
				}
			}
			return true, nil
		case "before":
			if len(v) < 3 {
				return nil, fmt.Errorf("before requires 2 arguments")
			}
			a, err := eval(v[1], env)
			if err != nil {
				return nil, err
			}
			b, err := eval(v[2], env)
			if err != nil {
				return nil, err
			}
			sa, okA := a.(string)
			sb, okB := b.(string)
			if !okA || !okB {
				return nil, fmt.Errorf("before requires string arguments")
			}
			return sa < sb, nil
		case "get":
			if len(v) < 3 {
				return nil, fmt.Errorf("get requires 2 arguments")
			}
			obj, err := eval(v[1], env)
			if err != nil {
				return nil, err
			}
			key, err := eval(v[2], env)
			if err != nil {
				return nil, err
			}
			if m, ok := obj.(map[string]any); ok {
				if s, ok := key.(string); ok {
					return m[s], nil
				}
			}
			return nil, nil
		case "per-day-count":
			if len(v) < 3 {
				return nil, fmt.Errorf("per-day-count requires 2 arguments")
			}
			action, err := eval(v[1], env)
			if err != nil {
				return nil, err
			}
			day, err := eval(v[2], env)
			if err != nil {
				return nil, err
			}
			actionStr, ok := action.(string)
			if !ok {
				return nil, fmt.Errorf("per-day-count: action must be string")
			}
			dayStr, ok := day.(string)
			if !ok {
				return nil, fmt.Errorf("per-day-count: day must be string")
			}
			return float64(env.PerDayCount(actionStr, dayStr)), nil
		case "dpop_ok?":
			return env.Crypto.DPoPOk(), nil
		case "merkle_ok?":
			if len(v) < 2 {
				return nil, fmt.Errorf("merkle_ok? requires 1 argument")
			}
			tuple, err := eval(v[1], env)
			if err != nil {
				return nil, err
			}
			arr, ok := tuple.([]any)
			if !ok {
				return nil, fmt.Errorf("merkle_ok? argument must be a tuple")
			}
			return env.Crypto.MerkleOk(arr), nil
		case "vrf_ok?":
			if len(v) < 3 {
				return nil, fmt.Errorf("vrf_ok? requires 2 arguments")
			}
			day, err := eval(v[1], env)
			if err != nil {
				return nil, err
			}
			amount, err := eval(v[2], env)
			if err != nil {
				return nil, err
			}
			dayStr, ok := day.(string)
			if !ok {
				return nil, fmt.Errorf("vrf_ok?: day must be string")
			}
			switch a := amount.(type) {
			case float64:
				return env.Crypto.VRFOk(dayStr, a), nil
			case int:
				return env.Crypto.VRFOk(dayStr, float64(a)), nil
			default:
				return nil, fmt.Errorf("vrf_ok?: amount must be numeric")
			}
		// thresh_ok? — Threshold co-signature verification.
		// Expected protocol: k-of-n co-signatures where the verifier checks each
		// signature against its corresponding public key and confirms count >= threshold.
		// Not implemented in v0.1 — remains an interface stub. Provide your own
		// implementation via env.Crypto.ThreshOk when integrating.
		case "thresh_ok?":
			return env.Crypto.ThreshOk(), nil
		case "tuple":
			var out []any
			for _, a := range v[1:] {
				val, err := eval(a, env)
				if err != nil {
					return nil, err
				}
				out = append(out, val)
			}
			return out, nil
		default:
			return nil, fmt.Errorf("unknown op: %v", op)
		}
	case string:
		return resolveSymbol(v, env)
	default:
		return v, nil
	}
}

func resolveSymbol(name string, env *Env) (any, error) {
	switch name {
	case "req":
		return env.Req, nil
	case "now":
		if v, ok := env.Vars["now"]; ok {
			return v, nil
		}
		if env.Strict {
			return nil, fmt.Errorf("unresolved symbol: %s", name)
		}
		return name, nil
	case "#t":
		return true, nil
	case "#f":
		return false, nil
	default:
		if env.Vars != nil {
			if v, ok := env.Vars[name]; ok {
				return v, nil
			}
		}
		if env.Strict {
			return nil, fmt.Errorf("unresolved symbol: %s", name)
		}
		return name, nil
	}
}

func truthy(x any) bool {
	switch t := x.(type) {
	case bool:
		return t
	case nil:
		return false
	default:
		return true
	}
}

func eq(a, b any) bool {
	switch av := a.(type) {
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case float64:
		switch bv := b.(type) {
		case float64:
			return av == bv
		case int:
			return av == float64(bv)
		}
		return false
	case int:
		switch bv := b.(type) {
		case int:
			return av == bv
		case float64:
			return float64(av) == bv
		}
		return false
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case nil:
		return b == nil
	default:
		return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
	}
}

func cmp(args []Node, env *Env, op string) (any, error) {
	a, err := eval(args[0], env)
	if err != nil {
		return nil, err
	}
	b, err := eval(args[1], env)
	if err != nil {
		return nil, err
	}
	af := toFloat(a)
	bf := toFloat(b)
	switch op {
	case "<=":
		return af <= bf, nil
	case "<":
		return af < bf, nil
	case ">=":
		return af >= bf, nil
	case ">":
		return af > bf, nil
	}
	return false, nil
}

func toFloat(x any) float64 {
	switch v := x.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	default:
		return 0
	}
}
