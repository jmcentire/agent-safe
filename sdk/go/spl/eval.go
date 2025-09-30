package spl

import (
	"fmt"
)

type Env struct {
	Req map[string]any
	AllowedRecipients []string
	PerDayCount func(action, day string) int
	Crypto struct{
		DPoPOk func() bool
		MerkleOk func(tuple []any) bool
		VRFOk func(day string, amount float64) bool
	}
}

func Verify(ast Node, env Env) (bool, error) {
	val, err := eval(ast, env)
	if err != nil { return false, err }
	b, ok := val.(bool)
	if !ok { return false, fmt.Errorf("policy did not return boolean") }
	return b, nil
}

func eval(n Node, env Env) (any, error) {
	switch v := n.(type) {
	case []Node:
		if len(v) == 0 { return nil, nil }
		op := v[0]
		if sym, ok := op.(string); ok {
			switch sym {
			case "and":
				for _, a := range v[1:] {
					res, err := eval(a, env); if err != nil { return nil, err }
					if !truthy(res) { return false, nil }
				}
				return true, nil
			case "or":
				for _, a := range v[1:] {
					res, err := eval(a, env); if err != nil { return nil, err }
					if truthy(res) { return true, nil }
				}
				return false, nil
			case "not":
				res, err := eval(v[1], env); if err != nil { return nil, err }
				return !truthy(res), nil
			case "=":
				a, _ := eval(v[1], env); b, _ := eval(v[2], env); return eq(a,b), nil
			case "<=":
				return cmp(v[1:], env, "<=")
			case "<":
				return cmp(v[1:], env, "<")
			case ">=":
                return cmp(v[1:], env, ">=")
			case ">":
                return cmp(v[1:], env, ">")
			case "member":
				x, _ := eval(v[1], env)
				lst, _ := eval(v[2], env)
				if arr, ok := lst.([]any); ok {
					for _, e := range arr { if eq(e,x) { return true, nil } }
				}
				return false, nil
			case "get":
				obj, _ := eval(v[1], env)
				key, _ := eval(v[2], env)
				if m, ok := obj.(map[string]any); ok {
					if s, ok := key.(string); ok { return m[s], nil }
				}
				return nil, nil
			case "per-day-count":
				action, _ := eval(v[1], env)
				day, _ := eval(v[2], env)
				return float64(env.PerDayCount(action.(string), day.(string))), nil
			case "dpop_ok?":
				return env.Crypto.DPoPOk(), nil
			case "merkle_ok?":
				tuple, _ := eval(v[1], env)
				return env.Crypto.MerkleOk(tuple.([]any)), nil
			case "vrf_ok?":
				day, _ := eval(v[1], env)
				amount, _ := eval(v[2], env)
				switch a := amount.(type) {
				case float64: return env.Crypto.VRFOk(day.(string), a), nil
				case int: return env.Crypto.VRFOk(day.(string), float64(a)), nil
				default: return false, nil
				}
			case "tuple":
				var out []any
				for _, a := range v[1:] { val, _ := eval(a, env); out = append(out, val) }
				return out, nil
			default:
				return nil, fmt.Errorf("unknown op: %v", sym)
			}
		}
		return nil, fmt.Errorf("bad form")
	case string:
		switch v {
		case "req":
			return env.Req, nil
		case "allowed_recipients":
			// convert to []any
			aa := make([]any, len(env.AllowedRecipients))
			for i,s := range env.AllowedRecipients { aa[i]=s }
			return aa, nil
		case "#t":
			return true, nil
		case "#f":
			return false, nil
		default:
			return v, nil
		}
	default:
		return v, nil
	}
}

func truthy(x any) bool {
	switch t := x.(type) {
	case bool: return t
	case nil: return false
	default: return true
	}
}

func eq(a,b any) bool { return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b) }

func cmp(args []Node, env Env, op string) (any, error) {
	a, _ := eval(args[0], env)
	b, _ := eval(args[1], env)
	af := toFloat(a); bf := toFloat(b)
	switch op {
	case "<=": return af <= bf, nil
	case "<":  return af <  bf, nil
	case ">=": return af >= bf, nil
	case ">":  return af >  bf, nil
	}
	return false, nil
}
func toFloat(x any) float64 {
	switch v := x.(type) {
	case float64: return v
	case int: return float64(v)
	case string:
		var f float64; fmt.Sscanf(v, "%f", &f); return f
	default: return 0
	}
}
