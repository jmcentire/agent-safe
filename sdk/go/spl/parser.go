package spl

import (
	"fmt"
	"strconv"
	"strings"
)

type Node interface{}

const MaxPolicyBytes = 65536 // 64 KB

func Parse(src string) (Node, error) {
	if len(src) > MaxPolicyBytes {
		return nil, fmt.Errorf("policy exceeds maximum size of %d bytes", MaxPolicyBytes)
	}
	toks := tokenize(src)
	i := 0
	var parse func() (Node, error)
	parse = func() (Node, error) {
		if i >= len(toks) {
			return nil, fmt.Errorf("unexpected EOF")
		}
		tok := toks[i]
		i++
		switch tok {
		case "(":
			var arr []Node
			for {
				if i >= len(toks) {
					return nil, fmt.Errorf("unterminated (")
				}
				if toks[i] == ")" {
					i++
					break
				}
				n, err := parse()
				if err != nil {
					return nil, err
				}
				arr = append(arr, n)
			}
			return arr, nil
		case ")":
			return nil, fmt.Errorf("unexpected )")
		default:
			if tok == "#t" {
				return true, nil
			}
			if tok == "#f" {
				return false, nil
			}
			if strings.HasPrefix(tok, "\"") && strings.HasSuffix(tok, "\"") {
				s, err := strconv.Unquote(tok)
				if err != nil {
					return nil, err
				}
				return s, nil
			}
			if n, err := strconv.ParseFloat(tok, 64); err == nil {
				return n, nil
			}
			return tok, nil
		}
	}
	return parse()
}

func tokenize(src string) []string {
	var toks []string
	var buf strings.Builder
	inStr := false
	for _, ch := range src {
		if inStr {
			buf.WriteRune(ch)
			if ch == '"' {
				inStr = false
				toks = append(toks, buf.String())
				buf.Reset()
			}
			continue
		}
		switch ch {
		case '(', ')':
			if buf.Len() > 0 {
				toks = append(toks, strings.Fields(buf.String())...)
				buf.Reset()
			}
			toks = append(toks, string(ch))
		case ' ', '\n', '\t', '\r':
			if buf.Len() > 0 {
				toks = append(toks, strings.Fields(buf.String())...)
				buf.Reset()
			}
		case '"':
			if buf.Len() > 0 {
				toks = append(toks, strings.Fields(buf.String())...)
				buf.Reset()
			}
			inStr = true
			buf.WriteRune(ch)
		default:
			buf.WriteRune(ch)
		}
	}
	if buf.Len() > 0 {
		toks = append(toks, strings.Fields(buf.String())...)
	}
	return toks
}
