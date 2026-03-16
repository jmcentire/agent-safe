# Security Audit Report

**Generated:** 2026-03-15T18:49:09.817197

## Summary

- Critical: 4
- High: 0
- Medium: 0
- Low: 5
- Info: 0
- **Total: 9**

## CRITICAL (4)

- **_parse** (sdk/python/spl/parser.py:70) [NOT COVERED]
  - Pattern: variable: tokens
  - Complexity: 7
  - Suggestion: Ensure branch on 'tokens' is tested with both truthy and falsy values
- **_parse** (sdk/python/spl/parser.py:70) [NOT COVERED]
  - Pattern: variable: tokens
  - Complexity: 7
  - Suggestion: Ensure branch on 'tokens' is tested with both truthy and falsy values
- **_parse** (sdk/python/spl/parser.py:70) [NOT COVERED]
  - Pattern: variable: tokens
  - Complexity: 7
  - Suggestion: Ensure branch on 'tokens' is tested with both truthy and falsy values
- **verify_token** (sdk/python/spl/token.py:138) [NOT COVERED]
  - Pattern: variable: token
  - Complexity: 19
  - Suggestion: Ensure branch on 'token' is tested with both truthy and falsy values

## LOW (5)

- **parse** (sdk/python/spl/parser.py:61) [covered]
  - Pattern: variable: tokens
  - Complexity: 10
  - Suggestion: Ensure branch on 'tokens' is tested with both truthy and falsy values
- **parse** (sdk/python/spl/parser.py:61) [covered]
  - Pattern: variable: tokens
  - Complexity: 10
  - Suggestion: Ensure branch on 'tokens' is tested with both truthy and falsy values
- **parse** (sdk/python/spl/parser.py:61) [covered]
  - Pattern: variable: tokens
  - Complexity: 10
  - Suggestion: Ensure branch on 'tokens' is tested with both truthy and falsy values
- **parse** (sdk/python/spl/parser.py:61) [covered]
  - Pattern: variable: tokens
  - Complexity: 10
  - Suggestion: Ensure branch on 'tokens' is tested with both truthy and falsy values
- **parse** (sdk/python/spl/parser.py:61) [covered]
  - Pattern: variable: tokens
  - Complexity: 10
  - Suggestion: Ensure branch on 'tokens' is tested with both truthy and falsy values
