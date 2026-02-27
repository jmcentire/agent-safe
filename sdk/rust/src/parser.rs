use crate::types::{Node, SplError};

const MAX_POLICY_BYTES: usize = 65536; // 64 KB

/// Parse an SPL S-expression string into an AST Node.
pub fn parse(src: &str) -> Result<Node, SplError> {
    if src.len() > MAX_POLICY_BYTES {
        return Err(SplError(format!("policy exceeds maximum size of {MAX_POLICY_BYTES} bytes")));
    }
    let tokens = tokenize(src.trim());
    if tokens.is_empty() {
        return Err(SplError("unexpected EOF".into()));
    }
    let mut pos = 0;
    let result = parse_expr(&tokens, &mut pos)?;
    if pos != tokens.len() {
        return Err(SplError("extra tokens".into()));
    }
    Ok(result)
}

fn parse_expr(tokens: &[String], pos: &mut usize) -> Result<Node, SplError> {
    if *pos >= tokens.len() {
        return Err(SplError("unexpected EOF".into()));
    }
    let tok = &tokens[*pos];
    *pos += 1;

    if tok == "(" {
        let mut items = Vec::new();
        loop {
            if *pos >= tokens.len() {
                return Err(SplError("unterminated (".into()));
            }
            if tokens[*pos] == ")" {
                *pos += 1;
                break;
            }
            items.push(parse_expr(tokens, pos)?);
        }
        Ok(Node::List(items))
    } else if tok == ")" {
        Err(SplError("unexpected )".into()))
    } else {
        Ok(parse_atom(tok))
    }
}

fn parse_atom(tok: &str) -> Node {
    match tok {
        "#t" => Node::Bool(true),
        "#f" => Node::Bool(false),
        _ => {
            // Try number
            if let Ok(n) = tok.parse::<f64>() {
                return Node::Number(n);
            }
            // Quoted string
            if tok.starts_with('"') && tok.ends_with('"') && tok.len() >= 2 {
                let inner = &tok[1..tok.len() - 1];
                return Node::Str(inner.replace("\\\"", "\""));
            }
            // Symbol
            Node::Symbol(tok.to_string())
        }
    }
}

fn tokenize(src: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut buf = String::new();
    let mut in_str = false;

    for ch in src.chars() {
        if in_str {
            buf.push(ch);
            if ch == '"' {
                in_str = false;
                tokens.push(buf.clone());
                buf.clear();
            }
            continue;
        }

        match ch {
            '"' => {
                flush_buf(&mut buf, &mut tokens);
                buf.push('"');
                in_str = true;
            }
            '(' | ')' => {
                flush_buf(&mut buf, &mut tokens);
                tokens.push(ch.to_string());
            }
            ' ' | '\n' | '\t' | '\r' => {
                flush_buf(&mut buf, &mut tokens);
            }
            _ => {
                buf.push(ch);
            }
        }
    }
    flush_buf(&mut buf, &mut tokens);
    tokens
}

fn flush_buf(buf: &mut String, tokens: &mut Vec<String>) {
    let trimmed = buf.trim().to_string();
    if !trimmed.is_empty() {
        for word in trimmed.split_whitespace() {
            tokens.push(word.to_string());
        }
    }
    buf.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_integer() {
        assert_eq!(parse("42").unwrap(), Node::Number(42.0));
    }

    #[test]
    fn parse_negative_float() {
        assert_eq!(parse("-3.14").unwrap(), Node::Number(-3.14));
    }

    #[test]
    fn parse_string() {
        assert_eq!(parse(r#""hello""#).unwrap(), Node::Str("hello".into()));
    }

    #[test]
    fn parse_bool_true() {
        assert_eq!(parse("#t").unwrap(), Node::Bool(true));
    }

    #[test]
    fn parse_bool_false() {
        assert_eq!(parse("#f").unwrap(), Node::Bool(false));
    }

    #[test]
    fn parse_symbol() {
        assert_eq!(parse("foo").unwrap(), Node::Symbol("foo".into()));
    }

    #[test]
    fn parse_list() {
        let ast = parse("(and #t #f)").unwrap();
        match ast {
            Node::List(items) => {
                assert_eq!(items.len(), 3);
                assert_eq!(items[0], Node::Symbol("and".into()));
            }
            _ => panic!("expected list"),
        }
    }

    #[test]
    fn parse_nested() {
        let ast = parse("(and (= 1 2) (> 3 1))").unwrap();
        if let Node::List(items) = ast {
            assert_eq!(items.len(), 3);
            if let Node::List(inner) = &items[1] {
                assert_eq!(inner[0], Node::Symbol("=".into()));
            } else {
                panic!("expected inner list");
            }
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn parse_strings_with_spaces() {
        let ast = parse(r#"(= "hello world" "hello world")"#).unwrap();
        if let Node::List(items) = ast {
            assert_eq!(items[1], Node::Str("hello world".into()));
        } else {
            panic!("expected list");
        }
    }

    #[test]
    fn parse_unterminated() {
        assert!(parse("(and #t").is_err());
    }

    #[test]
    fn parse_unexpected_close() {
        assert!(parse(")").is_err());
    }

    #[test]
    fn parse_extra_tokens() {
        assert!(parse("#t #f").is_err());
    }

    #[test]
    fn parse_empty() {
        assert!(parse("").is_err());
    }
}
