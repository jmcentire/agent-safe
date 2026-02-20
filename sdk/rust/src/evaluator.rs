use crate::types::{Env, Node, SplError, SplResult};

const MAX_DEPTH: i64 = 64;

struct EvalState {
    gas: i64,
    depth: i64,
}

/// Evaluate an SPL AST within an environment. Returns the result Node.
pub fn eval_policy(ast: &Node, env: &Env) -> SplResult {
    let mut state = EvalState {
        gas: env.max_gas,
        depth: 0,
    };
    eval(ast, env, &mut state)
}

fn eval(node: &Node, env: &Env, st: &mut EvalState) -> SplResult {
    st.gas -= 1;
    if st.gas < 0 {
        return Err(SplError("gas budget exceeded".into()));
    }
    st.depth += 1;
    if st.depth > MAX_DEPTH {
        st.depth -= 1;
        return Err(SplError("max nesting depth exceeded".into()));
    }
    let result = eval_inner(node, env, st);
    st.depth -= 1;
    result
}

fn eval_inner(node: &Node, env: &Env, st: &mut EvalState) -> SplResult {
    match node {
        Node::List(items) if items.is_empty() => Ok(Node::Nil),
        Node::List(items) => {
            let op = match &items[0] {
                Node::Symbol(s) => s.as_str(),
                _ => return Err(SplError("operator must be a symbol".into())),
            };
            let args = &items[1..];
            eval_op(op, args, env, st)
        }
        Node::Symbol(s) => resolve_symbol(s, env),
        Node::Bool(_) | Node::Number(_) | Node::Str(_) | Node::Nil => Ok(node.clone()),
    }
}

fn eval_op(op: &str, args: &[Node], env: &Env, st: &mut EvalState) -> SplResult {
    match op {
        "and" => {
            for a in args {
                let val = eval(a, env, st)?;
                if !val.is_truthy() {
                    return Ok(Node::Bool(false));
                }
            }
            Ok(Node::Bool(true))
        }
        "or" => {
            for a in args {
                let val = eval(a, env, st)?;
                if val.is_truthy() {
                    return Ok(Node::Bool(true));
                }
            }
            Ok(Node::Bool(false))
        }
        "not" => {
            let val = eval(&args[0], env, st)?;
            Ok(Node::Bool(!val.is_truthy()))
        }
        "=" => {
            let a = eval(&args[0], env, st)?;
            let b = eval(&args[1], env, st)?;
            Ok(Node::Bool(node_eq(&a, &b)))
        }
        "<=" | "<" | ">=" | ">" => {
            let a = eval(&args[0], env, st)?.as_f64();
            let b = eval(&args[1], env, st)?.as_f64();
            let result = match op {
                "<=" => a <= b,
                "<" => a < b,
                ">=" => a >= b,
                ">" => a > b,
                _ => false,
            };
            Ok(Node::Bool(result))
        }
        "member" | "in" => {
            let val = eval(&args[0], env, st)?;
            let lst = eval(&args[1], env, st)?;
            if let Node::List(items) = lst {
                Ok(Node::Bool(items.iter().any(|item| node_eq(item, &val))))
            } else {
                Ok(Node::Bool(false))
            }
        }
        "subset?" => {
            let a = eval(&args[0], env, st)?;
            let b = eval(&args[1], env, st)?;
            match (a, b) {
                (Node::List(a_items), Node::List(b_items)) => {
                    let all_in = a_items.iter().all(|item| {
                        b_items.iter().any(|candidate| node_eq(item, candidate))
                    });
                    Ok(Node::Bool(all_in))
                }
                _ => Ok(Node::Bool(false)),
            }
        }
        "before" => {
            let a = eval(&args[0], env, st)?;
            let b = eval(&args[1], env, st)?;
            let a_str = node_to_string(&a);
            let b_str = node_to_string(&b);
            Ok(Node::Bool(a_str < b_str))
        }
        "get" => {
            let key = eval(&args[1], env, st)?;
            let key_str = match &key {
                Node::Str(s) => s.as_str(),
                _ => return Ok(Node::Nil),
            };
            // Check if first arg is symbol "req" — look up in env.req
            if let Node::Symbol(s) = &args[0] {
                if s == "req" {
                    return Ok(env.req.get(key_str).cloned().unwrap_or(Node::Nil));
                }
            }
            // Otherwise resolve symbol and try map-like access on vars
            let obj_name = match &args[0] {
                Node::Symbol(s) => s.as_str(),
                _ => return Ok(Node::Nil),
            };
            // For non-req symbols, resolve them
            if let Some(v) = env.vars.get(obj_name) {
                if let Node::List(_) = v {
                    // Can't get from a list by string key
                    return Ok(Node::Nil);
                }
            }
            Ok(Node::Nil)
        }
        "tuple" => {
            let mut result = Vec::new();
            for a in args {
                result.push(eval(a, env, st)?);
            }
            Ok(Node::List(result))
        }
        "per-day-count" => {
            let action = eval(&args[0], env, st)?;
            let day = eval(&args[1], env, st)?;
            let a = node_to_string(&action);
            let d = node_to_string(&day);
            let count = (env.per_day_count)(&a, &d);
            Ok(Node::Number(count as f64))
        }
        "dpop_ok?" => Ok(Node::Bool((env.crypto.dpop_ok)())),
        "merkle_ok?" => {
            let mut evaluated = Vec::new();
            for a in args {
                evaluated.push(eval(a, env, st)?);
            }
            Ok(Node::Bool((env.crypto.merkle_ok)(&evaluated)))
        }
        "vrf_ok?" => {
            let day = eval(&args[0], env, st)?;
            let amount = eval(&args[1], env, st)?;
            let d = node_to_string(&day);
            let a = amount.as_f64();
            Ok(Node::Bool((env.crypto.vrf_ok)(&d, a)))
        }
        "thresh_ok?" => Ok(Node::Bool((env.crypto.thresh_ok)())),
        _ => Err(SplError(format!("Unknown op: {op}"))),
    }
}

fn resolve_symbol(name: &str, env: &Env) -> SplResult {
    match name {
        "#t" => Ok(Node::Bool(true)),
        "#f" => Ok(Node::Bool(false)),
        "req" => {
            // Convert req HashMap to a form the evaluator can use
            // We use a special wrapper — return a map-like node
            Ok(Node::Str("__req__".into()))
        }
        "now" => {
            if let Some(v) = env.vars.get("now") {
                Ok(v.clone())
            } else {
                Ok(Node::Symbol(name.into()))
            }
        }
        _ => {
            if let Some(v) = env.vars.get(name) {
                Ok(v.clone())
            } else {
                Ok(Node::Symbol(name.into()))
            }
        }
    }
}

fn node_eq(a: &Node, b: &Node) -> bool {
    match (a, b) {
        (Node::Bool(x), Node::Bool(y)) => x == y,
        (Node::Number(x), Node::Number(y)) => x == y,
        (Node::Str(x), Node::Str(y)) => x == y,
        (Node::Symbol(x), Node::Symbol(y)) => x == y,
        (Node::Str(x), Node::Symbol(y)) | (Node::Symbol(x), Node::Str(y)) => x == y,
        (Node::Nil, Node::Nil) => true,
        _ => node_to_string(a) == node_to_string(b),
    }
}

fn node_to_string(node: &Node) -> String {
    match node {
        Node::Bool(true) => "true".into(),
        Node::Bool(false) => "false".into(),
        Node::Number(n) => format!("{n}"),
        Node::Str(s) => s.clone(),
        Node::Symbol(s) => s.clone(),
        Node::Nil => "nil".into(),
        Node::List(_) => format!("{node}"),
    }
}
