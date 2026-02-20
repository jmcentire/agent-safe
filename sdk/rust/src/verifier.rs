use crate::evaluator::eval_policy;
use crate::types::{Env, Node, SplError};

/// Verify result.
pub struct VerifyResult {
    pub allow: bool,
    pub obligations: Vec<String>,
}

/// Evaluate an SPL policy AST against a request within an environment.
pub fn verify(ast: &Node, env: &Env) -> Result<VerifyResult, SplError> {
    if env.sealed {
        return Err(SplError("token is sealed and cannot be attenuated".to_string()));
    }
    let result = eval_policy(ast, env)?;
    let allow = result.is_truthy();
    Ok(VerifyResult {
        allow,
        obligations: Vec::new(),
    })
}
