# Agent-Safe SPL — Java SDK

Java implementation of the SPL (Safe Policy Lisp) evaluator for Agent-Safe capability tokens.

## Requirements

- JDK 21+ (uses sealed interfaces, record patterns, switch pattern matching, EdDSA)
- Maven 3.8+

## Build & Test

```bash
cd sdk/java
mvn test
```

## Usage

```java
import io.agentsafe.spl.*;
import java.util.List;

Node ast = Parser.parse("(and (= (get req \"action\") \"read\") (<= (get req \"amount\") 100))");

Env env = new Env();
env.req.put("action", Node.str("read"));
env.req.put("amount", Node.num(50.0));

Verifier.Result result = Verifier.verify(ast, env);
System.out.println(result.allow() ? "ALLOW" : "DENY");
```

## Dependencies

Zero runtime dependencies. JDK 17+ provides EdDSA (Ed25519) and SHA-256.
