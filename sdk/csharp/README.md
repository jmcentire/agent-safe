# Agent-Safe SPL — C# SDK

C# implementation of the SPL (Safe Policy Lisp) evaluator for Agent-Safe capability tokens.

## Requirements

- .NET 10.0+
- Ed25519 verification requires opt-in via `AGENTSAFE_ED25519` define (API not yet stable in .NET)

## Build & Test

```bash
cd sdk/csharp
dotnet test
```

## Usage

```csharp
using AgentSafe.Spl;

var ast = Parser.Parse("(and (= (get req \"action\") \"read\") (<= (get req \"amount\") 100))");

var env = new Env();
env.Req["action"] = Node.Str("read");
env.Req["amount"] = Node.Num(50.0);

var result = Verifier.Verify(ast, env);
Console.WriteLine(result.Allow ? "ALLOW" : "DENY");
```

## Dependencies

Zero external dependencies. .NET 10+ provides SHA-256 via stdlib. Ed25519 is behind `AGENTSAFE_ED25519` preprocessor guard until the API stabilizes.
