# Part 2 — On-Behalf-Of Token Exchange

An RFC 8693 token exchange endpoint: it takes a caller's token and issues a new, narrower
one scoped to a specific downstream user and service. This is **option C** from the brief,
and the implementation of §1C of [DESIGN.md](DESIGN.md).

```bash
dotnet test     # 27 tests
dotnet run --project src/Collaborate.TokenExchange
```

## Why this slice

Option C is the only one of the three that exercises the confused-deputy problem the brief
calls out by name, and it is the one place where a framework does *not* hand you the
answer — so it is where a judgment call is actually visible.

## What is framework, what is custom, and why

Everything cryptographic and protocol-shaped is the framework's:

| Concern | Handled by |
|---|---|
| Token parsing, signature verification | `JsonWebTokenHandler.ValidateTokenAsync` |
| Issuer / audience / lifetime validation | `TokenValidationParameters` |
| Token creation and signing | `JsonWebTokenHandler.CreateToken` |
| Key material | `System.Security.Cryptography.RSA` + `RsaSecurityKey` |
| Hosting, DI, request pipeline | ASP.NET Core minimal APIs |

Nothing in this repository parses a JWT, verifies a signature, or implements an algorithm.

**The custom code is one file:** [`ExchangePolicy.cs`](src/Collaborate.TokenExchange/Domain/ExchangePolicy.cs).
That is unavoidable rather than chosen — neither Duende IdentityServer nor OpenIddict ships
RFC 8693; both require a custom grant handler (`IExtensionGrantValidator` in Duende, a
custom handler in OpenIddict). Since custom code was required, the goal became confining it
to the smallest possible pure function: no I/O, no clock, no token handling — just the
decision. That is what makes the security-critical logic exhaustively table-testable.

The split throughout is **I/O in the service, judgment in the policy**. `TokenExchangeService`
gathers facts (validate token, check entitlement, query the PDP) and `ExchangePolicy` decides.

## The four controls

Implemented in [`ExchangePolicy.Evaluate`](src/Collaborate.TokenExchange/Domain/ExchangePolicy.cs), in order:

1. **Firm boundary** — a client cannot act for a user outside its own firm. Modelled as a
   closed `ActorConstraint` hierarchy so that "may act across firms" is a named, privileged
   registration decision, not the accidental result of a null field.
2. **Delegation depth** — an already-delegated token cannot be exchanged again.
3. **Audience pinning** — exactly one downstream service, drawn from the client's registered
   set. `audience` is required, though RFC 8693 makes it optional: an unpinned token is the
   confused-deputy problem restated.
4. **Scope as intersection** — `requested ∩ subject token ∩ client ceiling ∩ current PDP`.

### The distinction worth defending

The two ways a scope can fail are treated differently on purpose:

- A scope the subject token **never carried**, or above the **client ceiling**, is an
  escalation attempt → `invalid_scope`, loudly. Silently narrowing here would hide both a
  caller bug and a real attack behind a success response.
- A scope the user **has since lost** is ordinary staleness → dropped silently, with the
  granted scope reported back per RFC 6749 §5.1. Failing here would break a legitimate
  integration every time a permission changed.

An empty result is always a refusal: a downstream service that reads an absent scope claim
as "unrestricted" would turn a fully-revoked user into an unbounded one.

## Tradeoffs

- **A standalone minimal API rather than a grant handler inside a real AS.** Keeps the slice
  reviewable and library-agnostic, at the cost of not being a real authorization server —
  no discovery document, no JWKS endpoint, no client management. In production this code
  moves inside the AS unchanged; only its mounting changes.
- **`client_secret_post` for client authentication.** Spec-legal (RFC 6749 §2.3.1) and
  enough to demonstrate the flow, but a deployment where clients act on behalf of other
  organisations' users should require `private_key_jwt` or mTLS — a shared secret is
  replayable by anyone who obtains it.
- **One signing key for subject and issued tokens.** Keeps the demo self-contained. Real
  deployments verify subject tokens against Caseware's IdP keys and sign with their own;
  `SubjectTokenValidator` takes its key separately so that is configuration, not a rewrite.
- **Sender-constrained tokens (mTLS / DPoP) are not implemented.** Named as an open decision
  in the design rather than silently skipped.
- **The PDP port returns scopes, not per-resource decisions.** Resource-level overrides are
  evaluated at request time by the enforcement point — a fact that can change between mint
  and use does not belong in a token.

## Tests

[`ExchangePolicyTests`](tests/Collaborate.TokenExchange.Tests/ExchangePolicyTests.cs) — 15 tests
over the pure decision matrix. [`TokenExchangeEndpointTests`](tests/Collaborate.TokenExchange.Tests/TokenExchangeEndpointTests.cs) —
12 tests over real HTTP, covering the issued JWT's claims, every OAuth error code, expired
and rogue-signed and wrong-audience subject tokens.

The negative tests carry the weight here: a bug in this code grants access rather than
throwing, so the tests that prove something is *refused* matter more than the happy path.

One seed value is deliberately wrong and load-bearing — `InMemoryActorEntitlementStore`
grants Acme's integration consent for a Globex user, i.e. the consent store is misconfigured
exactly the way a real one could be. The exchange still refuses, because the firm boundary is
structural and runs regardless. Without that entry the cross-firm test would pass on a
missing consent record and never exercise the invariant it exists to protect.

## Stubbed

`IClientRegistry`, `IActorEntitlementStore`, and `IPermissionQuery` are in-memory. Each sits
behind the interface its real implementation would satisfy — per-firm client config from a
cached database read, a durable consent record, and the Redis-backed PDP from the design.
Swapping them changes composition only.
