namespace Collaborate.TokenExchange.Domain;

/// <summary>
/// Per-firm client configuration from Part 1 §1A. Backed by Collaborate's database
/// behind a cache in production; in-memory here.
/// </summary>
public interface IClientRegistry
{
    ClientRegistration? Find(string clientId);
}

/// <summary>
/// The Policy Decision Point from Part 1 §1B — Redis-backed, invalidated by database
/// change events. Stubbed here.
/// </summary>
/// <remarks>
/// Consulting the PDP at mint time is what keeps an exchanged token consistent with the
/// source of truth: the subject token may have been issued before a permission change,
/// and it is this call that catches that. Combined with a 60-second token lifetime it
/// bounds how stale a delegated call can be.
///
/// Note this returns *scopes*, not per-resource decisions. Resource-level overrides
/// ("this one document, shared with this one external user") are evaluated at request
/// time by the enforcement point, not baked in here — for exactly the reason given in
/// Part 1: a fact that can change between mint and use does not belong in a token.
/// </remarks>
public interface IPermissionQuery
{
    Task<IReadOnlySet<string>> GetCurrentScopesAsync(string userId, CancellationToken ct);
}

/// <summary>
/// Whether a specific client is entitled to act for a specific user at all — the
/// control that is most often omitted, and the one that prevents a confused deputy.
/// </summary>
/// <remarks>
/// The firm-boundary check in <c>ExchangePolicy</c> is a structural invariant that runs
/// regardless. This port is the finer-grained layer on top: whether the user actually
/// authorized this integration. Kept separate so that the structural check cannot be
/// switched off by a store returning true.
///
/// RFC 8693 §4.4 defines a <c>may_act</c> claim for this, embedded in the subject token.
/// We deliberately do not use it: an embedded claim is a decision frozen at issue time,
/// which is precisely the staleness this design avoids elsewhere. A lookup at exchange
/// time reflects a revoked authorization immediately.
/// </remarks>
public interface IActorEntitlementStore
{
    Task<bool> MayActForAsync(string clientId, string userId, CancellationToken ct);
}
