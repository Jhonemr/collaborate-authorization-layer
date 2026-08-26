namespace Collaborate.TokenExchange.Domain;

/// <summary>
/// Who a registered client is permitted to act on behalf of.
/// </summary>
/// <remarks>
/// Modelled as a closed hierarchy rather than a nullable FirmId so that
/// "may act across firm boundaries" is a named, deliberate choice at the call
/// site instead of the incidental result of a null. Cross-firm delegation is
/// the confused-deputy risk in this system; it should be impossible to grant
/// by forgetting to set a field.
/// </remarks>
public abstract record ActorConstraint
{
    private ActorConstraint() { }

    /// <summary>A firm's own integration. May act only for users of that firm.</summary>
    public sealed record SameFirmOnly(string FirmId) : ActorConstraint;

    /// <summary>
    /// A first-party Caseware service (e.g. notifications) acting for whichever
    /// user triggered it. Deliberately separate from <see cref="SameFirmOnly"/>:
    /// granting this is a privileged registration decision, not a config default.
    /// </summary>
    public sealed record AnyFirm : ActorConstraint;
}

/// <summary>
/// A client registered with Collaborate's authorization server. In production this
/// is the per-firm client configuration described in Part 1 (§1A), read through a
/// cache; here it is served from memory.
/// </summary>
/// <param name="ScopeCeiling">
/// The maximum scope this client may ever obtain, independent of the user. A client
/// cannot exceed this even when the user is entitled to more — this is what stops a
/// compromised integration from escalating through a privileged user's token.
/// </param>
public sealed record ClientRegistration(
    string ClientId,
    ActorConstraint ActorConstraint,
    IReadOnlySet<string> AllowedAudiences,
    IReadOnlySet<string> ScopeCeiling);

/// <summary>
/// The user the caller is acting for, as established from a *validated* subject token.
/// Constructing this from an unvalidated token would defeat the entire exchange, so it
/// is only ever produced by <c>SubjectTokenValidator</c>.
/// </summary>
/// <param name="DelegationDepth">
/// How many times this token has already been exchanged, read from the nesting of the
/// <c>act</c> claim (RFC 8693 §4.1). Zero for a token obtained directly by the user.
/// Chains are capped so a delegated token cannot be re-delegated indefinitely, which
/// would otherwise let a low-trust hop launder its way toward a higher-trust audience.
/// </param>
public sealed record SubjectPrincipal(
    string UserId,
    string FirmId,
    IReadOnlySet<string> Scopes,
    int DelegationDepth = 0);

/// <summary>
/// A parsed RFC 8693 token exchange request.
/// </summary>
/// <param name="RequestedScopes">
/// Null when the <c>scope</c> parameter was omitted. RFC 8693 §2.1 permits omission and
/// leaves the resulting scope to the authorization server; we then grant the full
/// intersection of the remaining ceilings, which is still a narrowing.
/// </param>
public sealed record TokenExchangeRequest(
    string SubjectToken,
    string SubjectTokenType,
    string Audience,
    IReadOnlySet<string>? RequestedScopes);
