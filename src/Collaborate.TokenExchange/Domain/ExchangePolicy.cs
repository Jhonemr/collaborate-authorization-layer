namespace Collaborate.TokenExchange.Domain;

/// <summary>
/// Decides whether an exchange is permitted and what scope the issued token carries.
/// </summary>
/// <remarks>
/// Deliberately pure: no I/O, no async, no clock. Every input is a parameter, so the
/// full decision matrix is table-testable without infrastructure. This is the code path
/// where a bug is a privilege escalation rather than a crash, so it is the code path
/// kept easiest to test exhaustively.
///
/// The caller performs the I/O (token validation, PDP lookup, entitlement lookup) and
/// hands the results in.
/// </remarks>
public static class ExchangePolicy
{
    /// <summary>
    /// How many times a token may be exchanged. One hop covers both scenarios in the
    /// brief; anything deeper is a chain nobody has designed and should be refused.
    /// </summary>
    public const int MaxDelegationDepth = 1;

    public static ExchangeDecision Evaluate(
        ClientRegistration client,
        SubjectPrincipal subject,
        TokenExchangeRequest request,
        IReadOnlySet<string> currentUserScopes)
    {
        // (1) Firm boundary. First, so that a client which may not act for this user at
        //     all learns nothing about which audiences or scopes exist.
        if (!MayActAcross(client.ActorConstraint, subject.FirmId))
        {
            return new ExchangeDecision.Refused(
                OAuthError.UnauthorizedClient,
                "Client may not act for users outside its own firm.");
        }

        // (2) Delegation depth.
        if (subject.DelegationDepth >= MaxDelegationDepth)
        {
            return new ExchangeDecision.Refused(
                OAuthError.InvalidGrant,
                "Subject token has already been delegated and may not be exchanged again.");
        }

        // (3) Audience pinning. The issued token names exactly one downstream service,
        //     and only services this client is registered against.
        if (!client.AllowedAudiences.Contains(request.Audience))
        {
            return new ExchangeDecision.Refused(
                OAuthError.InvalidTarget,
                "Requested audience is not registered for this client.");
        }

        // (4) The two static ceilings: what the user's token carries, and what this
        //     client may ever hold. A privileged user's token must not lift a client
        //     above its own ceiling.
        var ceiling = Intersect(subject.Scopes, client.ScopeCeiling);

        IReadOnlySet<string> candidate;
        if (request.RequestedScopes is { } requested)
        {
            // Asking for something above a static ceiling is an escalation attempt, not
            // staleness. Fail loudly: silently narrowing here would hide both the caller's
            // bug and a real attack behind a success response.
            var escalation = Except(requested, ceiling);
            if (escalation.Count > 0)
            {
                return new ExchangeDecision.Refused(
                    OAuthError.InvalidScope,
                    $"Requested scope exceeds subject token or client ceiling: {string.Join(' ', escalation.Order())}.");
            }

            candidate = requested;
        }
        else
        {
            // RFC 8693 §2.1 permits omitting scope. Granting the full intersection is
            // still a narrowing against both static ceilings.
            candidate = ceiling;
        }

        // (5) Current permissions from the PDP. Unlike (4) this is live state, so a scope
        //     missing here is ordinary staleness — the subject token predates a permission
        //     change. Drop it silently and report what was actually granted, per RFC 6749
        //     §5.1, rather than breaking a legitimate integration mid-flight.
        var granted = Intersect(candidate, currentUserScopes);
        var dropped = Except(candidate, currentUserScopes);

        if (granted.Count == 0)
        {
            // Never issue a scopeless token: a downstream service that treats an absent
            // scope claim as "unrestricted" would turn a fully-revoked user into an
            // unbounded one.
            return new ExchangeDecision.Refused(
                OAuthError.InvalidScope,
                "No scope remains after applying the user's current permissions.");
        }

        return new ExchangeDecision.Granted(granted, dropped);
    }

    private static bool MayActAcross(ActorConstraint constraint, string subjectFirmId) =>
        constraint switch
        {
            ActorConstraint.AnyFirm => true,
            ActorConstraint.SameFirmOnly f => string.Equals(f.FirmId, subjectFirmId, StringComparison.Ordinal),

            // Fail closed. If the hierarchy ever grows a variant and this switch is not
            // updated, the new variant denies rather than permits.
            _ => false,
        };

    // Scope strings are case-sensitive (RFC 6749 §3.3). Rebuilding both sides with an
    // ordinal comparer means a caller that supplied a case-insensitive set cannot widen
    // a ceiling by casing — the comparison is always the spec's.
    private static IReadOnlySet<string> Intersect(IEnumerable<string> a, IEnumerable<string> b)
    {
        var set = new HashSet<string>(a, StringComparer.Ordinal);
        set.IntersectWith(b);
        return set;
    }

    private static IReadOnlySet<string> Except(IEnumerable<string> a, IEnumerable<string> b)
    {
        var set = new HashSet<string>(a, StringComparer.Ordinal);
        set.ExceptWith(b);
        return set;
    }
}
