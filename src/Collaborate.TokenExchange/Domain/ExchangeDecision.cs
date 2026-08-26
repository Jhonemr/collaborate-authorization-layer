namespace Collaborate.TokenExchange.Domain;

/// <summary>
/// The outcome of evaluating an exchange request.
/// </summary>
/// <remarks>
/// A result type rather than exceptions. Two reasons: refusal is an expected outcome
/// here, not an exceptional one; and every refusal has to surface as a specific OAuth
/// error code, which a result carries naturally and an exception hierarchy does not.
/// </remarks>
public abstract record ExchangeDecision
{
    private ExchangeDecision() { }

    /// <param name="DroppedByPolicy">
    /// Scopes the subject token still carries but the user has since lost. Not an error —
    /// ordinary staleness — but emitted so it can be observed. A rising rate here means
    /// callers are holding tokens well past a permission change.
    /// </param>
    public sealed record Granted(
        IReadOnlySet<string> Scopes,
        IReadOnlySet<string> DroppedByPolicy) : ExchangeDecision;

    public sealed record Refused(string Error, string Description) : ExchangeDecision;
}

/// <summary>
/// OAuth 2.0 error codes used by the exchange endpoint.
/// </summary>
public static class OAuthError
{
    /// <summary>RFC 6749 §5.2 — malformed or incomplete request.</summary>
    public const string InvalidRequest = "invalid_request";

    /// <summary>RFC 6749 §5.2 — the subject token is invalid, expired, or unusable.</summary>
    public const string InvalidGrant = "invalid_grant";

    /// <summary>RFC 6749 §5.2 — requested scope exceeds a ceiling.</summary>
    public const string InvalidScope = "invalid_scope";

    /// <summary>RFC 6749 §5.2 — this client may not act for this subject.</summary>
    public const string UnauthorizedClient = "unauthorized_client";

    /// <summary>
    /// RFC 8707 §2 — the requested target service is unknown or not permitted for
    /// this client. Distinct from invalid_scope on purpose: the caller asked for a
    /// legitimate scope at a service it may not address.
    /// </summary>
    public const string InvalidTarget = "invalid_target";
}
