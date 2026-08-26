using Collaborate.TokenExchange.Domain;

namespace Collaborate.TokenExchange.Exchange;

public abstract record ExchangeResult
{
    private ExchangeResult() { }

    public sealed record Issued(string AccessToken, int ExpiresIn, string Scope) : ExchangeResult;

    public sealed record Failed(string Error, string Description) : ExchangeResult;
}

/// <summary>
/// Orchestrates one exchange: gather the facts, then let
/// <see cref="ExchangePolicy"/> decide.
/// </summary>
/// <remarks>
/// All the I/O lives here and all the judgement lives in the policy. That split is the
/// point — it is what lets the security-critical decision matrix be tested exhaustively
/// without a database, a clock, or a token.
/// </remarks>
public sealed class TokenExchangeService(
    IClientRegistry clients,
    IActorEntitlementStore entitlements,
    IPermissionQuery permissions,
    SubjectTokenValidator validator,
    DelegatedTokenIssuer issuer,
    ILogger<TokenExchangeService> logger)
{
    private static readonly HashSet<string> SupportedSubjectTokenTypes = new(StringComparer.Ordinal)
    {
        "urn:ietf:params:oauth:token-type:access_token",
        "urn:ietf:params:oauth:token-type:jwt",
    };

    /// <param name="clientId">
    /// Already authenticated by the endpoint. This method never sees credentials, so no
    /// path through it can accidentally trust a caller-supplied identity.
    /// </param>
    public async Task<ExchangeResult> ExchangeAsync(
        string clientId,
        TokenExchangeRequest request,
        CancellationToken ct)
    {
        if (!SupportedSubjectTokenTypes.Contains(request.SubjectTokenType))
        {
            return Fail(OAuthError.InvalidRequest, "Unsupported subject_token_type.");
        }

        var client = clients.Find(clientId);
        if (client is null)
        {
            return Fail(OAuthError.InvalidRequest, "Unknown client.");
        }

        var subject = await validator.ValidateAsync(request.SubjectToken);
        if (subject is null)
        {
            return Fail(OAuthError.InvalidGrant, "Subject token is not valid.");
        }

        // Whether the user authorised this integration at all. Checked at exchange time
        // rather than read from a may_act claim, so a withdrawn authorisation takes
        // effect immediately instead of when the subject token happens to expire.
        if (!await entitlements.MayActForAsync(clientId, subject.UserId, ct))
        {
            logger.LogWarning(
                "Exchange refused: client {ClientId} is not entitled to act for {UserId}.",
                clientId, subject.UserId);

            return Fail(OAuthError.UnauthorizedClient, "Client may not act for this user.");
        }

        // The PDP from Part 1 §1B. This is the call that keeps an exchanged token
        // consistent with the source of truth when the subject token predates a change.
        var current = await permissions.GetCurrentScopesAsync(subject.UserId, ct);

        // Note the ordering: the entitlement store above is a *policy* check and could in
        // principle be misconfigured to return true. The firm boundary inside Evaluate is
        // structural and runs regardless, so a permissive store still cannot produce a
        // cross-firm token.
        var decision = ExchangePolicy.Evaluate(client, subject, request, current);

        switch (decision)
        {
            case ExchangeDecision.Refused refused:
                logger.LogWarning(
                    "Exchange refused for client {ClientId} acting for {UserId}: {Error} — {Description}",
                    clientId, subject.UserId, refused.Error, refused.Description);

                return Fail(refused.Error, refused.Description);

            case ExchangeDecision.Granted granted:
                if (granted.DroppedByPolicy.Count > 0)
                {
                    // Not an error — the subject token predates a permission change. Worth
                    // a signal nonetheless: a rising rate means callers are holding tokens
                    // well past revocation.
                    logger.LogInformation(
                        "Narrowed scope for {UserId}: dropped {Dropped}.",
                        subject.UserId, string.Join(' ', granted.DroppedByPolicy.Order(StringComparer.Ordinal)));
                }

                var (token, expiresIn) = issuer.Issue(subject, clientId, request.Audience, granted.Scopes);
                var scope = string.Join(' ', granted.Scopes.Order(StringComparer.Ordinal));

                // The audit record required by Part 1 §4: who acted, for whom, at what
                // scope, against which audience. In production this goes to an append-only
                // store, not the application log.
                logger.LogInformation(
                    "Exchange issued: act={ClientId} sub={UserId} aud={Audience} scope=\"{Scope}\"",
                    clientId, subject.UserId, request.Audience, scope);

                return new ExchangeResult.Issued(token, expiresIn, scope);

            default:
                // Fail closed if the decision hierarchy ever grows an unhandled variant.
                return Fail(OAuthError.InvalidRequest, "Exchange could not be evaluated.");
        }
    }

    private static ExchangeResult Fail(string error, string description) =>
        new ExchangeResult.Failed(error, description);
}
