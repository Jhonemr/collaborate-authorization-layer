using System.Text.Json;
using Collaborate.TokenExchange.Domain;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.TokenExchange.Exchange;

/// <summary>
/// Turns a raw subject token into a <see cref="SubjectPrincipal"/>, or nothing.
/// </summary>
/// <remarks>
/// Validation is delegated wholesale to <see cref="JsonWebTokenHandler"/> and
/// <see cref="TokenValidationParameters"/>. Nothing here parses JWT structure, checks a
/// signature, or touches cryptography — that is the framework's job and it does it
/// better than hand-written code would. What this class adds is only the mapping from
/// validated claims to a domain type, plus the delegation-depth read that RFC 8693
/// leaves to the implementation.
///
/// The single most important property of this class: <see cref="SubjectPrincipal"/> can
/// only be produced downstream of a successful validation. Nothing else in the codebase
/// constructs one from an unvalidated token.
/// </remarks>
public sealed class SubjectTokenValidator(
    TokenValidationParameters parameters,
    ILogger<SubjectTokenValidator> logger)
{
    private readonly JsonWebTokenHandler _handler = new();

    public async Task<SubjectPrincipal?> ValidateAsync(string token)
    {
        var result = await _handler.ValidateTokenAsync(token, parameters);

        if (!result.IsValid)
        {
            // Logged, never returned. The caller sees a flat invalid_grant: telling an
            // unauthenticated caller *why* a token failed is a probing oracle.
            logger.LogInformation(result.Exception, "Subject token rejected.");
            return null;
        }

        if (result.SecurityToken is not JsonWebToken jwt)
        {
            return null;
        }

        if (!jwt.TryGetPayloadValue<string>("sub", out var userId) || string.IsNullOrWhiteSpace(userId))
        {
            logger.LogInformation("Subject token carries no sub claim.");
            return null;
        }

        if (!jwt.TryGetPayloadValue<string>("firm_id", out var firmId) || string.IsNullOrWhiteSpace(firmId))
        {
            // Without a firm the cross-firm invariant cannot be evaluated, so the only
            // safe answer is to refuse rather than to default.
            logger.LogInformation("Subject token carries no firm_id claim.");
            return null;
        }

        jwt.TryGetPayloadValue<string>("scope", out var scope);

        return new SubjectPrincipal(
            userId,
            firmId,
            ParseScope(scope),
            DelegationDepth(jwt));
    }

    /// <summary>
    /// Space-delimited, case-sensitive, per RFC 6749 §3.3.
    /// </summary>
    private static IReadOnlySet<string> ParseScope(string? scope) =>
        string.IsNullOrWhiteSpace(scope)
            ? new HashSet<string>(StringComparer.Ordinal)
            : new HashSet<string>(
                scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                StringComparer.Ordinal);

    /// <summary>
    /// Counts nested <c>act</c> claims (RFC 8693 §4.1). A token obtained directly by the
    /// user has no <c>act</c> and therefore depth 0.
    /// </summary>
    /// <remarks>
    /// Recursive rather than a presence check so that raising
    /// <see cref="ExchangePolicy.MaxDelegationDepth"/> stays a one-constant change.
    /// </remarks>
    private static int DelegationDepth(JsonWebToken jwt)
    {
        if (!jwt.TryGetPayloadValue<JsonElement>("act", out var act) || act.ValueKind != JsonValueKind.Object)
        {
            return 0;
        }

        var depth = 1;
        while (act.TryGetProperty("act", out var nested) && nested.ValueKind == JsonValueKind.Object)
        {
            depth++;
            act = nested;
        }

        return depth;
    }
}
