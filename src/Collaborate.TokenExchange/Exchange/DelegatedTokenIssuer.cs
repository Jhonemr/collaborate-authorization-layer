using Collaborate.TokenExchange.Domain;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.TokenExchange.Exchange;

public sealed class TokenIssuerOptions
{
    public string Issuer { get; init; } = "https://auth.collaborate.caseware.com";

    /// <summary>
    /// Short by design. An exchanged token expires faster than the revocation SLA in
    /// Part 1 §1B, which is why exchanged tokens need no revocation machinery of their
    /// own — the permission change that matters will be reflected at the next mint.
    /// </summary>
    public TimeSpan Lifetime { get; init; } = TimeSpan.FromSeconds(60);
}

/// <summary>
/// Mints the narrowed, audience-pinned token.
/// </summary>
/// <remarks>
/// <see cref="JsonWebTokenHandler.CreateToken(SecurityTokenDescriptor)"/> does the
/// signing. This class chooses <em>what</em> goes in the token; it does not implement
/// any part of <em>how</em> a token is produced.
/// </remarks>
public sealed class DelegatedTokenIssuer(TokenIssuerOptions options, TokenKeys keys)
{
    private readonly JsonWebTokenHandler _handler = new();

    public (string Token, int ExpiresIn) Issue(
        SubjectPrincipal subject,
        string actorClientId,
        string audience,
        IReadOnlySet<string> scopes)
    {
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = options.Issuer,

            // Exactly one audience. This is the control that stops the issued token being
            // replayed against a service the caller was never authorised to address.
            Audience = audience,

            Expires = DateTime.UtcNow.Add(options.Lifetime),
            SigningCredentials = keys.SigningCredentials,

            Claims = new Dictionary<string, object>
            {
                // The token remains the *user's*, which is what keeps a downstream
                // permission check and an audit trail attributable to them.
                ["sub"] = subject.UserId,
                ["firm_id"] = subject.FirmId,
                ["scope"] = string.Join(' ', scopes.Order(StringComparer.Ordinal)),

                // RFC 8693 §4.1. Delegation, not impersonation: the downstream service
                // and the audit log can both see who actually made the call. Dropping
                // this would make a delegated call indistinguishable from the user's own.
                ["act"] = new Dictionary<string, object>
                {
                    ["sub"] = actorClientId,
                },
            },
        };

        return (_handler.CreateToken(descriptor), (int)options.Lifetime.TotalSeconds);
    }
}
