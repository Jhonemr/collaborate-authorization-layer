using Collaborate.TokenExchange.Domain;
using Collaborate.TokenExchange.Exchange;
using Collaborate.TokenExchange.Infrastructure;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// The audience Collaborate's own API is addressed by — i.e. what a valid *subject*
// token is issued for. Checking it stops a token minted for some other service being
// presented here as a subject token.
const string CollaborateApiAudience = "https://api.collaborate.caseware.com";
const string Issuer = "https://auth.collaborate.caseware.com";
const string TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange";
const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";

builder.Services.AddSingleton<TokenKeys>();
builder.Services.AddSingleton(new TokenIssuerOptions { Issuer = Issuer });

builder.Services.AddSingleton<IClientRegistry, InMemoryClientRegistry>();
builder.Services.AddSingleton<IActorEntitlementStore, InMemoryActorEntitlementStore>();
builder.Services.AddSingleton<IPermissionQuery, StubPermissionQuery>();
builder.Services.AddSingleton<InMemoryClientAuthenticator>();

builder.Services.AddSingleton(sp => new SubjectTokenValidator(
    new TokenValidationParameters
    {
        ValidIssuer = Issuer,
        ValidAudience = CollaborateApiAudience,
        IssuerSigningKey = sp.GetRequiredService<TokenKeys>().SecurityKey,

        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateIssuerSigningKey = true,
        ValidateLifetime = true,

        // Tighter than the five-minute default. Exchanged tokens live 60 seconds, so a
        // generous skew allowance would be a large fraction of their lifetime.
        ClockSkew = TimeSpan.FromSeconds(30),
    },
    sp.GetRequiredService<ILogger<SubjectTokenValidator>>()));

builder.Services.AddSingleton<DelegatedTokenIssuer>();
builder.Services.AddSingleton<TokenExchangeService>();

var app = builder.Build();

// ---------------------------------------------------------------------------
// RFC 8693 token exchange.
//
// Mounted on the token endpoint as an additional grant_type rather than as a bespoke
// route, because that is what the spec says it is: a grant, not a new protocol. A
// production deployment folds this into the authorization server's own token endpoint
// (an IExtensionGrantValidator in Duende, a custom grant handler in OpenIddict) — the
// evaluation and issuing code below is unchanged by that move.
// ---------------------------------------------------------------------------
app.MapPost("/connect/token", async (
    HttpRequest http,
    TokenExchangeService exchange,
    InMemoryClientAuthenticator authenticator,
    CancellationToken ct) =>
{
    if (!http.HasFormContentType)
    {
        return OAuthResponse.BadRequest(OAuthError.InvalidRequest, "Expected application/x-www-form-urlencoded.");
    }

    var form = await http.ReadFormAsync(ct);

    if (form["grant_type"].ToString() != TokenExchangeGrantType)
    {
        return OAuthResponse.BadRequest("unsupported_grant_type", "Only token-exchange is supported at this endpoint.");
    }

    // Authenticate the caller before reading anything else it sent. Everything after
    // this point is attributed to a known client.
    var clientId = authenticator.Authenticate(form["client_id"], form["client_secret"]);
    if (clientId is null)
    {
        return OAuthResponse.Unauthorized("invalid_client", "Client authentication failed.");
    }

    var subjectToken = form["subject_token"].ToString();
    if (string.IsNullOrWhiteSpace(subjectToken))
    {
        return OAuthResponse.BadRequest(OAuthError.InvalidRequest, "subject_token is required.");
    }

    // RFC 8693 §2.1 makes audience optional, but an unpinned token is the confused-deputy
    // problem restated. We require it: no audience, no token.
    var audience = form["audience"].ToString();
    if (string.IsNullOrWhiteSpace(audience))
    {
        return OAuthResponse.BadRequest(OAuthError.InvalidTarget, "audience is required; tokens are never issued unpinned.");
    }

    var subjectTokenType = form["subject_token_type"].ToString();
    if (string.IsNullOrWhiteSpace(subjectTokenType))
    {
        subjectTokenType = AccessTokenType;
    }

    var scope = form["scope"].ToString();
    var requestedScopes = string.IsNullOrWhiteSpace(scope)
        ? null
        : new HashSet<string>(
            scope.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
            StringComparer.Ordinal);

    var result = await exchange.ExchangeAsync(
        clientId,
        new TokenExchangeRequest(subjectToken, subjectTokenType, audience, requestedScopes),
        ct);

    return result switch
    {
        ExchangeResult.Issued issued => Results.Json(new
        {
            access_token = issued.AccessToken,
            issued_token_type = AccessTokenType,
            token_type = "Bearer",
            expires_in = issued.ExpiresIn,
            scope = issued.Scope,
        }),

        ExchangeResult.Failed failed => OAuthResponse.BadRequest(failed.Error, failed.Description),

        _ => OAuthResponse.BadRequest(OAuthError.InvalidRequest, "Exchange could not be evaluated."),
    };
});

app.Run();

/// <summary>OAuth error responses per RFC 6749 §5.2.</summary>
internal static class OAuthResponse
{
    public static IResult BadRequest(string error, string description) =>
        Results.Json(new { error, error_description = description }, statusCode: StatusCodes.Status400BadRequest);

    public static IResult Unauthorized(string error, string description) =>
        Results.Json(new { error, error_description = description }, statusCode: StatusCodes.Status401Unauthorized);
}

/// <summary>Exposed so the integration tests can host the app in-process.</summary>
public partial class Program;
