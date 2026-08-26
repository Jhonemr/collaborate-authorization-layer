using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Collaborate.TokenExchange.Exchange;
using Collaborate.TokenExchange.Infrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Collaborate.TokenExchange.Tests;

/// <summary>
/// End-to-end coverage of the exchange endpoint over real HTTP.
/// </summary>
/// <remarks>
/// <see cref="ExchangePolicyTests"/> covers the decision matrix; these tests cover what
/// only shows up once the wiring is real — that a rejected token never reaches the
/// policy, that the issued JWT actually carries the claims the design promises, and that
/// each refusal surfaces as the right OAuth error code and status.
/// </remarks>
public class TokenExchangeEndpointTests : IClassFixture<WebApplicationFactory<Program>>
{
    private const string Issuer = "https://auth.collaborate.caseware.com";
    private const string ApiAudience = "https://api.collaborate.caseware.com";
    private const string AcmeSecret = "acme-erp-development-secret";

    private readonly WebApplicationFactory<Program> _factory;

    public TokenExchangeEndpointTests(WebApplicationFactory<Program> factory) => _factory = factory;

    // ------------------------------------------------------------- happy path

    [Fact]
    public async Task Issues_a_narrowed_audience_pinned_token_carrying_an_act_claim()
    {
        var response = await Exchange(new()
        {
            ["client_id"] = Seed.AcmeErpClient,
            ["client_secret"] = AcmeSecret,
            ["subject_token"] = MintSubjectToken("user-acme-1", "firm-acme", "documents.read financial.read"),
            ["audience"] = Seed.DocumentsApi,
            ["scope"] = "documents.read",
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await ReadJson(response);
        Assert.Equal("Bearer", body.GetProperty("token_type").GetString());
        Assert.Equal("urn:ietf:params:oauth:token-type:access_token", body.GetProperty("issued_token_type").GetString());
        Assert.Equal("documents.read", body.GetProperty("scope").GetString());

        // Short-lived by design — the token expires faster than the revocation SLA.
        Assert.InRange(body.GetProperty("expires_in").GetInt32(), 1, 300);

        var issued = new JsonWebTokenHandler().ReadJsonWebToken(body.GetProperty("access_token").GetString());

        // Pinned to exactly one downstream service.
        Assert.Equal([Seed.DocumentsApi], issued.Audiences);

        // Still the user's token: attributable to them for permission checks and audit.
        Assert.Equal("user-acme-1", issued.Subject);

        // ...but the acting party is recorded (RFC 8693 §4.1), so a delegated call is
        // distinguishable from one the user made directly.
        Assert.True(issued.TryGetPayloadValue<JsonElement>("act", out var act));
        Assert.Equal(Seed.AcmeErpClient, act.GetProperty("sub").GetString());

        Assert.Equal("documents.read", issued.GetPayloadValue<string>("scope"));
    }

    [Fact]
    public async Task Narrows_silently_when_the_user_has_lost_a_scope_since_the_token_was_issued()
    {
        // user-acme-2's subject token still carries financial.read, but the PDP no longer
        // grants it. This is the test that proves the PDP is consulted at mint time —
        // without that call, the stale scope would be echoed straight through.
        var response = await Exchange(new()
        {
            ["client_id"] = Seed.AcmeErpClient,
            ["client_secret"] = AcmeSecret,
            ["subject_token"] = MintSubjectToken("user-acme-2", "firm-acme", "documents.read financial.read"),
            ["audience"] = Seed.DocumentsApi,
        });

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await ReadJson(response);
        Assert.Equal("documents.read", body.GetProperty("scope").GetString());
    }

    // ------------------------------------------------------- the firm boundary

    [Fact]
    public async Task Refuses_to_mint_for_a_user_outside_the_clients_own_firm()
    {
        // The confused deputy in its purest form here: Acme's integration asking for a
        // token that acts for a Globex user.
        var response = await Exchange(new()
        {
            ["client_id"] = Seed.AcmeErpClient,
            ["client_secret"] = AcmeSecret,
            ["subject_token"] = MintSubjectToken("user-globex-1", "firm-globex", "documents.read"),
            ["audience"] = Seed.DocumentsApi,
            ["scope"] = "documents.read",
        });

        await AssertOAuthError(response, HttpStatusCode.BadRequest, "unauthorized_client");
    }

    // ----------------------------------------------------------- other controls

    [Fact]
    public async Task Refuses_an_audience_the_client_is_not_registered_against()
    {
        var response = await Exchange(new()
        {
            ["client_id"] = Seed.AcmeErpClient,
            ["client_secret"] = AcmeSecret,
            ["subject_token"] = MintSubjectToken("user-acme-1", "firm-acme", "documents.read"),
            ["audience"] = Seed.CommentsApi,
            ["scope"] = "documents.read",
        });

        await AssertOAuthError(response, HttpStatusCode.BadRequest, "invalid_target");
    }

    [Fact]
    public async Task Refuses_a_scope_above_the_client_ceiling()
    {
        var response = await Exchange(new()
        {
            ["client_id"] = Seed.AcmeErpClient,
            ["client_secret"] = AcmeSecret,
            ["subject_token"] = MintSubjectToken("user-acme-1", "firm-acme", "documents.read documents.write"),
            ["audience"] = Seed.DocumentsApi,
            ["scope"] = "documents.write",
        });

        await AssertOAuthError(response, HttpStatusCode.BadRequest, "invalid_scope");
    }

    [Fact]
    public async Task Refuses_a_request_with_no_audience_rather_than_issuing_an_unpinned_token()
    {
        var response = await Exchange(new()
        {
            ["client_id"] = Seed.AcmeErpClient,
            ["client_secret"] = AcmeSecret,
            ["subject_token"] = MintSubjectToken("user-acme-1", "firm-acme", "documents.read"),
            ["scope"] = "documents.read",
        });

        await AssertOAuthError(response, HttpStatusCode.BadRequest, "invalid_target");
    }

    [Fact]
    public async Task Refuses_a_subject_token_that_has_already_been_delegated()
    {
        var response = await Exchange(new()
        {
            ["client_id"] = Seed.AcmeErpClient,
            ["client_secret"] = AcmeSecret,
            ["subject_token"] = MintSubjectToken(
                "user-acme-1", "firm-acme", "documents.read",
                act: new Dictionary<string, object> { ["sub"] = "some-other-service" }),
            ["audience"] = Seed.DocumentsApi,
            ["scope"] = "documents.read",
        });

        await AssertOAuthError(response, HttpStatusCode.BadRequest, "invalid_grant");
    }

    // ------------------------------------------------------- token authenticity

    [Fact]
    public async Task Refuses_an_expired_subject_token()
    {
        var response = await Exchange(new()
        {
            ["client_id"] = Seed.AcmeErpClient,
            ["client_secret"] = AcmeSecret,
            ["subject_token"] = MintSubjectToken(
                "user-acme-1", "firm-acme", "documents.read",
                lifetime: TimeSpan.FromMinutes(-5)),
            ["audience"] = Seed.DocumentsApi,
        });

        await AssertOAuthError(response, HttpStatusCode.BadRequest, "invalid_grant");
    }

    [Fact]
    public async Task Refuses_a_subject_token_signed_by_an_unknown_key()
    {
        using var rogue = RSA.Create(2048);
        var rogueCredentials = new SigningCredentials(
            new RsaSecurityKey(rogue), SecurityAlgorithms.RsaSha256);

        var response = await Exchange(new()
        {
            ["client_id"] = Seed.AcmeErpClient,
            ["client_secret"] = AcmeSecret,
            ["subject_token"] = MintSubjectToken(
                "user-acme-1", "firm-acme", "documents.read",
                credentials: rogueCredentials),
            ["audience"] = Seed.DocumentsApi,
        });

        await AssertOAuthError(response, HttpStatusCode.BadRequest, "invalid_grant");
    }

    [Fact]
    public async Task Refuses_a_subject_token_minted_for_a_different_audience()
    {
        // A token issued for some other service must not be usable as a subject token
        // here, or any service holding one could bootstrap delegation.
        var response = await Exchange(new()
        {
            ["client_id"] = Seed.AcmeErpClient,
            ["client_secret"] = AcmeSecret,
            ["subject_token"] = MintSubjectToken(
                "user-acme-1", "firm-acme", "documents.read",
                audience: "https://unrelated.example.com"),
            ["audience"] = Seed.DocumentsApi,
        });

        await AssertOAuthError(response, HttpStatusCode.BadRequest, "invalid_grant");
    }

    // -------------------------------------------------- client authentication

    [Fact]
    public async Task Rejects_a_wrong_client_secret_before_looking_at_the_subject_token()
    {
        var response = await Exchange(new()
        {
            ["client_id"] = Seed.AcmeErpClient,
            ["client_secret"] = "not-the-secret",
            ["subject_token"] = MintSubjectToken("user-acme-1", "firm-acme", "documents.read"),
            ["audience"] = Seed.DocumentsApi,
        });

        await AssertOAuthError(response, HttpStatusCode.Unauthorized, "invalid_client");
    }

    [Fact]
    public async Task Rejects_an_unsupported_grant_type()
    {
        var client = _factory.CreateClient();
        var response = await client.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string> { ["grant_type"] = "client_credentials" }));

        await AssertOAuthError(response, HttpStatusCode.BadRequest, "unsupported_grant_type");
    }

    // ------------------------------------------------------------------ helpers

    private Task<HttpResponseMessage> Exchange(Dictionary<string, string> form)
    {
        form["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange";
        form.TryAdd("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");

        return _factory.CreateClient().PostAsync("/connect/token", new FormUrlEncodedContent(form));
    }

    /// <summary>
    /// Mints a subject token with the host's own signing key, standing in for one issued
    /// by Caseware's identity provider.
    /// </summary>
    private string MintSubjectToken(
        string userId,
        string firmId,
        string scope,
        TimeSpan? lifetime = null,
        SigningCredentials? credentials = null,
        string? audience = null,
        Dictionary<string, object>? act = null)
    {
        var keys = _factory.Services.GetRequiredService<TokenKeys>();

        var claims = new Dictionary<string, object>
        {
            ["sub"] = userId,
            ["firm_id"] = firmId,
            ["scope"] = scope,
        };

        if (act is not null)
        {
            claims["act"] = act;
        }

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = Issuer,
            Audience = audience ?? ApiAudience,
            Expires = DateTime.UtcNow.Add(lifetime ?? TimeSpan.FromMinutes(5)),
            SigningCredentials = credentials ?? keys.SigningCredentials,
            Claims = claims,
        });
    }

    private static async Task<JsonElement> ReadJson(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsStringAsync()).RootElement;

    private static async Task AssertOAuthError(
        HttpResponseMessage response, HttpStatusCode expectedStatus, string expectedError)
    {
        Assert.Equal(expectedStatus, response.StatusCode);

        var body = await ReadJson(response);
        Assert.Equal(expectedError, body.GetProperty("error").GetString());

        // No token is ever present on a refusal path.
        Assert.False(body.TryGetProperty("access_token", out _));
    }
}
