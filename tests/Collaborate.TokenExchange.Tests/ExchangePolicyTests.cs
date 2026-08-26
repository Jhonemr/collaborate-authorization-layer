using Collaborate.TokenExchange.Domain;
using Xunit;

namespace Collaborate.TokenExchange.Tests;

/// <summary>
/// The decision matrix for <see cref="ExchangePolicy"/>.
/// </summary>
/// <remarks>
/// Grouped by the control each test exercises. The negative cases matter more than the
/// positive one here: a bug in this code grants access rather than throwing, so the
/// tests that prove something is *refused* are the ones carrying the weight.
/// </remarks>
public class ExchangePolicyTests
{
    private const string Documents = "https://documents.collaborate.caseware.com";
    private const string Financial = "https://financial.collaborate.caseware.com";

    // ---------------------------------------------------------------- happy path

    [Fact]
    public void Grants_the_intersection_when_every_ceiling_permits()
    {
        var decision = ExchangePolicy.Evaluate(
            Client(ceiling: ["documents.read", "documents.write"]),
            Subject(scopes: ["documents.read", "documents.write", "financial.read"]),
            Request(scopes: ["documents.read"]),
            currentUserScopes: Set("documents.read", "documents.write"));

        var granted = Assert.IsType<ExchangeDecision.Granted>(decision);
        AssertScopes(granted.Scopes, "documents.read");
        Assert.Empty(granted.DroppedByPolicy);
    }

    [Fact]
    public void Grants_the_full_intersection_when_scope_is_omitted()
    {
        // RFC 8693 §2.1 allows omitting scope; the result must still be narrowed by both
        // static ceilings rather than echoing the subject token back.
        var decision = ExchangePolicy.Evaluate(
            Client(ceiling: ["documents.read"]),
            Subject(scopes: ["documents.read", "documents.write", "financial.read"]),
            Request(scopes: null),
            currentUserScopes: Set("documents.read", "documents.write", "financial.read"));

        var granted = Assert.IsType<ExchangeDecision.Granted>(decision);
        AssertScopes(granted.Scopes, "documents.read");
    }

    // ------------------------------------------------- control 1: firm boundary

    [Fact]
    public void Refuses_when_the_client_and_subject_belong_to_different_firms()
    {
        var decision = ExchangePolicy.Evaluate(
            Client(constraint: new ActorConstraint.SameFirmOnly("firm-acme")),
            Subject(firmId: "firm-globex"),
            Request(),
            currentUserScopes: Set("documents.read", "documents.write"));

        AssertRefused(decision, OAuthError.UnauthorizedClient);
    }

    [Fact]
    public void Refuses_cross_firm_delegation_even_when_every_other_control_would_pass()
    {
        // The structural invariant from the design: firm A's integration must not be able
        // to reach firm B's user by any combination of otherwise-valid inputs. If this
        // test ever goes green by being deleted, the confused deputy is back.
        var decision = ExchangePolicy.Evaluate(
            Client(
                constraint: new ActorConstraint.SameFirmOnly("firm-acme"),
                audiences: [Documents],
                ceiling: ["documents.read"]),
            Subject(firmId: "firm-globex", scopes: ["documents.read"]),
            Request(audience: Documents, scopes: ["documents.read"]),
            currentUserScopes: Set("documents.read"));

        AssertRefused(decision, OAuthError.UnauthorizedClient);
    }

    [Fact]
    public void First_party_services_may_act_for_users_in_any_firm()
    {
        // Scenario (b): a notification service acting for whoever posted the comment.
        var decision = ExchangePolicy.Evaluate(
            Client(constraint: new ActorConstraint.AnyFirm()),
            Subject(firmId: "firm-globex"),
            Request(scopes: ["documents.read"]),
            currentUserScopes: Set("documents.read"));

        Assert.IsType<ExchangeDecision.Granted>(decision);
    }

    // ---------------------------------------------- control 2: audience pinning

    [Fact]
    public void Refuses_an_audience_the_client_is_not_registered_for()
    {
        var decision = ExchangePolicy.Evaluate(
            Client(audiences: [Documents]),
            Subject(),
            Request(audience: Financial),
            currentUserScopes: Set("documents.read", "documents.write"));

        AssertRefused(decision, OAuthError.InvalidTarget);
    }

    // ------------------------------------------- control 3: scope as intersection

    [Fact]
    public void Refuses_a_scope_the_subject_token_never_carried()
    {
        var decision = ExchangePolicy.Evaluate(
            Client(ceiling: ["documents.read", "financial.read"]),
            Subject(scopes: ["documents.read"]),
            Request(scopes: ["documents.read", "financial.read"]),
            currentUserScopes: Set("documents.read", "financial.read"));

        AssertRefused(decision, OAuthError.InvalidScope);
    }

    [Fact]
    public void Refuses_a_scope_above_the_client_ceiling_even_when_the_user_holds_it()
    {
        // A privileged user's token must not lift a client above its own ceiling —
        // otherwise a low-trust integration escalates simply by being used by an owner.
        var decision = ExchangePolicy.Evaluate(
            Client(ceiling: ["documents.read"]),
            Subject(scopes: ["documents.read", "financial.read"]),
            Request(scopes: ["financial.read"]),
            currentUserScopes: Set("documents.read", "financial.read"));

        AssertRefused(decision, OAuthError.InvalidScope);
    }

    [Fact]
    public void Scope_matching_is_case_sensitive()
    {
        // RFC 6749 §3.3. Case-insensitive comparison here would let a caller step over a
        // ceiling by re-casing a scope it was never granted.
        var decision = ExchangePolicy.Evaluate(
            Client(ceiling: ["documents.read"]),
            Subject(scopes: ["documents.read"]),
            Request(scopes: ["Documents.Read"]),
            currentUserScopes: Set("documents.read"));

        AssertRefused(decision, OAuthError.InvalidScope);
    }

    // ------------------------------------- the escalation / staleness distinction

    [Fact]
    public void Drops_a_scope_the_user_has_since_lost_without_failing_the_exchange()
    {
        // This is the test that proves the PDP is consulted at mint time: the subject
        // token still carries documents.write, but the user's permission was revoked
        // after it was issued. Ordinary staleness — narrow, report, do not break.
        var decision = ExchangePolicy.Evaluate(
            Client(ceiling: ["documents.read", "documents.write"]),
            Subject(scopes: ["documents.read", "documents.write"]),
            Request(scopes: ["documents.read", "documents.write"]),
            currentUserScopes: Set("documents.read"));

        var granted = Assert.IsType<ExchangeDecision.Granted>(decision);
        AssertScopes(granted.Scopes, "documents.read");
        AssertScopes(granted.DroppedByPolicy, "documents.write");
    }

    [Fact]
    public void Refuses_when_no_scope_survives_the_current_permission_check()
    {
        // A fully-revoked user must not receive a scopeless token: a downstream service
        // reading an absent scope claim as "unrestricted" would invert the outcome.
        var decision = ExchangePolicy.Evaluate(
            Client(ceiling: ["documents.read"]),
            Subject(scopes: ["documents.read"]),
            Request(scopes: ["documents.read"]),
            currentUserScopes: Set());

        AssertRefused(decision, OAuthError.InvalidScope);
    }

    // ------------------------------------------------ control 4: delegation depth

    [Fact]
    public void Refuses_a_subject_token_that_has_already_been_delegated()
    {
        var decision = ExchangePolicy.Evaluate(
            Client(),
            Subject(depth: 1),
            Request(scopes: ["documents.read"]),
            currentUserScopes: Set("documents.read"));

        AssertRefused(decision, OAuthError.InvalidGrant);
    }

    // ------------------------------------------------------------- the invariant

    [Theory]
    [InlineData("documents.read documents.write", "documents.read documents.write", "documents.read")]
    [InlineData("documents.read", "documents.read financial.read", "documents.read")]
    [InlineData("documents.read documents.write financial.read", "documents.write", "documents.write")]
    public void Granted_scope_never_exceeds_any_ceiling(string subjectScopes, string clientCeiling, string currentScopes)
    {
        var subject = Subject(scopes: subjectScopes.Split(' '));
        var client = Client(ceiling: clientCeiling.Split(' '));
        var current = Set(currentScopes.Split(' '));

        // Ask for everything, with scope omitted, so the evaluator has maximum latitude.
        var decision = ExchangePolicy.Evaluate(client, subject, Request(scopes: null), current);

        // Assert Granted rather than guarding on it: a regression that refused every
        // case would otherwise satisfy this test without ever checking the invariant.
        var granted = Assert.IsType<ExchangeDecision.Granted>(decision);
        var issued = granted.Scopes.ToHashSet(StringComparer.Ordinal);

        Assert.Subset(subject.Scopes.ToHashSet(StringComparer.Ordinal), issued);
        Assert.Subset(client.ScopeCeiling.ToHashSet(StringComparer.Ordinal), issued);
        Assert.Subset(current.ToHashSet(StringComparer.Ordinal), issued);
    }

    // ------------------------------------------------------------------ fixtures

    private static HashSet<string> Set(params string[] scopes) => new(scopes, StringComparer.Ordinal);

    private static ClientRegistration Client(
        ActorConstraint? constraint = null,
        IEnumerable<string>? audiences = null,
        IEnumerable<string>? ceiling = null) =>
        new(
            "client-acme-erp",
            constraint ?? new ActorConstraint.SameFirmOnly("firm-acme"),
            new HashSet<string>(audiences ?? [Documents], StringComparer.Ordinal),
            new HashSet<string>(ceiling ?? ["documents.read", "documents.write"], StringComparer.Ordinal));

    private static SubjectPrincipal Subject(
        string firmId = "firm-acme",
        IEnumerable<string>? scopes = null,
        int depth = 0) =>
        new(
            "user-1",
            firmId,
            new HashSet<string>(scopes ?? ["documents.read", "documents.write"], StringComparer.Ordinal),
            depth);

    private static TokenExchangeRequest Request(
        string audience = Documents,
        IEnumerable<string>? scopes = null) =>
        new(
            SubjectToken: "<opaque-in-these-tests>",
            SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
            Audience: audience,
            RequestedScopes: scopes is null ? null : new HashSet<string>(scopes, StringComparer.Ordinal));

    private static void AssertScopes(IReadOnlySet<string> actual, params string[] expected) =>
        Assert.Equal(
            expected.OrderBy(s => s, StringComparer.Ordinal),
            actual.OrderBy(s => s, StringComparer.Ordinal));

    private static void AssertRefused(ExchangeDecision decision, string expectedError)
    {
        var refused = Assert.IsType<ExchangeDecision.Refused>(decision);
        Assert.Equal(expectedError, refused.Error);
    }
}
