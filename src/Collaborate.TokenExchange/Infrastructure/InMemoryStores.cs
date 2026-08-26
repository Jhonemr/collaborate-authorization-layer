using System.Security.Cryptography;
using System.Text;
using Collaborate.TokenExchange.Domain;

namespace Collaborate.TokenExchange.Infrastructure;

/// <summary>
/// Stand-ins for the stores described in Part 1. Each sits behind the interface the real
/// implementation would satisfy, so swapping in the database-backed and Redis-backed
/// versions changes composition only.
/// </summary>
public static class Seed
{
    public const string DocumentsApi = "https://documents.collaborate.caseware.com";
    public const string FinancialApi = "https://financial.collaborate.caseware.com";
    public const string CommentsApi = "https://comments.collaborate.caseware.com";

    /// <summary>A firm's own integration — may act only for that firm's users.</summary>
    public const string AcmeErpClient = "acme-erp";

    /// <summary>A first-party Caseware service — may act for any user, in any firm.</summary>
    public const string NotificationService = "collaborate-notifications";
}

public sealed class InMemoryClientRegistry : IClientRegistry
{
    private readonly Dictionary<string, ClientRegistration> _clients = new(StringComparer.Ordinal)
    {
        [Seed.AcmeErpClient] = new(
            Seed.AcmeErpClient,
            new ActorConstraint.SameFirmOnly("firm-acme"),
            AllowedAudiences: new HashSet<string>(StringComparer.Ordinal) { Seed.DocumentsApi, Seed.FinancialApi },

            // Read-only: this integration pulls engagement data, it never writes. The
            // ceiling holds even when the acting user is a workspace owner.
            ScopeCeiling: new HashSet<string>(StringComparer.Ordinal) { "documents.read", "financial.read" }),

        [Seed.NotificationService] = new(
            Seed.NotificationService,
            new ActorConstraint.AnyFirm(),
            AllowedAudiences: new HashSet<string>(StringComparer.Ordinal) { Seed.CommentsApi },
            ScopeCeiling: new HashSet<string>(StringComparer.Ordinal) { "comments.read" }),
    };

    public ClientRegistration? Find(string clientId) =>
        _clients.TryGetValue(clientId, out var client) ? client : null;
}

/// <summary>
/// Whether a user has authorised a given integration. In production this is a durable
/// consent record, revocable by the user.
/// </summary>
public sealed class InMemoryActorEntitlementStore : IActorEntitlementStore
{
    private readonly HashSet<(string ClientId, string UserId)> _grants =
    [
        (Seed.AcmeErpClient, "user-acme-1"),
        (Seed.AcmeErpClient, "user-acme-2"),

        // Deliberately wrong, and load-bearing for the test suite: Acme's integration is
        // granted consent for a *Globex* user, i.e. this store is misconfigured exactly
        // the way a real consent store could be. The firm-boundary check in
        // ExchangePolicy is structural and runs anyway, so the exchange still refuses.
        // Without this entry the cross-firm test would pass on a missing consent record
        // and never exercise the invariant it exists to protect.
        (Seed.AcmeErpClient, "user-globex-1"),
    ];

    public Task<bool> MayActForAsync(string clientId, string userId, CancellationToken ct) =>
        // First-party services act for whoever triggered them, so they carry no per-user
        // consent record. The firm-boundary invariant still applies to them.
        Task.FromResult(clientId == Seed.NotificationService || _grants.Contains((clientId, userId)));
}

/// <summary>
/// Stands in for the Redis-backed PDP. The shape that matters is the signature: one
/// lookup by user, returning current scopes — cheap enough to sit on the mint path.
/// </summary>
public sealed class StubPermissionQuery : IPermissionQuery
{
    private readonly Dictionary<string, HashSet<string>> _current = new(StringComparer.Ordinal)
    {
        ["user-acme-1"] = new(StringComparer.Ordinal) { "documents.read", "financial.read" },

        // Deliberately reduced: this user's financial.read was revoked after their token
        // was issued. Exercises the silent-narrowing path end to end.
        ["user-acme-2"] = new(StringComparer.Ordinal) { "documents.read" },

        ["user-globex-1"] = new(StringComparer.Ordinal) { "documents.read", "comments.read" },
    };

    public Task<IReadOnlySet<string>> GetCurrentScopesAsync(string userId, CancellationToken ct) =>
        Task.FromResult<IReadOnlySet<string>>(
            _current.TryGetValue(userId, out var scopes)
                ? scopes
                : new HashSet<string>(StringComparer.Ordinal));
}

/// <summary>
/// Client authentication for the token endpoint.
/// </summary>
/// <remarks>
/// <c>client_secret_post</c> (RFC 6749 §2.3.1). Adequate for demonstrating the exchange,
/// but a production deployment handling cross-organisational delegation should require
/// <c>private_key_jwt</c> or mTLS instead — a shared secret is replayable by anyone who
/// obtains it, and these clients act on behalf of other people's users.
/// </remarks>
public sealed class InMemoryClientAuthenticator
{
    private readonly Dictionary<string, string> _secrets = new(StringComparer.Ordinal)
    {
        [Seed.AcmeErpClient] = "acme-erp-development-secret",
        [Seed.NotificationService] = "notifications-development-secret",
    };

    public string? Authenticate(string? clientId, string? clientSecret)
    {
        if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
        {
            return null;
        }

        if (!_secrets.TryGetValue(clientId, out var expected))
        {
            return null;
        }

        // Fixed-time comparison so a caller cannot recover a secret byte by byte from
        // response timing.
        var match = CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(clientSecret),
            Encoding.UTF8.GetBytes(expected));

        return match ? clientId : null;
    }
}
