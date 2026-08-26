using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.TokenExchange.Exchange;

/// <summary>
/// Signing material for this authorization server.
/// </summary>
/// <remarks>
/// A single in-memory RSA key generated at startup, which is what makes this runnable
/// with no identity provider behind it. Two things would differ in production, and
/// neither changes the code above this class:
///
///  - Keys would come from a managed store (AWS KMS or Secrets Manager) with rotation,
///    and be published at a JWKS endpoint for downstream services to fetch.
///  - Subject tokens and issued tokens would be verified against *different* keys —
///    subject tokens are signed by Caseware's IdP or by our own login flow, whereas
///    issued tokens are signed by this service. Sharing one key here keeps the demo
///    self-contained; <see cref="SubjectTokenValidator"/> takes its key separately so
///    that separation is a configuration change, not a rewrite.
///
/// Asymmetric rather than symmetric on purpose: downstream services must be able to
/// verify without holding anything that lets them mint.
/// </remarks>
public sealed class TokenKeys : IDisposable
{
    private readonly RSA _rsa;

    public TokenKeys()
    {
        _rsa = RSA.Create(2048);
        SecurityKey = new RsaSecurityKey(_rsa) { KeyId = "collaborate-dev-1" };
        SigningCredentials = new SigningCredentials(SecurityKey, SecurityAlgorithms.RsaSha256);
    }

    public RsaSecurityKey SecurityKey { get; }

    public SigningCredentials SigningCredentials { get; }

    public void Dispose() => _rsa.Dispose();
}
