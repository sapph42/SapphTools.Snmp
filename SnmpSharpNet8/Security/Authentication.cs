using System.Security.Cryptography;

namespace SnmpSharpNet8.Security;

public class Authentication {
    private readonly HashAlgorithmName _hashName;

    public int AuthHeaderLength { get; private set; }
    public string Name { get; }

    public Authentication(AuthenticationDigest algo) {
        (_hashName, AuthHeaderLength) = algo switch {
            AuthenticationDigest.MD5 => (HashAlgorithmName.MD5, 12),
            AuthenticationDigest.SHA1 => (HashAlgorithmName.SHA1, 12),
            AuthenticationDigest.SHA256 => (HashAlgorithmName.SHA256, 24),
            AuthenticationDigest.SHA384 => (HashAlgorithmName.SHA384, 32),
            AuthenticationDigest.SHA512 => (HashAlgorithmName.SHA512, 48),
            _ => throw new ArgumentOutOfRangeException(nameof(algo))
        };
        Name = $"HMAC-{_hashName.Name}";
    }
    public ReadOnlySpan<byte> Authenticate(byte[] key, ReadOnlySpan<byte> wholeMessage) {
        using IncrementalHash hmac = IncrementalHash.CreateHMAC(_hashName, key);
        hmac.AppendData(wholeMessage);
        ReadOnlySpan<byte> full = hmac.GetHashAndReset();
        return full[..AuthHeaderLength];
    }

    public bool AuthenticateIncomingMsg(
            byte[] key,
            ReadOnlySpan<byte> authenticationParameters,   // the digest extracted from the received message
            ReadOnlySpan<byte> wholeMessage) {              // MUST already have the auth field zeroed
        using var hmac = IncrementalHash.CreateHMAC(_hashName, key);
        hmac.AppendData(wholeMessage);
        ReadOnlySpan<byte> computed = hmac.GetHashAndReset();

        return CryptographicOperations.FixedTimeEquals(
            computed[..AuthHeaderLength],
            authenticationParameters[..AuthHeaderLength]);
    }

    public byte[] PasswordToKey(byte[] password, ReadOnlySpan<byte> engineId) {
        using var inc = IncrementalHash.CreateHash(_hashName);
        byte[] buf = new byte[64];
        int produced = 0;
        while (produced < 1048576) {
            for (int i = 0; i < 64; i++)
                buf[i] = password[(produced + i) % password.Length];
            inc.AppendData(buf);
            produced += 64;
        }
        byte[] ku = inc.GetHashAndReset();
        inc.AppendData(ku);
        inc.AppendData(engineId);
        inc.AppendData(ku);
        return inc.GetHashAndReset();           // localized key
    }
}
