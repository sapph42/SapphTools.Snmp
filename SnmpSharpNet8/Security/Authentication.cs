using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace SnmpSharpNet8.Security;

public class Authentication {
    private readonly HashAlgorithmName _hashName;
    private int keyLength;

    public int AuthHeaderLength { get; private set; }
    public string Name { get; }

    public Authentication(AuthenticationDigest algo) {
        (_hashName, AuthHeaderLength) = algo switch {
            AuthenticationDigest.MD5 => (HashAlgorithmName.MD5, 12),
            AuthenticationDigest.SHA1 => (HashAlgorithmName.SHA1, 12),
            AuthenticationDigest.SHA256 => (HashAlgorithmName.SHA256, 24),
            AuthenticationDigest.SHA384 => (HashAlgorithmName.SHA384, 32),
            AuthenticationDigest.SHA512 => (HashAlgorithmName.SHA512, 48),
            AuthenticationDigest.None => throw new NotImplementedException(),
            _ => throw new ArgumentOutOfRangeException(nameof(algo))
        };
        Name = $"HMAC-{_hashName.Name}";
        keyLength = IncrementalHash.CreateHash(_hashName).HashLengthInBytes;
    }
    public ReadOnlySpan<byte> Authenticate(Span<byte> key, ReadOnlySpan<byte> wholeMessage) {
        Debug.WriteLine("");
        Debug.WriteLine("");
        Debug.WriteLine($"Hash Requested              : {_hashName.Name}");
        key = key[..keyLength];
        Debug.WriteLine($"Pre-Hash Auth Message  [{wholeMessage.Length:D3}]: {
            string.Join(' ', wholeMessage.ToArray().Select(b => Convert.ToHexString([b])))
            }");
        Debug.WriteLine($"Auth Key               [{key.Length:D3}]: {
            string.Join(' ', key.ToArray().Select(b => Convert.ToHexString([b])))
            }");
        using IncrementalHash hmac = IncrementalHash.CreateHMAC(_hashName, key);
        hmac.AppendData(wholeMessage);
        ReadOnlySpan<byte> full = hmac.GetHashAndReset();
        Debug.WriteLine($"{AuthHeaderLength} Char Calc'ed HMAC    [{AuthHeaderLength}]: {
            string.Join(' ', full[..AuthHeaderLength].ToArray().Select(b => Convert.ToHexString([b])))
            }");
        return full[..AuthHeaderLength];
    }

    public bool AuthenticateIncomingMsg(
            Span<byte> key,
            ReadOnlySpan<byte> authenticationParameters,   // the digest extracted from the received message
            ReadOnlySpan<byte> wholeMessage) {              // MUST already have the auth field zeroed
        using IncrementalHash hmac = IncrementalHash.CreateHMAC(_hashName, key);
        hmac.AppendData(wholeMessage);
        ReadOnlySpan<byte> computed = hmac.GetHashAndReset();

        return CryptographicOperations.FixedTimeEquals(
            computed[..AuthHeaderLength],
            authenticationParameters[..AuthHeaderLength]);
    }

    public Span<byte> PasswordToKey(Span<byte> password, ReadOnlySpan<byte> engineId) {
        Debug.WriteLine("");
        Debug.WriteLine("");
        Debug.WriteLine($"Secret To Key Convert       : {_hashName.Name}");
        using IncrementalHash inc = IncrementalHash.CreateHash(_hashName);
        Span<byte> buf = stackalloc byte[64];
        int produced = 0;
        while (produced < 1048576) {
            for (int i = 0; i < 64; i++) {
                buf[i] = password[(produced + i) % password.Length];
            }
            inc.AppendData(buf);
            produced += 64;
        }
        byte[] ku = inc.GetHashAndReset();
        Debug.WriteLine($"KU                     [{ku.Length:D3}]: {string.Join(' ', ku.Select(b => Convert.ToHexString([b])))}");
        inc.AppendData(ku);
        inc.AppendData(engineId);
        inc.AppendData(ku);
        return inc.GetHashAndReset();
    }
}
