using System.Diagnostics;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace SapphTools.Snmp.Security;

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
        key = key[..keyLength];
#if DEBUG
        Debug.WriteLine("");
        Debug.WriteLine("");
        Debug.WriteLine($"Hash Requested              : {_hashName.Name}");
        Debug.WriteLine($"Pre-Hash Auth Message  [{wholeMessage.Length:D3}]: {
            string.Join(' ', wholeMessage.ToArray().Select(b => Convert.ToHexString([b])))
            }");
        Debug.WriteLine($"Auth Key               [{key.Length:D3}]: {
            string.Join(' ', key.ToArray().Select(b => Convert.ToHexString([b])))
            }");
#endif
        using IncrementalHash hmac = IncrementalHash.CreateHMAC(_hashName, key);
        hmac.AppendData(wholeMessage);
        ReadOnlySpan<byte> full = hmac.GetHashAndReset();
#if DEBUG
        Debug.WriteLine($"{AuthHeaderLength} Char Calc'ed HMAC    [{AuthHeaderLength}]: {
            string.Join(' ', full[..AuthHeaderLength].ToArray().Select(b => Convert.ToHexString([b])))
            }");
#endif
        return full[..AuthHeaderLength];
    }

    public bool AuthenticateIncomingMsg(
            Span<byte> key,
            ReadOnlySpan<byte> authenticationParameters,   // the digest extracted from the received message
            ReadOnlySpan<byte> wholeMessage) {              // MUST already have the auth field zeroed
        key = key[..keyLength];
#if DEBUG
        Debug.WriteLine("");
        Debug.WriteLine("");
        Debug.WriteLine($"Auth Requested              : {_hashName.Name}");
        Debug.WriteLine($"Message To Verify Hash [{wholeMessage.Length:D3}]: {
            string.Join(' ', wholeMessage.ToArray().Select(b => Convert.ToHexString([b])))
            }");
        Debug.WriteLine($"Auth Key               [{key.Length:D3}]: {
            string.Join(' ', key.ToArray().Select(b => Convert.ToHexString([b])))
            }");
#endif
        using IncrementalHash hmac = IncrementalHash.CreateHMAC(_hashName, key);
        hmac.AppendData(wholeMessage);
        ReadOnlySpan<byte> computed = hmac.GetHashAndReset();
        bool match = CryptographicOperations.FixedTimeEquals(
            computed[..AuthHeaderLength],
            authenticationParameters[..AuthHeaderLength]);
#if DEBUG
        Debug.WriteLine($"{AuthHeaderLength} Char Calc'ed HMAC    [{AuthHeaderLength}]: {
            string.Join(' ', computed[..AuthHeaderLength].ToArray().Select(b => Convert.ToHexString([b])))
            }");
        Debug.WriteLine($"{authenticationParameters.Length} Char Given HMAC      [{AuthHeaderLength}]: {
            string.Join(' ', authenticationParameters[..AuthHeaderLength].ToArray().Select(b => Convert.ToHexString([b])))
            }");
        Debug.WriteLine($"HMAC Match                  : {match}");
#endif
        return match;
    }

    public Span<byte> PasswordToKey(Span<byte> password, ReadOnlySpan<byte> engineId) {
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
#if DEBUG
        Debug.WriteLine("");
        Debug.WriteLine("");
        Debug.WriteLine($"Secret To Key Convert       : {_hashName.Name}");
        Debug.WriteLine($"KU                     [{ku.Length:D3}]: {string.Join(' ', ku.Select(b => Convert.ToHexString([b])))}");
#endif
        inc.AppendData(ku);
        inc.AppendData(engineId);
        inc.AppendData(ku);
        return inc.GetHashAndReset();
    }
}
