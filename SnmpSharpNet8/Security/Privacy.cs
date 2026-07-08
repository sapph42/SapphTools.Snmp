using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace SnmpSharpNet8.Security;

public class Privacy {
    private readonly IPrivacyProtocol? cryptoInstance;
    public PrivacyProtocol Algorithm { get; private set; }
    public required Authentication Auth { get; init; }
    public int PrivacyParametersLength => cryptoInstance?.PrivacyParametersLength ?? 0;
    public Privacy(PrivacyProtocol algo) {
        if (algo == PrivacyProtocol.None) {
            throw new ArgumentException("PrivacyProtocol.None is not valid for object construction.", nameof(algo));
        }
        Algorithm = algo;
    }
    [SetsRequiredMembers]
    public Privacy(PrivacyProtocol algo, Authentication auth) {
        if (algo == PrivacyProtocol.None) {
            throw new ArgumentException("PrivacyProtocol.None is not valid for object construction.", nameof(algo));
        }
        Algorithm = algo;
        Auth = auth;
    }
    public ReadOnlySpan<byte> Decrypt(
            ReadOnlySpan<byte> encryptedData,
            Span<byte> key,
            int engineBoots,
            int engineTime,
            Span<byte> privacyParameters
    ) => GetNewInstance().Decrypt(encryptedData, key, engineBoots, engineTime, privacyParameters);
    public ReadOnlySpan<byte> Encrypt(
            ReadOnlySpan<byte> unencryptedData,
            Span<byte> key,
            int engineBoots,
            int engineTime,
            out byte[] privacyParameters
    ) => GetNewInstance().Encrypt(unencryptedData, key, engineBoots, engineTime, out privacyParameters);
    private IPrivacyProtocol GetNewInstance() {
        return Algorithm switch {
            PrivacyProtocol.AES128 => new PrivacyAES128(Auth),
            PrivacyProtocol.AES192 => new PrivacyAES192(Auth),
            PrivacyProtocol.AES256 => new PrivacyAES256(Auth),
            PrivacyProtocol.DES => new PrivacyDES(Auth),
            _ => throw new UnreachableException()
        };
    }
}
