namespace SapphTools.Snmp.Security;

public interface IPrivacyProtocol {

    Authentication Auth { get; }
    bool CanExtendShortKey { get; }
    int MaximumKeyLength { get; }
    int MinimumKeyLength { get; }
    string Name { get; }
    static int PrivacyParametersLength { get; }

    ReadOnlySpan<byte> Decrypt(ReadOnlySpan<byte> encryptedData, Span<byte> key, int engineBoots, int engineTime, Span<byte> privacyParameters);
    ReadOnlySpan<byte> Encrypt(ReadOnlySpan<byte> unencryptedData, Span<byte> key, int engineBoots, int engineTime, out byte[] privacyParameters);
    Span<byte> ExtendShortKey(Span<byte> shortKey, ReadOnlySpan<byte> engineID);
    int GetEncryptedLength(int spanLength);
    Span<byte> PasswordToKey(Span<byte> secret, ReadOnlySpan<byte> engineId);
}
