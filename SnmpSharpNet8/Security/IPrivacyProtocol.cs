namespace SnmpSharpNet8.Security;

public interface IPrivacyProtocol {

    Authentication Auth { get; }
    bool CanExtendShortKey { get; }
    int MaximumKeyLength { get; }
    int MinimumKeyLength { get; }
    string Name { get; }
    int PrivacyParametersLength { get; }

    ReadOnlySpan<byte> Decrypt(byte[] cryptedData, byte[] key, int engineBoots, int engineTime, Span<byte> privacyParameters);
    ReadOnlySpan<byte> Encrypt(byte[] unencryptedData, byte[] encryptionKey, int engineBoots, int engineTime, out Span<byte> privacyParameters);
	byte[] ExtendShortKey(byte[] shortKey, ReadOnlySpan<byte> engineID);
    int GetEncryptedLength(int scopedPduLength);
    byte[] PasswordToKey(byte[] secret, ReadOnlySpan<byte> engineId);
}
