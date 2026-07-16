using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SapphTools.Snmp.Security;

#pragma warning disable CA5351 // Do Not Use Broken Cryptographic Algorithms
public class PrivacyDES : IPrivacyProtocol {
    protected int _salt;

    public Authentication Auth { get; init; }

    public bool CanExtendShortKey => false;
    public int MaximumKeyLength => 16;
    public int MinimumKeyLength => 16;
    public string Name => "DES";
    public static int PrivacyParametersLength => 8;

    public PrivacyDES(Authentication auth) {
        Auth = auth;
        Random random = new();
        _salt = random.Next(1, int.MaxValue);
    }

    public ReadOnlySpan<byte> Decrypt(
            ReadOnlySpan<byte> encryptedData,
            Span<byte> key,
            int __,
            int ___,
            Span<byte> privacyParameters
        ) {
        if (encryptedData.Length == 0) {
            throw new ArgumentNullException(nameof(encryptedData));
        }

        if (privacyParameters.Length != PrivacyParametersLength) {
            throw new ArgumentOutOfRangeException(nameof(privacyParameters), "Privacy parameters argument has to be 8 bytes long");
        }

        if (key.Length < MinimumKeyLength) {
            throw new ArgumentOutOfRangeException(nameof(key), "Decryption key has to be at least 16 bytes long.");
        }

        byte[] iv = new byte[8];
        for (int i = 0; i < 8; ++i) {
            iv[i] = (byte)(key[8 + i] ^ privacyParameters[i]);
        }
        byte[] pkey = key[..8].ToArray();
        using DES des = DES.Create();
        Span<byte> unencryptedData = new byte[encryptedData.Length];
        try {
            des.Key = pkey;
            des.IV = iv;
            _ = des.DecryptCbc(encryptedData, iv, unencryptedData, PaddingMode.None);
            return unencryptedData;
        } catch (Exception ex) {
            throw new SnmpPrivacyException("Exception was thrown while DES privacy protocol was encrypting data\r\n", ex);
        } finally {
            CryptographicOperations.ZeroMemory(iv);
            CryptographicOperations.ZeroMemory(pkey);
        }
    }
    public ReadOnlySpan<byte> Encrypt(
            ReadOnlySpan<byte> unencryptedData,
            Span<byte> key,
            int engineBoots,
            int _,
            out byte[] privacyParameters
    ) {
        if (key.Length < MinimumKeyLength) {
            throw new ArgumentOutOfRangeException(nameof(key), "Encryption key length has to be 16 bytes or more.");
        }
        privacyParameters = GetSalt(engineBoots);
        Span<byte> iv = GetIV(key, privacyParameters);
        byte[] pkey = GetKey(key);
        Span<byte> paddedUnencryptedData = new byte[GetEncryptedLength(unencryptedData.Length)];
        unencryptedData.CopyTo(paddedUnencryptedData);
        Span<byte> encryptedData = new byte[paddedUnencryptedData.Length];
        try {
            using DES des = DES.Create();
            des.Key = pkey;
            _ = des.EncryptCbc(
                paddedUnencryptedData,
                iv,
                encryptedData,
                PaddingMode.None);
            return encryptedData;
        } catch (Exception ex) {
            throw new SnmpPrivacyException("Exception was thrown while DES privacy protocol was encrypting data.", ex);
        } finally {
            CryptographicOperations.ZeroMemory(iv);
            CryptographicOperations.ZeroMemory(pkey);
            CryptographicOperations.ZeroMemory(paddedUnencryptedData);
        }
    }
    public Span<byte> ExtendShortKey(Span<byte> shortKey, ReadOnlySpan<byte> _) => throw new NotSupportedException();
    public int GetEncryptedLength(int spanLength) => (spanLength + 7) / 8 * 8;
    private static Span<byte> GetIV(Span<byte> privacyKey, ReadOnlySpan<byte> salt) {
        if (privacyKey.Length < 16) {
            throw new SnmpPrivacyException("Invalid privacy key length");
        }

        Span<byte> iv = new byte[8];
        for (int i = 0; i < iv.Length; i++) {
            iv[i] = (byte)(salt[i] ^ privacyKey[8 + i]);
        }
        return iv;
    }
    private static byte[] GetKey(Span<byte> privacyPassword) =>
        privacyPassword.Length < 16
            ? throw new SnmpPrivacyException("Invalid privacy key length.")
            : privacyPassword[..8].ToArray();
    private byte[] GetSalt(int engineBoots) {
        byte[] salt = new byte[8]; // salt is 8 bytes
        BinaryPrimitives.WriteInt32BigEndian(salt.AsSpan(0, 4), engineBoots);
        BinaryPrimitives.WriteInt32BigEndian(salt.AsSpan(4, 4), NextSalt());
        return salt;
    }
    protected int NextSalt() {
        _salt = _salt == int.MaxValue ?
            _salt = 1 :
            _salt += 1;
        return _salt;
    }
    public Span<byte> PasswordToKey(Span<byte> secret, ReadOnlySpan<byte> engineId) =>
        secret.Length < 8
            ? throw new SnmpPrivacyException("Invalid privacy secret length.")
            : Auth.PasswordToKey(secret, engineId);
}
#pragma warning restore CA5351 // Do Not Use Broken Cryptographic Algorithms