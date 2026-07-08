using SnmpSharpNet8.Exceptions;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SnmpSharpNet8.Security;

public class PrivacyAES : IPrivacyProtocol {
    protected long _salt = Random.Shared.NextInt64();
    protected int _keyBytes = 16; // Default is 128bit AES protocol
    public Authentication Auth { get; init; }
    public bool CanExtendShortKey => true;
    public virtual string Name => "AES";
    public int MaximumKeyLength => _keyBytes;
    public int MinimumKeyLength => _keyBytes;
    public int PrivacyParametersLength => 8;

    public PrivacyAES(int keyBytes, Authentication auth) {
        if (keyBytes is not 16 and not 24 and not 32) {
            throw new ArgumentOutOfRangeException(nameof(keyBytes), "Valid key sizes are 16, 24 and 32 bytes.");
        }

        _keyBytes = keyBytes;
        Auth = auth;
        Random rand = new();
        _salt = Convert.ToInt64(rand.Next(1, int.MaxValue));
    }

    public ReadOnlySpan<byte> Decrypt(
            ReadOnlySpan<byte> encryptedData,
            Span<byte> key,
            int engineBoots,
            int engineTime,
            Span<byte> privacyParameters
        ) {
        if (key.Length < MinimumKeyLength) {
            throw new ArgumentOutOfRangeException(nameof(key), "Invalid key length");
        }

        Span<byte> iv = stackalloc byte[16];
        byte[] pkey = [.. key];
        long salt = NextSalt();
        privacyParameters = new byte[8];
        BinaryPrimitives.WriteInt32BigEndian(iv[..4], engineBoots);
        BinaryPrimitives.WriteInt32BigEndian(iv[4..8], engineTime);
        privacyParameters[..8].CopyTo(iv[8..16]);
        Span<byte> unencryptedData = new byte[encryptedData.Length];
        try {
            using Aes aes = Aes.Create();
            aes.Key = pkey;
            _ = aes.DecryptCfb(
                encryptedData,
                iv,
                unencryptedData,
                PaddingMode.None,
                feedbackSizeInBits: 128);
            return unencryptedData;
        } catch (Exception ex) {
            throw new SnmpPrivacyException("Exception was thrown while AES privacy protocol was decrypting data.", ex);
        } finally {
            CryptographicOperations.ZeroMemory(iv);
        }
    }
    public ReadOnlySpan<byte> Encrypt(
            ReadOnlySpan<byte> unencryptedData,
            Span<byte> key,
            int engineBoots,
            int engineTime,
            out byte[] privacyParameters
        ) {
        if (key.Length < _keyBytes) {
            throw new ArgumentOutOfRangeException(nameof(key), "Invalid key length");
        }

        Span<byte> iv = stackalloc byte[16];
        byte[] pkey = [.. key];
        long salt = NextSalt();
        privacyParameters = new byte[8];
        BinaryPrimitives.WriteInt32BigEndian(iv[..4], engineBoots);
        BinaryPrimitives.WriteInt32BigEndian(iv[4..8], engineTime);
        BinaryPrimitives.WriteInt64BigEndian(privacyParameters.AsSpan(0, 8), salt);
        privacyParameters[..8].CopyTo(iv[8..16]);
        Span<byte> encryptedData = new byte[unencryptedData.Length];
        try {
            using Aes aes = Aes.Create();
            aes.Key = pkey;
            _ = aes.EncryptCfb(
                unencryptedData,
                iv,
                encryptedData,
                PaddingMode.None,
                feedbackSizeInBits: 128);
            return encryptedData;
        } catch (Exception ex) {
            throw new SnmpPrivacyException("Exception was thrown while AES privacy protocol was encrypting data.", ex);
        } finally {
            CryptographicOperations.ZeroMemory(iv);
            CryptographicOperations.ZeroMemory(pkey);
        }
    }
    public Span<byte> ExtendShortKey(Span<byte> shortKey, ReadOnlySpan<byte> engineID) {
        Span<byte> extKey = new byte[MinimumKeyLength];
        Span<byte> lastKeyBuf = stackalloc byte[shortKey.Length];
        shortKey.CopyTo(lastKeyBuf);
        int keyLen = shortKey.Length > MinimumKeyLength ? MinimumKeyLength : shortKey.Length;
        shortKey.CopyTo(extKey);
        while (keyLen < MinimumKeyLength) {
            Span<byte> tmpBuf = Auth.PasswordToKey(lastKeyBuf, engineID);
            if (tmpBuf.Length <= (MinimumKeyLength - keyLen)) {
                tmpBuf.CopyTo(extKey[keyLen..]);
                keyLen += tmpBuf.Length;
            } else {
                tmpBuf[..(MinimumKeyLength - keyLen)].CopyTo(extKey[keyLen..]);
                keyLen += MinimumKeyLength - keyLen;
            }
            lastKeyBuf = new byte[tmpBuf.Length];
            tmpBuf.CopyTo(lastKeyBuf);
        }
        CryptographicOperations.ZeroMemory(lastKeyBuf);
        return extKey;
    }
    public int GetEncryptedLength(int spanLength) => spanLength;
    protected long NextSalt() {
        long next = Interlocked.Increment(ref _salt);
        return next;
    }
    public Span<byte> PasswordToKey(Span<byte> secret, ReadOnlySpan<byte> engineId) {
        if (secret.Length < 8) {
            throw new SnmpPrivacyException("Invalid privacy secret length.");
        }

        Span<byte> key = Auth.PasswordToKey(secret, engineId);
        return key.Length < MinimumKeyLength ?
            ExtendShortKey(key, engineId) :
            key;
    }
}
