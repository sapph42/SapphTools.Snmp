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
		if (keyBytes != 16 && keyBytes != 24 && keyBytes != 32)
			throw new ArgumentOutOfRangeException(nameof(keyBytes), "Valid key sizes are 16, 24 and 32 bytes.");
		_keyBytes = keyBytes;
        Auth = auth;
		Random rand = new();
		_salt = Convert.ToInt64(rand.Next(1, int.MaxValue));
	}

    public ReadOnlySpan<byte> Decrypt(
            byte[] encryptedData,
            byte[] key,
            int engineBoots,
            int engineTime,
            Span<byte> privacyParameters
        ) {
        if (key == null || key.Length < MinimumKeyLength)
            throw new ArgumentOutOfRangeException(nameof(key), "Invalid key length");

        byte[] iv = new byte[16];
        int len = Math.Min(key.Length, MaximumKeyLength);
        try {
            BinaryPrimitives.WriteInt32BigEndian(iv.AsSpan(0, 4), engineBoots);
            BinaryPrimitives.WriteInt32BigEndian(iv.AsSpan(4, 4), engineTime);

            privacyParameters.CopyTo(iv.AsSpan(8));

            using Aes rm = Aes.Create();
            rm.KeySize = _keyBytes * 8;
            rm.FeedbackSize = 128;
            rm.BlockSize = 128;
            rm.Padding = PaddingMode.Zeros;
            rm.Mode = CipherMode.CFB;
            rm.Key = key[..len];
            rm.IV = iv;
            using ICryptoTransform cryptor = rm.CreateDecryptor();

            if ((encryptedData.Length % _keyBytes) != 0) {
                int paddedLength = (encryptedData.Length + 15) / 16 * 16;
                byte[] decryptBuffer = new byte[paddedLength];
                encryptedData.AsSpan(0, encryptedData.Length).CopyTo(decryptBuffer);
                return cryptor
                    .TransformFinalBlock(decryptBuffer, 0, paddedLength)
                    .AsSpan(0, encryptedData.Length);
            }
            return cryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
        } catch (Exception ex) {
            throw new SnmpPrivacyException("Exception was thrown while AES privacy protocol was decrypting data.", ex);
        } finally {
            CryptographicOperations.ZeroMemory(iv);
        }
    }
    public ReadOnlySpan<byte> Encrypt(
            byte[] unencryptedData,
            byte[] key,
            int engineBoots,
            int engineTime,
            out Span<byte> privacyParameters
        ) {
        if (key == null || key.Length < _keyBytes)
            throw new ArgumentOutOfRangeException(nameof(key), "Invalid key length");

        byte[] iv = new byte[16];
        byte[] pkey = new byte[MinimumKeyLength];
        long salt = NextSalt();
        BinaryPrimitives.WriteInt32BigEndian(iv.AsSpan(0, 4), engineBoots);
        BinaryPrimitives.WriteInt32BigEndian(iv.AsSpan(4, 4), engineTime);
        privacyParameters = BitConverter.GetBytes(salt);
        privacyParameters.Reverse();
        privacyParameters.CopyTo(iv.AsSpan(8));
        try {
            using Aes rm = Aes.Create();
            rm.KeySize = _keyBytes * 8;
            rm.FeedbackSize = 128;
            rm.BlockSize = 128;
            rm.Padding = PaddingMode.Zeros;
            rm.Mode = CipherMode.CFB;
            key.CopyTo(pkey, 0);
            rm.Key = pkey;
            rm.IV = iv;
            return rm
                .CreateEncryptor()
                .TransformFinalBlock(unencryptedData, 0, unencryptedData.Length)
                .AsSpan(0, unencryptedData.Length);
        } catch (Exception ex) {
            throw new SnmpPrivacyException("Exception was thrown while AES privacy protocol was encrypting data.", ex);
        } finally {
            CryptographicOperations.ZeroMemory(iv);
            CryptographicOperations.ZeroMemory(pkey);
        }
    }
    public byte[] ExtendShortKey(byte[] shortKey, ReadOnlySpan<byte> engineID) {
        byte[] extKey = new byte[MinimumKeyLength];
        byte[] lastKeyBuf = new byte[shortKey.Length];
        Array.Copy(shortKey, lastKeyBuf, shortKey.Length);
        int keyLen = shortKey.Length > MinimumKeyLength ? MinimumKeyLength : shortKey.Length;
        Array.Copy(shortKey, extKey, keyLen);
        while (keyLen < MinimumKeyLength) {
            byte[] tmpBuf = Auth.PasswordToKey(lastKeyBuf, engineID);
            if (tmpBuf.Length <= (MinimumKeyLength - keyLen)) {
                Array.Copy(tmpBuf, 0, extKey, keyLen, tmpBuf.Length);
                keyLen += tmpBuf.Length;
            } else {
                Array.Copy(tmpBuf, 0, extKey, keyLen, MinimumKeyLength - keyLen);
                keyLen += (MinimumKeyLength - keyLen);
            }
            lastKeyBuf = new byte[tmpBuf.Length];
            Array.Copy(tmpBuf, lastKeyBuf, tmpBuf.Length);
        }
        return extKey;
    }
    public int GetEncryptedLength(int scopedPduLength) => scopedPduLength;
    protected long NextSalt() {
        long next = Interlocked.Increment(ref _salt);
        return next;
    }
	public byte[] PasswordToKey(byte[] secret, ReadOnlySpan<byte> engineId) {
		if (secret == null || secret.Length < 8)
			throw new SnmpPrivacyException("Invalid privacy secret length.");
		byte[] key = Auth.PasswordToKey(secret, engineId);
        return key.Length < MinimumKeyLength ?
			ExtendShortKey(key, engineId) :
		    key;
	}
}
