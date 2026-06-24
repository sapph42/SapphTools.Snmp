using SnmpSharpNet8.Exceptions;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace SnmpSharpNet8.Security;

public class PrivacyDES : IPrivacyProtocol {
	protected int _salt = 0;

    public Authentication Auth { get; init; }

    public bool CanExtendShortKey => false;
    public int MaximumKeyLength => 16;
    public int MinimumKeyLength => 16;
    public string Name => "DES";
    public int PrivacyParametersLength => 8;

    public PrivacyDES(Authentication auth) {
        Auth = auth;
		Random random = new();
		_salt = random.Next(1, int.MaxValue);
	}

    public ReadOnlySpan<byte> Decrypt(
            byte[] encryptedData, 
			byte[] key, 
			int __, 
			int ___,
            ReadOnlySpan<byte> privacyParameters
		) {
        if ((encryptedData.Length % 8) != 0)
            throw new ArgumentOutOfRangeException(nameof(encryptedData), "Encrypted data buffer has to be divisible by 8.");
        if (encryptedData == null || encryptedData.Length == 0)
            throw new ArgumentNullException(nameof(encryptedData));
        if (privacyParameters == null || privacyParameters.Length != PrivacyParametersLength)
            throw new ArgumentOutOfRangeException(nameof(privacyParameters), "Privacy parameters argument has to be 8 bytes long");
        if (key == null || key.Length < MinimumKeyLength)
            throw new ArgumentOutOfRangeException(nameof(key), "Decryption key has to be at least 16 bytes long.");

        byte[] iv = new byte[8];
        for (int i = 0; i < 8; ++i) {
            iv[i] = (byte)(key[8 + i] ^ privacyParameters[i]);
        }
		DES des = DES.Create();
		try {
			des.Mode = CipherMode.CBC;
			des.Padding = PaddingMode.Zeros;
			// .NET implementation only takes an 8 byte key
			des.Key = key[..8];
			des.IV = iv;
			return des
				.CreateDecryptor()
				.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
        } catch (Exception ex) {
            throw new SnmpPrivacyException("Exception was thrown while TripleDES privacy protocol was encrypting data\r\n", ex);
        } finally {
            CryptographicOperations.ZeroMemory(iv);
            des.Clear();
        }
    }
    public ReadOnlySpan<byte> Encrypt(
            byte[] unencryptedData, 
			byte[] key, 
			int engineBoots, 
			int _, 
			out ReadOnlySpan<byte> privacyParameters
		) {
        ArgumentNullException.ThrowIfNull(key);
		if (key.Length < MinimumKeyLength) {
			throw new ArgumentOutOfRangeException(nameof(key), "Encryption key length has to be 32 bytes or more.");
		}
        privacyParameters = GetSalt(engineBoots);
        byte[] iv = GetIV(key, privacyParameters);
        byte[] outKey = GetKey(key);
        byte[] inputBlock = new byte[8];
        int encryptedLength = GetEncryptedLength(unencryptedData.Length);
        int blockCount = encryptedLength / 8;
        Span<byte> paddedPlaintext = stackalloc byte[encryptedLength];
        byte[] result = new byte[encryptedLength];
        (unencryptedData[..unencryptedData.Length]).CopyTo(paddedPlaintext);

        try {
            using DES des = DES.Create();
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.None;
            using ICryptoTransform transform = des.CreateEncryptor(outKey, null);
            int inputOffset = 0;
            int outputOffset = 0;

            for (int block = 0; block < blockCount; block++) {
                for (int i = 0; i < 8; i++) {
                    inputBlock[i] = (byte)(paddedPlaintext[inputOffset++] ^ iv[i]);
                }
                transform.TransformBlock(inputBlock, 0, inputBlock.Length, iv, 0);
                Buffer.BlockCopy(iv, 0, result, outputOffset, iv.Length);
                outputOffset += iv.Length;
            }
            return result;
        } catch (Exception ex) {
            throw new SnmpPrivacyException("Exception was thrown while DES privacy protocol was encrypting data.", ex);
        } finally {
            CryptographicOperations.ZeroMemory(iv);
            CryptographicOperations.ZeroMemory(outKey);
            CryptographicOperations.ZeroMemory(paddedPlaintext);
            CryptographicOperations.ZeroMemory(inputBlock);
        }
    }
    public byte[] ExtendShortKey(byte[] shortKey, ReadOnlySpan<byte> _) => throw new NotSupportedException();
    public int GetEncryptedLength(int scopedPduLength) => ((scopedPduLength + 7) / 8) * 8;
    private static byte[] GetIV(byte[] privacyKey, ReadOnlySpan<byte> salt) {
        if (privacyKey.Length < 16)
            throw new SnmpPrivacyException("Invalid privacy key length");
        byte[] iv = new byte[8];
        for (int i = 0; i < iv.Length; i++) {
            iv[i] = (byte)(salt[i] ^ privacyKey[8 + i]);
        }
        return iv;
    }
    private static byte[] GetKey(byte[] privacyPassword) {
        if (privacyPassword.Length < 16)
            throw new SnmpPrivacyException("Invalid privacy key length.");
        return privacyPassword[..8];
    }
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
	public byte[] PasswordToKey(byte[] secret, ReadOnlySpan<byte> engineId) {
		if (secret.Length < 8)
			throw new SnmpPrivacyException("Invalid privacy secret length.");
		return Auth.PasswordToKey(secret, engineId);
	}
}
