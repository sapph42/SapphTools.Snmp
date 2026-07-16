using SapphTools.Snmp.Interop;
using SapphTools.Snmp.Memory;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Windows.Win32.Security.Credentials;

namespace SapphTools.Snmp.Security;

public sealed class Credential : IDisposable {
    private const int CREDUIWIN_DO_NOT_PACK_AAD_AUTHORITY = 0x00040000;

    private readonly SemaphoreSlim _gate = new(1, 1);

    private bool _disposedValue;
    private SafeMemoryHandle _credHandle;
    private SafeMemoryHandle _keyHandle = SafeMemoryHandle.Zero;
    private bool _isEncrypted;
    private delegate Span<byte> KeyConverter(Span<byte> secret, ReadOnlySpan<byte> engineId);

    private static readonly CREDUIWIN_FLAGS BASIC = (CREDUIWIN_FLAGS)((int)CREDUIWIN_FLAGS.CREDUIWIN_GENERIC | CREDUIWIN_DO_NOT_PACK_AAD_AUTHORITY);

    public CredentialType Type { get; private set; }

    public interface ICredBuffer : IDisposable {
        string? GetUserName(bool withDomain = true);
        SafeMemoryHandle GetPassword();
    }
    private sealed class CredProxy(SafeMemoryHandle handle) : ICredBuffer {
        private readonly SafeMemoryHandle _credHandle = handle;
        private bool _valid = true;
        public SafeMemoryHandle SuppliedPassword = SafeMemoryHandle.Zero;
        private bool disposedValue;

        private void EnsureValid() {
            if (!_valid) {
                throw new ObjectDisposedException(nameof(CredProxy), "Credential is no longer usable.");
            }
        }
        public void Invalidate() => _valid = false;

        public SafeMemoryHandle GetPassword() {
            EnsureValid();
            SuppliedPassword?.Dispose();
            SuppliedPassword = CredApi.UnpackAuthBuffer(_credHandle, true).Password;
            return SuppliedPassword;
        }
        public string? GetUserName(bool withDomain = true) {
            EnsureValid();
            if (_credHandle.IsInvalid) {
                return null;
            }
            CredApi.CredentialPack cred = CredApi.UnpackAuthBuffer(_credHandle, false);
            if (!withDomain) {
                return cred.UserName.ToString();
            } else if (cred.UserName.ToString().Contains('\\')) {
                return cred.UserName.ToString();
            } else {
                return string.Concat(cred.Domain.ToString(), @"\", cred.UserName.ToString());
            }
        }

        private void Dispose(bool disposing) {
            if (!disposedValue) {
                if (disposing) {
                    // TODO: dispose managed state (managed objects)
                }
                SuppliedPassword.Dispose();
                Invalidate();
                disposedValue = true;
            }
        }
        ~CredProxy() {
            Dispose(disposing: false);
        }
        public void Dispose() {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }

    public Credential(IntPtr? callerHandle, string promptText, string? userName = null) {
        try {
            using SafeMemoryHandle prePack = CredApi.PackCredential(userName);
            _credHandle = CredApi.WindowsCredentialsPrompt(promptText, callerHandle, prePack, BASIC);
            Span<byte> cred = stackalloc byte[(int)_credHandle.Length];
            _credHandle.CopyTo(cred);
            Debug.WriteLine($"Cred Buffer [{cred.Length:D3}]: {string.Join(' ', cred.ToArray().Select(b => Convert.ToHexString([b])))}");
            EncryptCred();
            _isEncrypted = true;
            Type = CredentialType.User;
        } catch {
            if (!_credHandle?.IsInvalid ?? true) {
                _credHandle?.Dispose();
            }
            _credHandle = SafeMemoryHandle.Zero;
        }
    }
    public Credential(ref SafeMemoryHandle handle) {
        if (handle == SafeMemoryHandle.Zero) { }
        if (handle.Type == SafeMemoryHandle.MemoryType.CoTaskMem) {
            _credHandle = handle;
        } else {
            _ = SafeMemoryHandle.MigrateHandle(ref handle, out _credHandle, SafeMemoryHandle.MemoryType.CoTaskMem);
        }
        //Span<byte> cred = stackalloc byte[(int)_credHandle.Length];
        //_credHandle.CopyTo(cred);
        //Debug.WriteLine($"Input Cred Buffer          [{cred.Length:D3}]: {string.Join(' ', cred.ToArray().Select(b => Convert.ToHexString([b])))}");
        EncryptCred();
        _isEncrypted = true;
    }
    public Credential(string userName, CredentialType type) {
        Type = type;
        _credHandle = type switch {
            CredentialType.SecretOnly => CredApi.PackCredential("N/A"),
            CredentialType.User => CredApi.PackCredential(userName),
            _ => SafeMemoryHandle.Zero
        };
        EncryptCred();
        _isEncrypted = true;
    }
    public bool Authenticate(ReadOnlySpan<byte> authenticationParameters, ReadOnlySpan<byte> wholeMessage, Authentication algo) {
        if (_keyHandle.IsInvalid) {
            return false;
        }
        _gate.Wait();
        try {
            if (_isEncrypted) {
                DecryptKey();
                _isEncrypted = false;
            }
            byte[] key = new byte[_keyHandle.Length];
            try {
                Marshal.Copy(_keyHandle.DangerousGetHandle(), key, 0, key.Length);
                return algo.AuthenticateIncomingMsg(key, authenticationParameters, wholeMessage);
            } finally {
                CryptographicOperations.ZeroMemory(key);
            }
        } finally {
            EncryptKey();
            _isEncrypted = true;
            _ = _gate.Release();
        }
    }
    public ReadOnlySpan<byte> Decrypt(byte[] encryptedBytes, int engineBoots, int engineTime, Privacy algo, Span<byte> privParams) {
        if (_keyHandle.IsInvalid) {
            return [];
        }
        _gate.Wait();
        try {
            if (_isEncrypted) {
                DecryptKey();
                _isEncrypted = false;
            }
            byte[] key = new byte[_keyHandle.Length];
            try {
                Marshal.Copy(_keyHandle.DangerousGetHandle(), key, 0, key.Length);
                return algo.Decrypt(
                    encryptedBytes,
                    key,
                    engineBoots,
                    engineTime,
                    privParams
                );
            } finally {
                CryptographicOperations.ZeroMemory(key);
            }
        } finally {
            EncryptKey();
            _isEncrypted = true;
            _ = _gate.Release();
        }
    }
    public ReadOnlySpan<byte> Encrypt(
            ReadOnlySpan<byte> clearBytes,
            ReadOnlySpan<byte> engineId,
            long engineBoots,
            long engineTime,
            Privacy privAlgo,
            out byte[] privParams) {
        if (_credHandle.IsInvalid) {
            privParams = [];
            return [];
        }
        _gate.Wait();
        try {
            if (_keyHandle.IsInvalid || _keyHandle.IsClosed || _keyHandle == SafeMemoryHandle.Zero) {
                StoreCryptoKey(privAlgo, engineId);
            }
            if (_isEncrypted) {
                DecryptKey();
                _isEncrypted = false;
            }
            Span<byte> key = new byte[_keyHandle.Length];
            try {
                _keyHandle.CopyTo(key);
                Span<byte> cryptBytes = new byte[clearBytes.Length];
                privAlgo.Encrypt(
                    [.. clearBytes],
                    key,
                    (int)engineBoots,
                    (int)engineTime,
                    out privParams
                ).CopyTo(cryptBytes);
                return cryptBytes;
            } finally {
                CryptographicOperations.ZeroMemory(key);
            }
        } finally {
            EncryptKey();
            _isEncrypted = true;
            _ = _gate.Release();
        }
    }
    public ReadOnlySpan<byte> GenerateHash(ReadOnlySpan<byte> wholeMessage, ReadOnlySpan<byte> engineId, Authentication algo) {
        if (_credHandle.IsInvalid) {
            return [];
        }
        _gate.Wait();
        try {
            if (_isEncrypted) {
                if (_keyHandle.IsInvalid || _keyHandle.IsClosed || _keyHandle == SafeMemoryHandle.Zero) {
                    StoreHashKey(algo, engineId);
                }
                DecryptKey();
                _isEncrypted = false;
            }
            Span<byte> key = new byte[_keyHandle.Length];
            try {
                _keyHandle.CopyTo(key);
                return algo.Authenticate(key, wholeMessage);
            } finally {
                CryptographicOperations.ZeroMemory(key);
            }
        } finally {
            EncryptKey();
            _isEncrypted = true;
            _ = _gate.Release();
        }
    }
    private void StoreKey(KeyConverter keygen, ReadOnlySpan<byte> engineId) {
        if (_credHandle.IsInvalid) {
            return;
        }
        try {
            if (_isEncrypted) {
                DecryptCred();
            }
            _isEncrypted = false;
            using CredProxy proxy = new(_credHandle);
            int secretLen = CredApi.GetPassLength(_credHandle);
            int secretLenW = secretLen * sizeof(char);
            char[] chars = new char[secretLen - 1];
            Span<byte> secret = new byte [secretLenW];
            Span<byte> key = [];
            try {
                SafeMemoryHandle pass = proxy.GetPassword();
                Debug.WriteLine("");
                Debug.WriteLine("");
                Debug.WriteLine("Key Generation Requested");
                pass.CopyTo(secret, secretLenW);
                Debug.WriteLine($"Secret Raw Bytes       [{secret.Length:D3}]: {string.Join(' ', secret.ToArray().Select(b => Convert.ToHexString([b])))}");
                for (int i = 0; i < chars.Length; i++) {
                    if (secret[i * 2] == 0) {
                        continue;
                    }
                    chars[i] = (char)secret[i * 2];
                }
                Debug.WriteLine($"Secret Chars (**term)  [{chars.Length:D3}]: {string.Join("", chars)}**");
                CryptographicOperations.ZeroMemory(secret);
                secret = new byte[secretLen - 1];
                for (int i = 0; i < chars.Length; i++) {
                    secret[i] = (byte)chars[i];
                }
                Debug.WriteLine($"Secret ASCII Bytes     [{secret.Length:D3}]: {string.Join(' ', secret.ToArray().Select(b => Convert.ToHexString([b])))}");
                key = keygen(secret, engineId);
                _keyHandle = SafeMemoryHandle.CreateCoTaskMem((uint)key.Length);
                _keyHandle.CopyFrom(key);
            } catch (Exception ex) {
                Debug.WriteLine(ex.Message);
            } finally {
                CryptographicOperations.ZeroMemory(secret);
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes<char>(chars));
                CryptographicOperations.ZeroMemory(key);
            }
        } catch (Exception ex) {
            Debug.WriteLine(ex.Message);
        } finally {
            EncryptCred();
            EncryptKey();
            _isEncrypted = true;
        }
    }
    private void StoreHashKey(Authentication algo, ReadOnlySpan<byte> engineId) {
        KeyConverter del = algo.PasswordToKey;
        StoreKey(del, engineId);
    }
    private void StoreCryptoKey(Privacy algo, ReadOnlySpan<byte> engineId) {
        KeyConverter del = algo.GetNewInstance().PasswordToKey;
        StoreKey(del, engineId);
    }
    private void DecryptCred() {
        if (_credHandle.IsInvalid || !_isEncrypted) {
            return;
        }
        try {
            _credHandle.Decrypt();
            _isEncrypted = false;
        } catch { }
    }
    private void EncryptCred() {
        if (_credHandle.IsInvalid || _isEncrypted) {
            return;
        }
        try {
            _credHandle = _credHandle.Encrypt(true);
            _isEncrypted = true;
        } catch { }
    }
    private void DecryptKey() {
        if (_keyHandle.IsInvalid || !_isEncrypted) {
            return;
        }
        try {
            _keyHandle.Decrypt();
            _isEncrypted = false;
        } catch { }
    }
    private void EncryptKey() {
        if (_keyHandle.IsInvalid || _isEncrypted) {
            return;
        }
        try {
            _keyHandle = _keyHandle.Encrypt(true);
            _isEncrypted = true;
        } catch { }
    }
    public void Dispose(bool disposing) {
        if (!_disposedValue) {
            if (disposing) {
                // dispose managed state (managed objects)
            }
            _credHandle.Dispose();
            _keyHandle.Dispose();
            _disposedValue = true;
        }
    }
    ~Credential() {
        Dispose(disposing: false);
    }
    public void Dispose() {
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}