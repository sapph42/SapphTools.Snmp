using SnmpSharpNet8.Interop;
using SnmpSharpNet8.Memory;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace SnmpSharpNet8.Security;
public sealed class Credential : IDisposable {
    private readonly SemaphoreSlim _gate = new(1,1);

    private bool _disposedValue;
    private SafeMemoryHandle _credHandle;
    private SafeMemoryHandle _keyHandle = SafeMemoryHandle.Zero;
    private bool _isEncrypted = false;

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
            if (!_valid)
                throw new ObjectDisposedException(nameof(CredProxy), "Credential is no longer usable.");
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
            }
            if (cred.UserName.ToString().Contains('\\')) {
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
            _credHandle = CredApi.WindowsCredentialsPrompt(promptText, callerHandle, prePack, CredApi.PromptFlags.BASIC);
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
            _gate.Release();
        }
    }
    public ReadOnlySpan<byte> Decrypt(byte[] encryptedBytes, int engineBoots, int engineTime, IPrivacyProtocol algo, Span<byte> privParams) {
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
            _gate.Release();
        }
    }
    public ReadOnlySpan<byte> Encrypt(byte[] clearBytes, byte[] engineId, int engineBoots, int engineTime, IPrivacyProtocol algo, out Span<byte> privParams) {
        if (_credHandle.IsInvalid) {
            privParams = [];
            return [];
        }
        _gate.Wait();
        try {
            if (_isEncrypted) {
                if (_keyHandle.IsInvalid || _keyHandle.IsClosed || _keyHandle == SafeMemoryHandle.Zero) {
                    StoreKey(algo, engineId);
                }
                DecryptKey();
                _isEncrypted = false;
            }
            byte[] key = new byte[_keyHandle.Length];
            try {
                Marshal.Copy(_keyHandle.DangerousGetHandle(), key, 0, key.Length);
                return algo.Encrypt(
                    clearBytes,
                    key,
                    engineBoots,
                    engineTime,
                    out privParams
                );
            } finally {
                CryptographicOperations.ZeroMemory(key);
            }
        } finally {
            EncryptKey();
            _isEncrypted = true;
            _gate.Release();
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
                    StoreKey(algo, engineId);
                }
                DecryptKey();
                _isEncrypted = false;
            }
            byte[] key = new byte[_keyHandle.Length];
            try {
                Marshal.Copy(_keyHandle.DangerousGetHandle(), key, 0, key.Length);
                return algo.Authenticate(key, wholeMessage);
            } finally {
                CryptographicOperations.ZeroMemory(key);
            }
        } finally {
            EncryptKey();
            _isEncrypted = true;
            _gate.Release();
        }
    }
    private void StoreKey(Authentication algo, ReadOnlySpan<byte> engineId) {
        if (_credHandle.IsInvalid) {
            return;
        }
        _gate.Wait();
        try {
            if (_isEncrypted) {
                DecryptCred();
            }
            _isEncrypted = false;
            using CredProxy proxy = new(_credHandle);
            int secretLen = CredApi.GetPassLength(_credHandle);
            char[] chars = new char[secretLen];
            byte[] secret = [];
            byte[] key = new byte[algo.AuthHeaderLength];
            try {
                using SafeMemoryHandle pass = proxy.GetPassword();
                Marshal.Copy(pass.DangerousGetHandle(), chars, 0, secretLen);
                int byteCount = Encoding.ASCII.GetByteCount(chars);
                secret = new byte[byteCount];
                Encoding.ASCII.GetBytes(chars, secret);
                key = algo.PasswordToKey(secret, engineId);
                _keyHandle = SafeMemoryHandle.CreateCoTaskMem((uint)(key.Length + 1));
                Marshal.Copy(key, 0, _keyHandle.DangerousGetHandle(), key.Length + 1);
            } finally {
                CryptographicOperations.ZeroMemory(secret);
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes<char>(chars));
                CryptographicOperations.ZeroMemory(key);
            }
        } finally {
            EncryptCred();
            EncryptKey();
            _isEncrypted = true;
            _gate.Release();
        }
    }
    private void StoreKey(IPrivacyProtocol algo, byte[] engineId) {
        if (_credHandle.IsInvalid) {
            return;
        }
        _gate.Wait();
        try {
            if (_isEncrypted) {
                DecryptCred();
            }
            _isEncrypted = false;
            using CredProxy proxy = new(_credHandle);
            int secretLen = CredApi.GetPassLength(_credHandle);
            char[] chars = new char[secretLen];
            byte[] secret = [];
            byte[] key = new byte[algo.MinimumKeyLength];
            try {
                using SafeMemoryHandle pass = proxy.GetPassword();
                Marshal.Copy(pass.DangerousGetHandle(), chars, 0, secretLen);
                int byteCount = Encoding.ASCII.GetByteCount(chars);
                secret = new byte[byteCount];
                Encoding.ASCII.GetBytes(chars, secret);
                key = algo.PasswordToKey(secret, engineId);
                _keyHandle = SafeMemoryHandle.CreateCoTaskMem((uint)(key.Length + 1));
                Marshal.Copy(key, 0, _keyHandle.DangerousGetHandle(), key.Length + 1);
            } finally {
                CryptographicOperations.ZeroMemory(secret);
                CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes<char>(chars));
                CryptographicOperations.ZeroMemory(key);
            }
        } finally {
            EncryptCred();
            EncryptKey();
            _isEncrypted = true;
            _gate.Release();
        }
    }
    public T? WithCredProxy<T>(Func<ICredBuffer, T> func) {
        if (_credHandle.IsInvalid) {
            return default;
        }
        _gate.Wait();
        try {
            if (_isEncrypted) {
                DecryptCred();
            }
            _isEncrypted = false;
            using CredProxy proxy = new(_credHandle);
            return func(proxy);
        } finally {
            if (!_isEncrypted) {
                EncryptCred();
            }
            _isEncrypted = true;
            _gate.Release();
        }
    }
    public T? WithCredProxy<T, T2>(Func<ICredBuffer, T2[], T> func, params T2[] args) {
        if (_credHandle.IsInvalid) {
            return default;
        }
        _gate.Wait();
        try {
            if (_isEncrypted) {
                DecryptCred();
            }
            _isEncrypted = false;
            using CredProxy proxy = new(_credHandle);
            return func(proxy, args);
        } finally {
            if (!_isEncrypted) {
                EncryptCred();
            }
            _isEncrypted = true;
            _gate.Release();
        }
    }
    public bool ValidateCredential() {
        return GetUserName() != null;
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
    private string? GetUserName(bool withDomain = true) {
        bool[] args = [withDomain && Type == CredentialType.User];
        return WithCredProxy(
            (cp, argList) => {
                return cp.GetUserName(argList[0]);
            },
            args
        );
    }

    public void Dispose(bool disposing) {
        if (!_disposedValue) {
            if (disposing) {
                // dispose managed state (managed objects)
            }
            _credHandle.Dispose();
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