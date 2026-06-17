using SnmpSharpNet8.Types;
using SnmpSharpNet8.Unsafe;
using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

namespace SnmpSharpNet8.Security;
public sealed class Credential : IDisposable {
    private readonly SemaphoreSlim _gate = new(1,1);

    private bool _disposedValue;
    private SafeMemoryHandle _credHandle;
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
            _credHandle = CredApi.WindowsCredentialsPrompt(promptText, callerHandle, prePack, CredApi.PromptFlags.CREDUIWIN_GENERIC);
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
            CredentialType.Gmsa => _credHandle = CredApi.PackCredential(Regex.Replace(userName, @"^(?:MHS\\)?([^$\r\n]*)(?:\$?)$", @"MHS\$1$")),
            CredentialType.OtherWellKnown => _credHandle = CredApi.PackCredential(Regex.Replace(userName, @"^(?!NT AUTHORITY)(.*)", @"NT AUTHORITY\$1")),
            _ => SafeMemoryHandle.Zero
        };
        EncryptCred();
        _isEncrypted = true;
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