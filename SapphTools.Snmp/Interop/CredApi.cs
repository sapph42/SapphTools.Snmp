using SnmpSharpNet8.Memory;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Graphics.Gdi;
using Windows.Win32.Security.Credentials;

namespace SnmpSharpNet8.Interop;

internal static unsafe partial class CredApi {
    public ref struct CredentialPack {
        public ReadOnlySpan<char> UserName;
        public ReadOnlySpan<char> Domain;
        public SafeMemoryHandle Password;
    }
    private static readonly HWND HWND_NULL = new(IntPtr.Zero);
    public static SafeMemoryHandle WindowsCredentialsPrompt(string prompt, IntPtr? owner, SafeMemoryHandle prePack, CREDUIWIN_FLAGS flags) {
        IntPtr credBuffer;
        uint credBufferLength;
        uint ret = 0;
        fixed (char* p = prompt) {
            PCWSTR caption = new(p);
            HWND parent = new(owner ?? IntPtr.Zero);
            HBITMAP banner = new(IntPtr.Zero);
            CREDUI_INFOW info = new() {
                pszCaptionText = caption,
                pszMessageText = caption,
                hwndParent = parent,
                hbmBanner = banner
            };
            info.cbSize = (uint)Marshal.SizeOf(info);
            uint authPackage = 0;
            BOOL save = false;
            Span<byte> inBuff = stackalloc byte[(int)prePack.Length];
            prePack.CopyTo(inBuff);
            ret = PInvoke.CredUIPromptForWindowsCredentials(
                info,
                0,
                ref authPackage,
                inBuff,
                out void* credPointer,
                out credBufferLength,
                ref save,
                flags
            );
            credBuffer = (IntPtr)credPointer;
        }
        return ret == 0
            ? new SafeMemoryHandle(credBuffer, true, credBufferLength, SafeMemoryHandle.MemoryType.CoTaskMem)
            : SafeMemoryHandle.Zero;
    }
    public static SafeMemoryHandle PackCredential(string? username) {
        uint packSize = 0;
        IntPtr pack = IntPtr.Zero;
        if (string.IsNullOrWhiteSpace(username)) {
            return SafeMemoryHandle.Zero;
        }
        Span<char> passBuffer = stackalloc char[1];
        Span<byte> packBuff = [];
        fixed (char* u = username, p = passBuffer) {
            PWSTR userName = new(u);
            PWSTR password = new(p);
            _ = PInvoke.CredPackAuthenticationBuffer(
                0,
                userName,
                password,
                packBuff,
                ref packSize
            );
            packBuff = new byte[(int)packSize];
            _ = PInvoke.CredPackAuthenticationBuffer(
                0,
                userName,
                password,
                packBuff,
                ref packSize
            );
        }

        SafeMemoryHandle ret = SafeMemoryHandle.Create(SafeMemoryHandle.MemoryType.CoTaskMem, packSize);
        ret.CopyFrom(packBuff);
        return ret;
    }
    public static int GetPassLength(SafeMemoryHandle authBuffer) {
        if (authBuffer.IsInvalid) {
            return -1;
        }
        uint userLength = 0;
        uint passLength = 0;
        int ret = PInvoke.CredUnPackAuthenticationBuffer(
            0,
            (void*)authBuffer.DangerousGetHandle(),
            authBuffer.Length,
            null,
            ref userLength,
            null,
            null,
            null,
            ref passLength);
        return (int)passLength;
    }
    public static CredentialPack UnpackAuthBuffer(SafeMemoryHandle authBuffer, bool includePassword) {
        if (authBuffer.IsInvalid) {
            return new CredentialPack();
        }
        uint userLength = 0;
        uint domainLength = 0;
        uint passLength = 0;
        Span<byte> auth = new byte[authBuffer.Length];
        authBuffer.CopyTo(auth);
        _ = PInvoke.CredUnPackAuthenticationBuffer(
            0,
            auth,
            null,
            ref userLength,
            null,
            ref domainLength,
            null,
            ref passLength
        );
        Span<char> user = new char[(int)userLength + 1];
        Span<char> pass = stackalloc char[(int)passLength + 1];
        _ = PInvoke.CredUnPackAuthenticationBuffer(
            0,
            auth,
            user,
            ref userLength,
            null,
            ref domainLength,
            pass,
            ref passLength
        );
        CryptographicOperations.ZeroMemory(auth);
        SafeMemoryHandle password = SafeMemoryHandle.Zero;
        if (!includePassword) {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(pass));
        } else {
            password = SafeMemoryHandle.CreateCoTaskMem((passLength + 1) * sizeof(char));
            password.CopyFrom(MemoryMarshal.AsBytes(pass));
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(pass));
        }
        return new CredentialPack() {
            UserName = user,
            Domain = [],
            Password = password
        };
    }
}