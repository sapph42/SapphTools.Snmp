using SnmpSharpNet8.Memory;
using System.Runtime.InteropServices;
using System.Text;

namespace SnmpSharpNet8.Interop;
internal static partial class CredApi {
    [Flags]
    public enum PromptFlags {
        CREDUIWIN_GENERIC                   = 0x00000001,
        CREDUIWIN_CHECKBOX                  = 0x00000002,
        CREDUIWIN_AUTHPACKAGE_ONLY          = 0x00000010,
        CREDUIWIN_IN_CRED_ONLY              = 0x00000020,
        CREDUIWIN_ENUMERATE_ADMINS          = 0x00000100,
        CREDUIWIN_ENUMERATE_CURRENT_USER    = 0x00000200,
        CREDUIWIN_SECURE_PROMPT             = 0x00001000,
        CREDUIWIN_DO_NOT_PACK_AAD_AUTHORITY = 0x00040000,
        CREDUIWIN_PACK_32_WOW               = 0x10000000,
        BASIC                               = CREDUIWIN_GENERIC | CREDUIWIN_DO_NOT_PACK_AAD_AUTHORITY;
    }
    public struct CredentialPack {
        public StringBuilder UserName;
        public StringBuilder Domain;
        public SafeMemoryHandle Password;
    }
    public static SafeMemoryHandle WindowsCredentialsPrompt(string prompt, IntPtr? owner, SafeMemoryHandle prePack, PromptFlags flags) {
        CREDUI_INFO info = new() {
            pszCaptionText = prompt,
            pszMessageText = prompt,
            hwndParent = owner,
            hbmBanner = IntPtr.Zero
        };
        info.cbSize = Marshal.SizeOf(info);
        uint authPackage = 0;
        bool save = false;
        uint ret = CredUIPromptForWindowsCredentials(
                ref info,
                0,
                ref authPackage,
                prePack.DangerousGetHandle(),
                prePack.Length,
                out IntPtr credBuffer,
                out uint credBufferLength,
                ref save,
                flags
            );
        if (ret == 0) {
            return new SafeMemoryHandle(credBuffer, true, credBufferLength, SafeMemoryHandle.MemoryType.CoTaskMem);
        }
        return SafeMemoryHandle.Zero;
    }
    public static SafeMemoryHandle PackCredential(string? username) {
        int packSize = 0;
        IntPtr pack = IntPtr.Zero;
        if (string.IsNullOrWhiteSpace(username)) {
            return SafeMemoryHandle.Zero;
        }
        _ = CredPackAuthenticationBuffer(
            0,
            username,
            string.Empty,
            pack,
            ref packSize
        );
        pack = Marshal.AllocCoTaskMem(packSize);
        _ = CredPackAuthenticationBuffer(
            0,
            username,
            string.Empty,
            pack,
            ref packSize
        );
        return new SafeMemoryHandle(pack, true, packSize, SafeMemoryHandle.MemoryType.CoTaskMem);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDUI_INFO {
        public int cbSize;
        public IntPtr? hwndParent;
        public string pszMessageText;
        public string pszCaptionText;
        public IntPtr hbmBanner;
    }

    [DllImport("credui.dll", EntryPoint = "CredUIPromptForWindowsCredentialsW")]
    private extern static uint CredUIPromptForWindowsCredentials(
        ref CREDUI_INFO credUiInfo,
        int authError,
        ref uint authPackage,
        IntPtr InAuthBuffer,
        uint InAuthBufferSize,
        out IntPtr refOutAuthBuffer,
        out uint refOutAuthBufferSize,
        [MarshalAs(UnmanagedType.Bool)] ref bool fSave,
        PromptFlags flags
    );
    public static int GetPassLength(SafeMemoryHandle authBuffer) {
        if (authBuffer.IsInvalid) {
            return -1;
        }
        int userLength = 0;
        int domainLength = 0;
        int passLength = 0;
        _ = CredUnPackAuthenticationBuffer(
            0,
            authBuffer.DangerousGetHandle(),
            authBuffer.Length,
            null,
            ref userLength,
            null,
            ref domainLength,
            IntPtr.Zero,
            ref passLength
        );
        return passLength;
    }
    public static CredentialPack UnpackAuthBuffer(SafeMemoryHandle authBuffer, bool includePassword) {
        if (authBuffer.IsInvalid) {
            return new CredentialPack();
        }

        int userLength = 0;
        int domainLength = 0;
        int passLength = 0;
        _ = CredUnPackAuthenticationBuffer(
            0,
            authBuffer.DangerousGetHandle(),
            authBuffer.Length,
            null,
            ref userLength,
            null,
            ref domainLength,
            IntPtr.Zero,
            ref passLength
        );
        StringBuilder user = new(userLength);
        StringBuilder domain = new(domainLength);
        SafeMemoryHandle password = SafeMemoryHandle.CreateCoTaskMem((uint)((passLength + 1) * sizeof(char)));
        _ = CredUnPackAuthenticationBuffer(
            0,
            authBuffer.DangerousGetHandle(),
            authBuffer.Length,
            user,
            ref userLength,
            domain,
            ref domainLength,
            password.DangerousGetHandle(),
            ref passLength
        );
        if (!includePassword) {
            password.Dispose();
            password = SafeMemoryHandle.Zero;
        }
        return new CredentialPack() {
            UserName = user,
            Domain = domain,
            Password = password
        };
    }

    [DllImport("credui.dll", CharSet = CharSet.Unicode)]
    private static extern bool CredUnPackAuthenticationBuffer(
        int dwFlags,
        IntPtr pAuthBuffer,
        uint cbAuthBuffer,
        StringBuilder? pszUserName,
        ref int pcchMaxUserName,
        StringBuilder? pszDomainName,
        ref int pcchMaxDomainname,
        IntPtr pszPassword,
        ref int pcchMaxPassword
    );

    [LibraryImport("credui.dll", EntryPoint = "CredPackAuthenticationBufferW", StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CredPackAuthenticationBuffer(
        int dwFlags,
        string pszUserName,
        string pszPassword,
        IntPtr pPackedCredentials,
        ref int pcbPackedCredentials
    );

}