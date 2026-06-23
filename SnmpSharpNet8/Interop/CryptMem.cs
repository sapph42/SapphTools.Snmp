using SnmpSharpNet8.Memory;
using System.Runtime.InteropServices;

namespace SnmpSharpNet8.Interop;
internal static partial class CryptMem {
    internal const uint CRYPTPROTECTMEMORY_SAME_PROCESS = 0;
    internal const uint CRYPTPROTECTMEMORY_BLOCK_SIZE = 16;

    public const int INVALID_BLOCK_SIZE = -4242;

    public static int CryptProtectMemory(SafeMemoryHandle handle) {
        if (handle.EncryptedLength % CRYPTPROTECTMEMORY_BLOCK_SIZE != 0) {
            return INVALID_BLOCK_SIZE;
        }
        if (CryptProtectMemory(handle.DangerousGetHandle(), handle.EncryptedLength)) {
            return 0;
        }
        return 1;
    }
    public static int CryptUnprotectMemory(SafeMemoryHandle handle) {
        if (handle.EncryptedLength % CRYPTPROTECTMEMORY_BLOCK_SIZE != 0) {
            return INVALID_BLOCK_SIZE;
        }
        if (CryptUnprotectMemory(handle.DangerousGetHandle(), handle.EncryptedLength)) {
            return 0;
        }
        return 1;
    }

    [LibraryImport("crypt32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptProtectMemory(IntPtr ptr, uint size, uint dwFlags = CRYPTPROTECTMEMORY_SAME_PROCESS);

    [LibraryImport("crypt32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool CryptUnprotectMemory(IntPtr ptr, uint size, uint dwFlags = CRYPTPROTECTMEMORY_SAME_PROCESS);
}