using SnmpSharpNet8.Memory;
using Windows.Win32;

namespace SnmpSharpNet8.Interop;

internal static unsafe partial class CryptMem {
    internal const uint CRYPTPROTECTMEMORY_SAME_PROCESS = 0;
    internal const uint CRYPTPROTECTMEMORY_BLOCK_SIZE = 16;

    public const int INVALID_BLOCK_SIZE = -4242;

    public static int CryptProtectMemory(SafeMemoryHandle handle) {
        if (handle.EncryptedLength % CRYPTPROTECTMEMORY_BLOCK_SIZE != 0) {
            return INVALID_BLOCK_SIZE;
        } else {
            if (PInvoke.CryptProtectMemory((void*)handle.DangerousGetHandle(), handle.EncryptedLength, CRYPTPROTECTMEMORY_SAME_PROCESS)) {
                return 0;
            } else {
                return 1;
            }
        }
    }
    public static int CryptUnprotectMemory(SafeMemoryHandle handle) {
        if (handle.EncryptedLength % CRYPTPROTECTMEMORY_BLOCK_SIZE != 0) {
            return INVALID_BLOCK_SIZE;
        } else {
            if (PInvoke.CryptUnprotectMemory((void*)handle.DangerousGetHandle(), handle.EncryptedLength, CRYPTPROTECTMEMORY_SAME_PROCESS)) {
                return 0;
            } else {
                return 1;
            }
        }
    }
}