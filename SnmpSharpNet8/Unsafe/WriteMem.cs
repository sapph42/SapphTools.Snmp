using SnmpSharpNet8.Types;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace SnmpSharpNet8.Unsafe;
internal static partial class WriteMem {
    public static SafeMemoryHandle MemCopy(SafeMemoryHandle src, UIntPtr count, uint destSize = 0) {
        if (src.IsInvalid) {
            return SafeMemoryHandle.Zero;
        }
        if (src.EncryptedLength < (uint)count) {
            return SafeMemoryHandle.Zero;
        }
        destSize = destSize == 0 ? src.EncryptedLength : destSize;
        SafeMemoryHandle ret = SafeMemoryHandle.Create(src.Type, destSize);
        _ = Memcpy(ret.DangerousGetHandle(), src.DangerousGetHandle(), count);
        return ret;
    }
    public static SafeMemoryHandle MemCopy(SafeMemoryHandle src, UIntPtr count, SafeMemoryHandle.MemoryType outType, uint destSize = 0) {
        if (src.IsInvalid) {
            return SafeMemoryHandle.Zero;
        }
        if (src.EncryptedLength < (uint)count) {
            return SafeMemoryHandle.Zero;
        }
        destSize = destSize == 0 ? src.EncryptedLength : destSize;
        SafeMemoryHandle ret = SafeMemoryHandle.Create(outType, destSize);
        _ = Memcpy(ret.DangerousGetHandle(), src.DangerousGetHandle(), count);
        return ret;
    }
    public static SafeMemoryHandle MemCopy(SafeMemoryHandle src, uint count, uint destSize = 0) => MemCopy(src, (UIntPtr)count, destSize);
    public static SafeMemoryHandle MemCopy(SafeMemoryHandle src, int count, uint destSize = 0) => MemCopy(src, (UIntPtr)count, destSize);
    public static SafeMemoryHandle MemCopy(SafeMemoryHandle src, uint count, SafeMemoryHandle.MemoryType outType, uint destSize = 0) => MemCopy(src, (UIntPtr)count, outType, destSize);
    public static SafeMemoryHandle MemCopy(SafeMemoryHandle src, int count, SafeMemoryHandle.MemoryType outType, uint destSize = 0) => MemCopy(src, (UIntPtr)count, outType, destSize);

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool MemSet(SafeMemoryHandle handle, byte c, UIntPtr count) {
        if (handle.IsInvalid) {
            return false;
        }
        if (handle.EncryptedLength < (uint)count) {
            return false;
        }
        _ = Memset(handle.DangerousGetHandle(), (int)c, count);
        return true;
    }
    public static bool MemSet(SafeMemoryHandle handle, byte c, uint count) => MemSet(handle, c, (UIntPtr)count);
    public static bool MemSet(SafeMemoryHandle handle, byte c, int count) => MemSet(handle, c, (UIntPtr)count);

    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static bool MemZero(SafeMemoryHandle handle) {
        return MemSet(handle, 0, handle.EncryptedLength);
    }

    [LibraryImport("msvcrt.dll", EntryPoint = "memcpy", SetLastError = false)]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(CallConvCdecl) })]
    private static partial IntPtr Memcpy(IntPtr dest, IntPtr src, UIntPtr count);

    [LibraryImport("msvcrt.dll", EntryPoint = "memset", SetLastError = false)]
    [UnmanagedCallConv(CallConvs = new Type[] { typeof(CallConvCdecl) })]
    private static partial IntPtr Memset(IntPtr dest, int c, UIntPtr count);
}