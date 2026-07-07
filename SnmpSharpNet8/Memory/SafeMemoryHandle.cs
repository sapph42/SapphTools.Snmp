using SnmpSharpNet8.Interop;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SnmpSharpNet8.Memory;
public class SafeMemoryHandle : SafeHandle {
    public enum MemoryType {
        None,
        Heap,
        CoTaskMem
    }

    public static SafeMemoryHandle Zero => new(IntPtr.Zero, false, 0, MemoryType.None);
    public uint Length { get; init; }
    public uint EncryptedLength { get; init; }
    public MemoryType Type { get; init; }
    public override bool IsInvalid => handle == IntPtr.Zero || Length == 0;

    public SafeMemoryHandle(IntPtr existingHandle, bool ownsHandle, uint length, MemoryType type) : base(IntPtr.Zero, ownsHandle) {
        Length = length;
        EncryptedLength = length;
        Type = type;
        SetHandle(existingHandle);
    }
    public SafeMemoryHandle(IntPtr existingHandle, bool ownsHandle, int length, MemoryType type) :
        this(existingHandle, ownsHandle, (uint)length, type) { }

    public void Decrypt() {
        _ = CryptMem.CryptUnprotectMemory(this);
    }
    public SafeMemoryHandle Encrypt(bool release = true) {
        if (GetEncryptSize() == EncryptedLength) {
            CryptMem.CryptProtectMemory(this);
            return this;
        }
        uint encryptSize = GetEncryptSize();
        SafeMemoryHandle dest = WriteMem.MemCopy(this, Length, encryptSize);
        _ = CryptMem.CryptProtectMemory(dest);
        try {
            return dest;
        } finally {
            if (release) {
                Dispose();
            }
        }
    }
    public uint GetEncryptSize() {
        if (Length % CryptMem.CRYPTPROTECTMEMORY_BLOCK_SIZE != 0) {
            return Length + (CryptMem.CRYPTPROTECTMEMORY_BLOCK_SIZE - (Length % CryptMem.CRYPTPROTECTMEMORY_BLOCK_SIZE));
        } else {
            return Length;
        }
    }
    public unsafe void Read(Span<byte> destination) {
        if (destination.Length > Length) {
            throw new ArgumentOutOfRangeException(nameof(destination), "Destination buffer is larger than the allocated memory length.");
        }
        new Span<byte>((void*)handle, (int)Length).CopyTo(destination);
    }
    public unsafe void Write(ReadOnlySpan<byte> source) {
        if (source.Length > Length) {
            throw new ArgumentOutOfRangeException(nameof(source), "Source buffer is larger than the allocated memory length.");
        }
        source.CopyTo(new Span<byte>((void*)handle, source.Length));
    }
    protected override bool ReleaseHandle() {
        if (IsInvalid) {
            return false;
        }
        _ = WriteMem.MemZero(this);
        switch (Type) {
            case MemoryType.None:
                return false;
            case MemoryType.Heap:
                Marshal.FreeHGlobal(handle);
                break;
            case MemoryType.CoTaskMem:
                Marshal.FreeCoTaskMem(handle);
                break;
        }
        return true;
    }
    public static SafeMemoryHandle Create(MemoryType type, uint length) {
        return type switch {
            MemoryType.CoTaskMem => new SafeMemoryHandle(Marshal.AllocCoTaskMem((int)length), true, length, MemoryType.CoTaskMem),
            _ => new SafeMemoryHandle(Marshal.AllocHGlobal((int)length), true, length, MemoryType.Heap),
        };
    }
    public static SafeMemoryHandle CreateCoTaskMem(uint length) => Create(MemoryType.CoTaskMem, length);
    public static SafeMemoryHandle CreateHGlobal(uint length) => Create(MemoryType.Heap, length);

    public static SafeMemoryHandle MigrateHandle(ref SafeMemoryHandle consumedHandle, out SafeMemoryHandle resultHandle, MemoryType resultType) {
        SafeMemoryHandle local = Interlocked.Exchange(ref consumedHandle!, null) ?? throw new ArgumentNullException(nameof(consumedHandle));
        try {
            resultHandle = WriteMem.MemCopy(consumedHandle, consumedHandle.EncryptedLength, resultType);
            return resultHandle;
        } finally {
            local.Dispose();
        }
    }
    public new void Dispose() {
        unsafe {
            CryptographicOperations.ZeroMemory(new Span<byte>((void*)handle, (int)Length));
        }
        ReleaseHandle();
    }
}