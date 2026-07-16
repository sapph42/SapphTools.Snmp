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
    public unsafe SafeMemoryHandle Encrypt(bool release = true) {
        if (GetEncryptSize() == EncryptedLength) {
            CryptMem.CryptProtectMemory(this);
            return this;
        }
        uint encryptSize = GetEncryptSize();

        SafeMemoryHandle dest = Create(Type, encryptSize);
        Span<byte> srcData = new((void*)handle, (int)Length);
        Span<byte> dstData = new((void*)dest.handle, (int)encryptSize);
        dstData.Clear();
        srcData.CopyTo(dstData);
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
        return Length % CryptMem.CRYPTPROTECTMEMORY_BLOCK_SIZE != 0
            ? Length + (CryptMem.CRYPTPROTECTMEMORY_BLOCK_SIZE - (Length % CryptMem.CRYPTPROTECTMEMORY_BLOCK_SIZE))
            : Length;
    }
    public unsafe void CopyTo(Span<byte> destination) {
        if (Length > destination.Length) {
            throw new ArgumentOutOfRangeException(nameof(destination), "Destination buffer is smaller than the allocated memory length.");
        }
        new Span<byte>((void*)handle, (int)Length).CopyTo(destination);
    }
    public unsafe void CopyTo(Span<byte> destination, int length) {
        if (destination.Length > length) {
            throw new ArgumentOutOfRangeException(nameof(destination), "Destination buffer is smaller than the allocated memory length slice.");
        }
        if (length > Length) {
            throw new ArgumentOutOfRangeException(nameof(length), "Requested slice larger than the allocated memory length.");
        }
        new Span<byte>((void*)handle, length).CopyTo(destination);
    }
    public unsafe void CopyFrom(ReadOnlySpan<byte> source) {
        if (source.Length > Length) {
            throw new ArgumentOutOfRangeException(nameof(source), "Source buffer is larger than the allocated memory length.");
        }
        source.CopyTo(new Span<byte>((void*)handle, source.Length));
    }
    public unsafe void ZeroMem() {
        Span<byte> span = new((void*)handle, (int)Length);
        CryptographicOperations.ZeroMemory(span);
    }
    protected override bool ReleaseHandle() {
        if (IsInvalid) {
            return false;
        }
        ZeroMem();
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

    public static unsafe SafeMemoryHandle MigrateHandle(ref SafeMemoryHandle consumedHandle, out SafeMemoryHandle resultHandle, MemoryType resultType) {
        SafeMemoryHandle local = Interlocked.Exchange(ref consumedHandle!, null) ?? throw new ArgumentNullException(nameof(consumedHandle));
        try {
            uint len = consumedHandle.EncryptedLength;
            resultHandle = Create(resultType, len);
            Span<byte> srcData = new((void*)consumedHandle.handle, (int)len);
            Span<byte> dstData = new((void*)resultHandle.handle, (int)len);
            dstData.Clear();
            srcData.CopyTo(dstData);
            return resultHandle;
        } finally {
            local.Dispose();
        }
    }
    public new void Dispose() {
        unsafe {
            CryptographicOperations.ZeroMemory(new Span<byte>((void*)handle, (int)Length));
        }
        _ = ReleaseHandle();
    }
}