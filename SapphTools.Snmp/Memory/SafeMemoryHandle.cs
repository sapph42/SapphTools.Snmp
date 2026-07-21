using SapphTools.Snmp.Interop;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace SapphTools.Snmp.Memory;

public class SafeMemoryHandle : SafeHandle, IEquatable<SafeMemoryHandle> {
    public enum MemoryType {
        None,
        Heap,
        CoTaskMem
    }

    public static SafeMemoryHandle Zero => new(IntPtr.Zero, false, 0, MemoryType.None);
    public uint Length { get; init; }
    public uint EncryptedLength { get; init; }
    public MemoryType Type { get; init; }
    public override bool IsInvalid => handle == IntPtr.Zero;

    public SafeMemoryHandle(IntPtr existingHandle, bool ownsHandle, uint length, MemoryType type) : base(IntPtr.Zero, ownsHandle) {
        Length = length;
        EncryptedLength = length;
        Type = type;
        SetHandle(existingHandle);
    }
    public SafeMemoryHandle(IntPtr existingHandle, bool ownsHandle, int length, MemoryType type) :
        this(existingHandle, ownsHandle, (uint)length, type) { }

    public void Decrypt() => _ = CryptMem.CryptUnprotectMemory(this);
    public unsafe SafeMemoryHandle Encrypt(bool release = true) {
        if (GetEncryptSize() == EncryptedLength) {
            _ = CryptMem.CryptProtectMemory(this);
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
        Span<byte> span = new((void*)handle, (int)EncryptedLength);
        CryptographicOperations.ZeroMemory(span);
    }
    protected override bool ReleaseHandle() {
        if (handle == IntPtr.Zero) {
            return true;
        }
        try {
            ZeroMem();
            switch (Type) {
                case MemoryType.Heap:
                    Marshal.FreeHGlobal(handle);
                    break;
                case MemoryType.CoTaskMem:
                    Marshal.FreeCoTaskMem(handle);
                    break;
                case MemoryType.None:
                    break;
            }
            return true;
        } catch {
            // ReleaseHandle must not allow exceptions to escape.
            return false;
        }
    }
    public static SafeMemoryHandle Create(MemoryType type, uint length) {
        return type switch {
            MemoryType.CoTaskMem => new SafeMemoryHandle(Marshal.AllocCoTaskMem((int)length), true, length, MemoryType.CoTaskMem),
            MemoryType.None or MemoryType.Heap or _ => new SafeMemoryHandle(Marshal.AllocHGlobal((int)length), true, length, MemoryType.Heap)
        };
    }
    public static SafeMemoryHandle CreateCoTaskMem(uint length) => Create(MemoryType.CoTaskMem, length);
    public static SafeMemoryHandle CreateHGlobal(uint length) => Create(MemoryType.Heap, length);

    public static unsafe SafeMemoryHandle MigrateHandle(
        ref SafeMemoryHandle consumedHandle,
        out SafeMemoryHandle resultHandle,
        MemoryType resultType
    ) {
        SafeMemoryHandle local =
            Interlocked.Exchange(ref consumedHandle!, null)
            ?? throw new ArgumentNullException(nameof(consumedHandle));
        try {
            uint length = local.EncryptedLength;
            resultHandle = Create(resultType, length);
            Span<byte> source = new((void*)local.DangerousGetHandle(), checked((int)length));
            Span<byte> destination = new((void*)resultHandle.DangerousGetHandle(), checked((int)length));
            destination.Clear();
            source.CopyTo(destination);
            return resultHandle;
        } finally {
            local.Dispose();
        }
    }
    public bool Equals(SafeMemoryHandle? other) {
        if (other is null) {
            return false;
        }
        if (handle == IntPtr.Zero && other.handle == IntPtr.Zero) {
            return true;
        }
        return handle == other.handle && Length == other.Length && Type == other.Type;
    }
    public override bool Equals(object? obj) => Equals(obj as SafeMemoryHandle);
    public override int GetHashCode() => base.GetHashCode();
}