namespace SapphTools.Snmp.Asn1;

public abstract class SnmpUnsigned {
    protected byte[] bytes = [];

    public ReadOnlySpan<byte> Raw {
        get => bytes.AsSpan();
        set {
            bytes = [.. value];
            Value = DecodeUnsigned(bytes);
        }
    }
    public ulong Value { get; protected set; }

    internal static ulong DecodeUnsigned(ReadOnlySpan<byte> bytes) {
        ulong result = 0;
        foreach (byte b in bytes) {
            result = result << 8 | b;
        }
        return result;
    }
}
