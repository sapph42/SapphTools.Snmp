using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using System.Formats.Asn1;

namespace SapphTools.Snmp.Asn1;

public class TimeTicks : ILeafDataType<TimeSpan>, ICreateFromArg<TimeTicks>, ITagged<TimeTicks> {
    private byte[] bytes = [];
    private ulong _decoded;
    public static Asn1Tag Tag => new(TagClass.Application, 3);

    public ReadOnlySpan<byte> Raw {
        get => bytes.AsSpan();
        set {
            bytes = [.. value];
            _decoded = SnmpUnsigned.DecodeUnsigned(bytes);
        }
    }

    public TimeSpan Value => TimeSpan.FromMilliseconds(_decoded * 10);

    Asn1Tag IAsn1Node.Tag => Tag;
    string? IAsn1Node.Value => Value.ToString();
    IReadOnlyList<IAsn1Node>? IAsn1Node.Children => null;

    static TimeTicks() {
        DataTypeRegistry.Register<TimeTicks>();
    }
    public TimeTicks(ReadOnlySpan<byte> raw) {
        bytes = [.. raw];
        _decoded = SnmpUnsigned.DecodeUnsigned(bytes);
    }
    public ReadOnlySpan<byte> Construct() {
        return Node.Construct(this);
    }

    public static TimeTicks Create(ReadOnlySpan<byte> raw) => new(raw);
    public static TimeTicks Create(byte[] raw) => new(raw);
}