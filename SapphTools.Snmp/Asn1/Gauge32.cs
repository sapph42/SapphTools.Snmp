using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using System.Formats.Asn1;

namespace SapphTools.Snmp.Asn1;

public class Gauge32 : SnmpUnsigned, ILeafDataType<ulong>, ICreateFromArg<Gauge32>, ITagged<Gauge32> {
    public static Asn1Tag Tag => new(TagClass.Application, 2);

    Asn1Tag IAsn1Node.Tag => Tag;
    string? IAsn1Node.Value => Value.ToString();
    IReadOnlyList<IAsn1Node>? IAsn1Node.Children => null;

    static Gauge32() {
        DataTypeRegistry.Register<Gauge32>();
    }
    public Gauge32(ReadOnlySpan<byte> raw) {
        bytes = [.. raw];
        Value = DecodeUnsigned(bytes);
    }

    public ReadOnlySpan<byte> Construct() {
        return Node.Construct(this);
    }

    public static Gauge32 Create(ReadOnlySpan<byte> raw) => new(raw);
    public static Gauge32 Create(byte[] raw) => new(raw);
    public override string ToString() => ((IAsn1Node)this).Value ?? "<no value>";
}