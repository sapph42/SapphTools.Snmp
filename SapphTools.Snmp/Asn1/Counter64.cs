using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using System.Formats.Asn1;

namespace SapphTools.Snmp.Asn1;

public class Counter64 : SnmpUnsigned, ILeafDataType<ulong>, ICreateFromArg<Counter64>, ITagged<Counter64> {
    public static Asn1Tag Tag => new(TagClass.Application, 6);

    Asn1Tag IAsn1Node.Tag => Tag;
    string? IAsn1Node.Value => Value.ToString();
    IReadOnlyList<IAsn1Node>? IAsn1Node.Children => null;

    static Counter64() {
        DataTypeRegistry.Register<Counter64>();
    }
    public Counter64(ReadOnlySpan<byte> raw) {
        bytes = [.. raw];
        Value = DecodeUnsigned(bytes);
    }

    public ReadOnlySpan<byte> Construct() {
        return Node.Construct(this);
    }

    public static Counter64 Create(ReadOnlySpan<byte> raw) => new(raw);
    public static Counter64 Create(byte[] raw) => new(raw);
    public override string ToString() => ((IAsn1Node)this).Value ?? "<no value>";
}