using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using System.Formats.Asn1;

namespace SapphTools.Snmp.Asn1;

public class Counter32 : SnmpUnsigned, ILeafDataType<ulong>, ICreateFromArg<Counter32>, ITagged<Counter32> {
    public static Asn1Tag Tag => new(TagClass.Application, 1);

    Asn1Tag IAsn1Node.Tag => Tag;
    string? IAsn1Node.Value => Value.ToString();
    IReadOnlyList<IAsn1Node>? IAsn1Node.Children => null;

    static Counter32() {
        DataTypeRegistry.Register<Counter32>();
    }
    public Counter32(ReadOnlySpan<byte> raw) {
        bytes = [.. raw];
        Value = DecodeUnsigned(bytes);
    }

    public ReadOnlySpan<byte> Construct() {
        return Node.Construct(this);
    }
    public static Counter32 Create(ReadOnlySpan<byte> raw) => new(raw);
    public static Counter32 Create(byte[] raw) => new(raw);
    public override string ToString() => ((IAsn1Node)this).Value ?? "<no value>";
}
