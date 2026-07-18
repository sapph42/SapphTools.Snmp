using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using System.Formats.Asn1;
using System.Net;

namespace SapphTools.Snmp.Asn1;

public sealed class SnmpIpAddress : ILeafDataType<IPAddress>, ICreateFromArg<SnmpIpAddress>, ITagged<SnmpIpAddress> {
    private byte[] bytes = [];

    public ReadOnlySpan<byte> Raw {
        get => bytes.AsSpan();
        set => bytes = [.. value];
    }
    public static Asn1Tag Tag => new(TagClass.Application, 0);  // 0x40
    public IPAddress Value => new(bytes);

    Asn1Tag IAsn1Node.Tag => Tag;
    string? IAsn1Node.Value => Value.ToString();
    IReadOnlyList<IAsn1Node>? IAsn1Node.Children => null;

    static SnmpIpAddress() {
        DataTypeRegistry.Register<SnmpIpAddress>();
    }
    public SnmpIpAddress(ReadOnlySpan<byte> raw) => bytes = [.. raw];
    public ReadOnlySpan<byte> Construct() {
        return Node.Construct(this);
    }

    public static SnmpIpAddress Create(ReadOnlySpan<byte> raw) => new(raw);
    public static SnmpIpAddress Create(byte[] raw) => new(raw);
    public override string ToString() => ((IAsn1Node)this).Value ?? "<no value>";
}