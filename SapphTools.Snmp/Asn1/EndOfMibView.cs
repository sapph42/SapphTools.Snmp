using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using System.Formats.Asn1;

namespace SapphTools.Snmp.Asn1;
public class EndOfMibView : ILeafDataType<object?>, ICreateFromArg<EndOfMibView>, ITagged<EndOfMibView> {
    public static readonly EndOfMibView Instance = new();
    public ReadOnlySpan<byte> Raw {
        get => [];
        set { }
    }
    public static Asn1Tag Tag => new(TagClass.ContextSpecific, 0, false);
    public object? Value => null;
    Asn1Tag IAsn1Node.Tag => Tag;
    string? IAsn1Node.Value => null;
    IReadOnlyList<IAsn1Node>? IAsn1Node.Children => null;
    static EndOfMibView() {
        DataTypeRegistry.Register<EndOfMibView>();
    }
    public EndOfMibView() { }
    public ReadOnlySpan<byte> Construct() => Node.Construct(this);
    public static EndOfMibView Create(ReadOnlySpan<byte> _) => new();
    public static EndOfMibView Create(byte[] _) => new();
    public static EndOfMibView Create(object? _) => new();
}
