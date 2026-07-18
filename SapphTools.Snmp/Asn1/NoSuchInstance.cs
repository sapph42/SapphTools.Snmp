using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using System.Formats.Asn1;

namespace SapphTools.Snmp.Asn1;
public class NoSuchInstance : ILeafDataType<object?>, ICreateFromArg<NoSuchInstance>, ITagged<NoSuchInstance> {
    public static readonly NoSuchInstance Instance = new();
    public ReadOnlySpan<byte> Raw {
        get => [];
        set { }
    }
    public static Asn1Tag Tag => new(TagClass.ContextSpecific, 0, false);
    public object? Value => null;
    Asn1Tag IAsn1Node.Tag => Tag;
    string? IAsn1Node.Value => null;
    IReadOnlyList<IAsn1Node>? IAsn1Node.Children => null;
    static NoSuchInstance() {
        DataTypeRegistry.Register<NoSuchInstance>();
    }
    public NoSuchInstance() { }
    public ReadOnlySpan<byte> Construct() => Node.Construct(this);
    public static NoSuchInstance Create(ReadOnlySpan<byte> _) => new();
    public static NoSuchInstance Create(byte[] _) => new();
    public static NoSuchInstance Create(object? _) => new();
}
