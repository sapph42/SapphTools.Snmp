using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using System.Formats.Asn1;

namespace SapphTools.Snmp.Asn1;
public class NoSuchObject : ILeafDataType<object?>, ICreateFromArg<NoSuchObject>, ITagged<NoSuchObject> {
    public static readonly NoSuchObject Instance = new();
    public ReadOnlySpan<byte> Raw {
        get => [];
        set { }
    }
    public static Asn1Tag Tag => new(TagClass.ContextSpecific, 0, false);
    public object? Value => null;
    Asn1Tag IAsn1Node.Tag => Tag;
    string? IAsn1Node.Value => null;
    IReadOnlyList<IAsn1Node>? IAsn1Node.Children => null;
    static NoSuchObject() {
        DataTypeRegistry.Register<NoSuchObject>();
    }
    public NoSuchObject() { }
    public ReadOnlySpan<byte> Construct() => Node.Construct(this);
    public static NoSuchObject Create(ReadOnlySpan<byte> _) => new();
    public static NoSuchObject Create(byte[] _) => new();
    public static NoSuchObject Create(object? _) => new();
}
