using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using SnmpSharpNet8.Pdu;
using System.Formats.Asn1;

namespace SnmpSharpNet8.Messages;

public class SnmpV2Asn1Structure : IAsn1Structure {
    private byte[] bytes = [];

    public IReadOnlyList<IAsn1Node>? Children => [Pdu];
    public string Community { get; init; } = "";
    public int Length => bytes.Length;
    public SnmpPdu Pdu { get; init; } = null!;
    public Asn1Tag Tag => default;
    public string? Value => string.Join(", ", Pdu.VarBindings.Select(vb => vb.Value));
    public long Version { get; init; }

    public ReadOnlySpan<byte> Raw {
        get => bytes.AsSpan();
        set => bytes = [.. value];
    }
    ReadOnlySpan<byte> IConstructable.Construct() => [];
}
public class SnmpV3Asn1Structure : IAsn1Structure {
    private byte[] bytes = [];

    IReadOnlyList<IAsn1Node>? IAsn1Node.Children => [ScopedPdu.InnerPdu];
    public int Length => bytes.Length;
    public required MsgGlobalData MsgGlobalData { get; init; }
    public required OctetStringRaw MsgSecurityParametersEnvelope { get; init; }
    public required UsmSecurityParameters UsmSecurityParameters { get; init; }
    public required OctetStringRaw? ScopedPduEnvelope { get; init; }
    public required ScopedPdu ScopedPdu { get; init; }
    public Asn1Tag Tag => default;
    public string? Value => string.Join(", ", ScopedPdu.InnerPdu.VarBindings.Select(vb => vb.Value));
    public long Version { get; init; }

    public ReadOnlySpan<byte> Raw {
        get => bytes.AsSpan();
        set => bytes = [.. value];
    }
    ReadOnlySpan<byte> IConstructable.Construct() => [];
}