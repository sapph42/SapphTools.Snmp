using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;

namespace SnmpSharpNet8.Pdu;

public class ScopedPdu : IConstructable {
    private byte[] _raw;
    internal Asn1Tag Tag => new(UniversalTagNumber.OctetString);
    internal int Length = 0;
    public required OctetStringRaw ContextEngineId { get; init; }
    public required OctetStringRaw ContextName { get; init; }
    public ReadOnlySpan<byte> Raw {
        get => _raw;
    }
    public required SnmpPdu RequestPdu { get; init; }

    [SetsRequiredMembers]
    internal ScopedPdu(OctetStringRaw contextEngineId, OctetStringRaw contextName, SnmpPdu requestPdu) {
        ContextEngineId = contextEngineId;
        ContextName = contextName;
        RequestPdu = requestPdu;
        ReadOnlySpan<byte> cei = ContextEngineId.Construct();
        ReadOnlySpan<byte> cn = ContextName.Construct();
        ReadOnlySpan<byte> rp = RequestPdu.Construct();
        Length = cei.Length + cn.Length + rp.Length;
        _raw = new byte[Length];
        cei.CopyTo(_raw);
        cn.CopyTo(_raw.AsSpan(cei.Length));
        rp.CopyTo(_raw.AsSpan(cei.Length + cn.Length));
    }
    public ReadOnlySpan<byte> Construct() => ConstructRequest();
    public ReadOnlySpan<byte> ConstructRequest() {
        Span<byte> tagValue = stackalloc byte[1];
        _ = new Asn1Tag(UniversalTagNumber.OctetString).Encode(tagValue);
        return (byte[])[
            ..tagValue,
            ..IDataType.EncodeLength(_raw.Length),
            .._raw
        ];
    }
    public static ScopedPdu DiscoveryScopedPdu(out int reqId) {
        return new ScopedPdu(
            new([]),
            new([]),
            SnmpPdu.DiscoveryPdu(out reqId)
        );
    }
}
