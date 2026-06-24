using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using System.Formats.Asn1;

namespace SnmpSharpNet8.Pdu;

public class ScopedPdu {
    public required OctetStringRaw ContextEngineId { get; init; }
    public required OctetStringRaw ContextName { get; init; }
    public required SnmpPdu RequestPdu { get; init; }

    public ReadOnlySpan<byte> ConstructRequest() {
        byte[] payload = [
            ..ContextEngineId.Construct(),
            ..ContextName.Construct(),
            ..RequestPdu.ConstructRequest()
        ];
        Span<byte> tagValue = [];
        _ = new Asn1Tag(TagClass.ContextSpecific, 0, true).Encode(tagValue);
        return (byte[])[
            ..tagValue,
            ..IDataType.EncodeLength(payload.Length),
            ..payload
        ];
    }
    public static ScopedPdu DiscoveryScopedPdu(out int reqId) {
        return new ScopedPdu() {
            ContextEngineId = new([]),
            ContextName = new([]),
            RequestPdu = SnmpPdu.DiscoveryPdu(out reqId)
        };
    }
}
