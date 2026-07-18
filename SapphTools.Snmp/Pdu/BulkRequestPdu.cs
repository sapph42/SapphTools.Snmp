using SapphTools.Asn1;
using SapphTools.Snmp.Asn1;
using System.Formats.Asn1;

namespace SapphTools.Snmp.Pdu;

public sealed class BulkRequestPdu : Asn1Node, IRequestPdu {
    public override IReadOnlyList<IAsn1Node>? Children => VarBindings;
    public Asn1Tag PduType { get; init; }
    public long RequestId { get; init; }
    public int NonRepeaters { get; init; }
    public int MaxRepititions { get; init; }
    public IReadOnlyList<VarBinding> VarBindings { get; init; } = [];

    public BulkRequestPdu(ReadOnlySpan<byte> raw, Asn1Tag pduType,
               long requestId, int nonRepeaters, int maxRepetitions,
               IReadOnlyList<VarBinding> varBindings) : base(raw) {
        Tag = pduType;
        PduType = pduType;
        RequestId = requestId;
        NonRepeaters = nonRepeaters;
        MaxRepititions = maxRepetitions;
        VarBindings = varBindings;
    }
    public override ReadOnlySpan<byte> Construct() => ConstructRequest([], out _);
    public ReadOnlySpan<byte> Construct(string[] _, out long requestId) => ConstructRequest([], out requestId);
    public ReadOnlySpan<byte> ConstructRequest(string[] _, out long requestId) {
        int tagValue = PduType.TagValue;
        requestId = RequestId;
        int nonRep = NonRepeaters;
        int maxRep = MaxRepititions;
        List<byte> varBindings = [];
        foreach (VarBinding vb in VarBindings) {
            varBindings.AddRange(vb.ConstructRequest());
        }
        return (byte[])[
            ..BitConverter.GetBytes(tagValue),
            ..BitConverter.GetBytes(requestId),
            ..BitConverter.GetBytes(nonRep),
            ..BitConverter.GetBytes(maxRep),
            ..varBindings
        ];
    }
    public static string PduKind(Asn1Tag t) =>
    t.TagClass == TagClass.ContextSpecific
        ? t.TagValue switch {
            0 => "GetRequest",
            1 => "GetNextRequest",
            2 => "GetResponse",
            3 => "SetRequest",
            5 => "GetBulkRequest",
            6 => "InformRequest",
            7 => "SNMPv2-Trap",
            8 => "Report",
            _ => $"PDU({t.TagValue})"
        }
        : $"PDU({t.TagClass}:{t.TagValue})";
    static IRequestPdu IRequestPdu.Create(ReadOnlySpan<byte> raw, Asn1Tag tag) => throw new NotImplementedException();
}