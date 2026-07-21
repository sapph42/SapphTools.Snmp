using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using SapphTools.Snmp.Asn1;
using SapphTools.Snmp.Messages;
using System.Diagnostics;
using System.Formats.Asn1;

namespace SapphTools.Snmp.Pdu;

public sealed class BulkRequestPdu : Asn1Node, IRequestPdu {
    public override IReadOnlyList<IAsn1Node>? Children => VarBindings;
    public Asn1Tag PduType { get; init; }
    public long RequestId { get; init; }
    public int Value1 { get; init; }
    public int Value2 { get; init; }
    public int NonRepeaters {
        get => Value1;
        init => Value1 = value;
    }
    public int MaxRepititions {
        get => Value2;
        init => Value2 = value;
    }
    public IReadOnlyList<VarBinding> VarBindings { get; init; } = [];

    public BulkRequestPdu(ReadOnlySpan<byte> raw,
               long requestId, int nonRepeaters, int maxRepetitions,
               IReadOnlyList<VarBinding> varBindings) : base(raw) {
        Tag = GeneralRequestType.GetBulkRequest.ToTag();
        PduType = GeneralRequestType.GetBulkRequest.ToTag();
        RequestId = requestId;
        NonRepeaters = nonRepeaters;
        MaxRepititions = maxRepetitions;
        VarBindings = varBindings;
    }
    public static BulkRequestPdu Build(IReadOnlyList<VarBinding>? varBindings, int nonRepeaters, int maxRepetitions) {
        varBindings ??= [];
        Span<byte> tagByte = stackalloc byte[1];
        _ = GeneralRequestType.GetBulkRequest.ToTag().Encode(tagByte);
        int requestId = Random.Shared.Next();
        Sequence varBindSeq = new([]);
        //Debug.WriteLine("");
        //Debug.WriteLine("");
        //Debug.WriteLine("Building BulkRequest PDU");
        //Debug.WriteLine("NonRepeaters: ");
        //int nonRepIdx = 0;
        foreach (VarBinding vb in varBindings) {
            //if (nonRepIdx == nonRepeaters) {
            //    Debug.WriteLine($"MaxRepetitions: {maxRepetitions}");
            //}
            //nonRepIdx++;
            //Debug.WriteLine($"  {{{vb.Name.Value.Value}}}");
            varBindSeq.AddChild(vb);
        }
        byte[] payload = [
            ..new Integer(requestId).Construct(),
            ..new Integer(nonRepeaters).Construct(),
            ..new Integer(maxRepetitions).Construct(),
            ..varBindSeq.Construct()
        ];
        return new(payload, requestId, nonRepeaters, maxRepetitions, varBindings);
    }
    public override ReadOnlySpan<byte> Construct() => ConstructRequest([], out _);
    public ReadOnlySpan<byte> Construct(out long requestId) => ConstructRequest([], out requestId);
    public ReadOnlySpan<byte> ConstructRequest(string[] oids, out long requestId) {
        Span<byte> tagByte = stackalloc byte[1];
        _ = PduType.Encode(tagByte);
        requestId = RequestId;
        Sequence varBindings = new([]);
        if (oids.Length == 0) {
            foreach (VarBinding vb in VarBindings) {
                varBindings.AddChild(vb);
            }
        } else {
            foreach (string oid in oids) {
                varBindings.AddChild(new VarBinding(oid, Asn1Null.Instance));
            }
        }
        byte[] payload = [
            ..new Integer(requestId).Construct(),
            ..new Integer(NonRepeaters).Construct(),
            ..new Integer(MaxRepititions).Construct(),
            ..varBindings.Construct()
        ];
        return (byte[])[
            ..tagByte,
            ..IDataType.EncodeLength(payload.Length),
            ..payload
        ];
    }
    static IRequestPdu IRequestPdu.Create(ReadOnlySpan<byte> raw, Asn1Tag tag) => throw new NotImplementedException();
}