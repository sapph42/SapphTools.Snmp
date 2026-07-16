using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using System.Formats.Asn1;

namespace SnmpSharpNet8.Pdu;

public class SnmpPdu : Asn1Node, IRequestPdu, IDataType, ICreateFromArg<SnmpPdu>, ITagged<SnmpPdu> {
    public override IReadOnlyList<IAsn1Node>? Children => VarBindings;
    public long ErrorIndex { get; init; }
    public long ErrorStatus { get; init; }
    public Asn1Tag PduType { get; init; }
    static Asn1Tag ITagged<SnmpPdu>.Tag => new(TagClass.ContextSpecific, 30, true);
    public long RequestId { get; init; }
    public IReadOnlyList<VarBinding> VarBindings { get; init; } = [];
    public override string? Value =>
        $"{PduKind(PduType)} reqId={RequestId} errStatus={ErrorStatus} " +
        $"errIndex={ErrorIndex} [{string.Join("; ", VarBindings.Select(v => v.Value))}]";

    static SnmpPdu() {
        DataTypeRegistry.Register<SnmpPdu>();
        DataTypeRegistry.Register<SnmpPdu>(new(TagClass.ContextSpecific, 2, false));
        DataTypeRegistry.Register<SnmpPdu>(new(TagClass.ContextSpecific, 8, false));
        DataTypeRegistry.RegisterPdu<SnmpPdu>();
        DataTypeRegistry.RegisterPdu<SnmpPdu>(new(TagClass.ContextSpecific, 2, true));
        DataTypeRegistry.RegisterPdu<SnmpPdu>(new(TagClass.ContextSpecific, 8, true));
    }
    public SnmpPdu(ReadOnlySpan<byte> raw, Asn1Tag pduType,
               long requestId, long errorStatus, long errorIndex,
               IReadOnlyList<VarBinding> varBindings) : base(raw) {
        Tag = pduType;
        PduType = pduType;
        RequestId = requestId;
        ErrorStatus = errorStatus;
        ErrorIndex = errorIndex;
        VarBindings = varBindings;
    }
    public static SnmpPdu Build(Asn1Tag pduType, IReadOnlyList<VarBinding>? varBindings) {
        varBindings ??= [];
        Span<byte> tagByte = stackalloc byte[1];
        _ = pduType.Encode(tagByte);
        int requestId = Random.Shared.Next();
        Sequence varBindSeq = new([]);
        foreach (VarBinding vb in varBindings) {
            varBindSeq.AddChild(vb);
        }
        byte[] payload = [
            ..new Integer(requestId).Construct(),
            ..new Integer(0).Construct(),
            ..new Integer(0).Construct(),
            ..varBindSeq.Construct()
        ];
        return new(payload, pduType, requestId, 0, 0, varBindings);
    }
    public override ReadOnlySpan<byte> Construct() => ConstructRequest([], out _);
    public ReadOnlySpan<byte> Construct(out long requestId) => ConstructRequest([], out requestId);
    public ReadOnlySpan<byte> ConstructRequest(string[] oids, out long requestId) {
        Span<byte> tagByte = stackalloc byte[1];
        _ = PduType.Encode(tagByte);
        requestId = RequestId;
        int errStatus = (int)Math.Clamp(ErrorStatus, 0, int.MaxValue);
        int errIndex = (int)Math.Clamp(ErrorIndex, 0, int.MaxValue);
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
            ..new Integer(errStatus).Construct(),
            ..new Integer(errIndex).Construct(),
            ..varBindings.Construct()
        ];
        return (byte[])[
            ..tagByte,
            ..IDataType.EncodeLength(payload.Length),
            ..payload
        ];
    }
    public static SnmpPdu Create(ReadOnlySpan<byte> raw) => (SnmpPdu)Create(raw, new(TagClass.ContextSpecific, 2, true));
    public static IRequestPdu Create(ReadOnlySpan<byte> raw, Asn1Tag tag) {
        List<IAsn1Node> children = Asn1.ParseChildren(raw, true);

        if (children.Count < 4) {
            throw new FormatException("PDU content too short");
        }

        Integer reqNode = children[0] as Integer ?? throw new FormatException("Missing requestId");
        Integer errStatusNode = children[1] as Integer ?? throw new FormatException("Missing errorStatus");
        Integer errIndexNode = children[2] as Integer ?? throw new FormatException("Missing errorIndex");
        Sequence varBindSeq = children[3] as Sequence ?? throw new FormatException("Missing varBind sequence");
        //////HERE IS THE FAILURE - VarBinding is a Sequence in spec and not in code and fails the cast!!!!!
        ///Original: VarBinding[] varBindings = [.. varBindSeq.Items.Cast<VarBinding>()];
        ///The following may or may not work.  Aggressive testing needed
        ///Condsider refactoring VarBinding to derive from Sequence
        List<VarBinding> varBindings = [];
        if (varBindSeq.Items.All(i => i is Sequence)) {
            foreach (Sequence seq in varBindSeq.Items.Cast<Sequence>()) {
                if (seq.Items.Count != 2) {
                    continue;
                }
                if (seq.Items[0] is not ObjectIdentifier oid) {
                    continue;
                }
                if (seq.Items[1] is not IDataType dt) {
                    continue;
                }
                VarBinding vb = new(seq.Raw, oid, dt);
                varBindings.Add(vb);
            }
        } else {
            for (int i = 0; i < varBindSeq.Items.Count; i += 2) {
                if (varBindSeq.Items[i] is not ObjectIdentifier oid) {
                    continue;
                }
                if (varBindSeq.Items[i + 1] is not IDataType dt) {
                    continue;
                }
                VarBinding vb = new(oid.Value.Value, dt);
                varBindings.Add(vb);
            }
        }
        return new SnmpPdu(raw, tag, reqNode.Value, errStatusNode.Value, errIndexNode.Value, varBindings);
    }
    public static SnmpPdu DiscoveryPdu(out long reqId) {
        return new(
            ConstructDiscoveryRequest(out reqId),
            new Asn1Tag(TagClass.ContextSpecific, 0, true),
            reqId,
            0,
            0,
            []
        );
    }
    private static ReadOnlySpan<byte> ConstructDiscoveryRequest(out long reqId) {
        Span<byte> tagValue = stackalloc byte[1];
        reqId = Random.Shared.NextInt64();
        int errStatus = 0;
        int errIndex = 0;
        return (byte[])[
            ..new Integer(reqId).Construct(),
            ..new Integer(errStatus).Construct(),
            ..new Integer(errIndex).Construct(),
            ..new Sequence([]).Construct()
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
}