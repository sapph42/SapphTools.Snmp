using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using System.Formats.Asn1;

namespace SnmpSharpNet8.Pdu;
public class ReportPdu : SnmpPdu, IDataType, ICreateFromArg<ReportPdu>, ITagged<ReportPdu> {
    public static new Asn1Tag Tag => new(TagClass.ContextSpecific, 8, true);
    static ReportPdu() {
        DataTypeRegistry.Register<ReportPdu>();
    }
    public ReportPdu(ReadOnlySpan<byte> raw,
            Asn1Tag pduType,
            long requestId,
            long errorStatus,
            long errorIndex,
            IReadOnlyList<VarBinding> varBindings
    ) : base(raw, pduType, requestId, errorStatus, errorIndex, varBindings) { }

    public static new ReportPdu Create(ReadOnlySpan<byte> raw) => (ReportPdu)Asn1.Parse(raw);
}
