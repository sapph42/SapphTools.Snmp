using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;

namespace SnmpSharpNet8.Pdu;

public class ScopedPdu {
    public OctetStringRaw ContextEngineId { get; init; }
    public OctetStringRaw ContextName { get; init; }
    public IRequestPdu RequestPdu { get; init; }
}
