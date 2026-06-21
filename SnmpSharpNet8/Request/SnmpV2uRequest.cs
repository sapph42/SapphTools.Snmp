using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;

namespace SnmpSharpNet8.Request;

public class SnmpV2uRequest : ISnmpV2Request {
    public int Version => 2;
    public Parameters2u Parameters { get; set; }
    public IRequestPdu Pdu { get; set; }
}