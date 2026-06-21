using SapphTools.Asn1.DataTypes;

namespace SnmpSharpNet8.Request;

public class SnmpV2pRequest : ISnmpRequest {
    public int Version => 1;
    public OctetStringRaw Community { get; set; }
    public object Pdu { get; set; }
}
