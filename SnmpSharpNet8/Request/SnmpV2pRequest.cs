using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;

namespace SnmpSharpNet8.Request;

public class SnmpV2pRequest : ISnmpV2Request {
    public int Version => 2;
    public ObjectIdentifier DstParty { get; set; }
    public ObjectIdentifier SrcParty { get; set; }
    public ObjectIdentifier Context { get; set; }
    public IRequestPdu Pdu { get; set; }

    public ReadOnlySpan<byte> Construct() {
        return (byte[])[
            ..BitConverter.GetBytes(Version),
            ..DstParty.Construct(),
            ..SrcParty.Construct(),
            ..Pdu.ConstructRequest()
        ];
    }
}