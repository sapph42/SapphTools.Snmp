using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;

namespace SnmpSharpNet8.Request;

public class SnmpV2cRequest : ISnmpV2Request {
    public int Version => 1;
    public OctetStringRaw Community { get; set; }
    public IRequestPdu Pdu { get; set; }

    public ReadOnlySpan<byte> Construct() {
        return (byte[])[
            ..BitConverter.GetBytes(Version),
            ..Community.Construct(),
            ..Pdu.ConstructRequest()
        ];
    }
}
