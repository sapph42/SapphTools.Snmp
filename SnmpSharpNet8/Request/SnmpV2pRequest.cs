using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;

namespace SnmpSharpNet8.Request;

public class SnmpV2pRequest : ISnmpV2Request {
    public Integer Version => new([0x2]);
    public ObjectIdentifier DstParty { get; set; }
    public ObjectIdentifier SrcParty { get; set; }
    public ObjectIdentifier Context { get; set; }
    public IRequestPdu Pdu { get; set; }

    public ReadOnlySpan<byte> Construct() {
        byte[] payload = [
            ..Version.Construct(),
            ..DstParty.Construct(),
            ..SrcParty.Construct(),
            ..Context.Construct(),
            ..Pdu.ConstructRequest()
        ];
        return (byte[])[
            0x30,
            ..IDataType.EncodeLength(payload.Length),
            ..payload
        ];
    }
}