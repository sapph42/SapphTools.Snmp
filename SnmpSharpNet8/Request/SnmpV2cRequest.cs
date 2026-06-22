using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;

namespace SnmpSharpNet8.Request;

public class SnmpV2cRequest : ISnmpV2Request {
    public Integer Version => new([0x1]);
    public OctetStringRaw Community { get; set; }
    public IRequestPdu Pdu { get; set; }

    public ReadOnlySpan<byte> Construct() {
        byte[] payload = [
            ..Version.Construct(),
            ..Community.Construct(),
            ..Pdu.ConstructRequest()
        ];
        return (byte[])[
            0x30,
            ..IDataType.EncodeLength(payload.Length),
            ..payload
        ];
    }
}
