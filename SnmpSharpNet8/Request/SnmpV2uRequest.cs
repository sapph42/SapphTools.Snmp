using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;

namespace SnmpSharpNet8.Request;

public class SnmpV2uRequest : ISnmpV2Request {
    private OctetStringRaw parametersWrapped => new(Parameters.GetBytes());
    public Integer Version => new([0x2]);
    public Parameters2u Parameters { get; set; }
    public IRequestPdu Pdu { get; set; }

    public ReadOnlySpan<byte> Construct() {
        byte[] payload = [
            ..Version.Construct(),
            ..parametersWrapped.Construct(),
            ..Pdu.ConstructRequest()
        ];
        return (byte[])[
            0x30,
            ..IDataType.EncodeLength(payload.Length),
            ..payload
        ];
    }
}