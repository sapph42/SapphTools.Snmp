using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using System.Net;

namespace SnmpSharpNet8.Messages; 
public class SnmpV1Request : Request, ISnmpRequest {
    public override Integer Version => new([0x0]);
    public required OctetStringRaw Community { get; init; }
    public override required IRequestPdu Pdu { get; init; }
    public override ReadOnlySpan<byte> Construct() {
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
    internal SnmpV1Request(IPAddress target, int port, int timeout, int retries) : base(target, port, timeout, retries) { }
}
