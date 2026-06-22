using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using SnmpSharpNet8.Types;
using System.Net;

namespace SnmpSharpNet8.Requests;

public class SnmpV2cRequest : Request, ISnmpV2Request {
    public override Integer Version => new([0x1]);
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
    internal SnmpV2cRequest(IPAddress target, int port, int timeout, int retries) : base(target, port, timeout, retries) { }
}
