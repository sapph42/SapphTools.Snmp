using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using SnmpSharpNet8.Types;
using System.Net;
using System.Formats.Asn1;

namespace SnmpSharpNet8.Requests;

public class SnmpV3Request : Request {
    private bool _didDiscovery = false;
    public override Integer Version => new([0x1]);
    public MsgFlags Flags { get; set; } = MsgFlags.None;
    public override required IRequestPdu Pdu { get; init; } = new SnmpPdu([], new Asn1Tag(UniversalTagNumber.Null), 0, 0, 0, []);
    public required ScopedPdu ScopedPdu { get; init; }
    public override ReadOnlySpan<byte> Construct() {
        Integer messageId = new(new Random((int)DateTime.Now.Ticks).Next());
        Integer maxMsgSize = new(63 * 1024);
        OctetStringRaw flags = new([(byte)Flags]);
        Integer secModel = new(3);
        object secParams; //TODO
        // THIS NEEDS SUBSTANTIAL ADDITIONAL WORK FOR FUNCTIONALITY
        byte[] payload = [
            ..Version.Construct(),
            ..messageId.Construct(),
            ..maxMsgSize.Construct(),
            ..Pdu.ConstructRequest()
        ];
        return (byte[])[
            0x30,
            ..IDataType.EncodeLength(payload.Length),
            ..payload
        ];
    }
    internal SnmpV3Request(IPAddress target, int port, int timeout, int retries) : base(target, port, timeout, retries) { }
}
