using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using System.Net;

namespace SapphTools.Snmp.Messages;

public class SnmpV1Request : Request, ISnmpRequest {
    public override Integer Version => new([0x0]);
    public required OctetStringRaw Community { get; init; }
    public override ReadOnlySpan<byte> Construct(string[] oids, out long requestId) {
        //placeholder
        requestId = 0;
        return [];
    }
    internal SnmpV1Request(IPAddress target, int port, int timeout, int retries) : base(target, port, timeout, retries) { }
}
