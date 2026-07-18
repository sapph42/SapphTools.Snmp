using SapphTools.Asn1.DataTypes;
using System.Net;

namespace SapphTools.Snmp.Messages;

public class SnmpV1Request : SnmpV2cRequest {
    public override Integer Version => new([0x0]);
    internal SnmpV1Request(IPAddress target, int port, int timeout, int retries) : base(target, port, timeout, retries) { }
    public override SnmpV1Asn1Structure? Get(string[] oids) => (SnmpV1Asn1Structure?)base.Get(oids);
    public override SnmpV1Asn1Structure? GetNext(string[] oids) => (SnmpV1Asn1Structure?)base.GetNext(oids);
    public new List<SnmpV1Asn1Structure> Walk(string ancestorOid) => [.. base.Walk(ancestorOid).Cast<SnmpV1Asn1Structure>()];
}
