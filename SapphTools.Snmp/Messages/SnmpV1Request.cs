using SapphTools.Asn1.DataTypes;
using System.Net;

namespace SapphTools.Snmp.Messages;

public class SnmpV1Request : SnmpV2cRequest {
    public override Integer Version => new([0x0]);
    internal SnmpV1Request(IPAddress target, int port, int timeout, int retries) : base(target, port, timeout, retries) { }
    public override Result Get(string[] oids) => base.Get(oids);
    public override Result GetNext(string[] oids) => base.GetNext(oids);
    public new Result Walk(string ancestorOid) => base.Walk(ancestorOid);
}
