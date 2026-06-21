using SapphTools.Asn1;

namespace SnmpSharpNet8.Request;

public interface ISnmpV2Request : ISnmpRequest {
    IRequestPdu Pdu { get; set; }
}
