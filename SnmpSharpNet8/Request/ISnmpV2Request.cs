using SapphTools.Asn1;

namespace SnmpSharpNet8.Request;

public interface ISnmpV2Request : ISnmpRequest {
    ISnmpRequest Pdu { get; set; }
}
