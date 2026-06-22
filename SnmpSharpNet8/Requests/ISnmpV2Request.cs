using SapphTools.Asn1;

namespace SnmpSharpNet8.Requests;

public interface ISnmpV2Request : ISnmpRequest {
    IRequestPdu Pdu { get; init; }
}
