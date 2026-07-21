using SapphTools.Asn1;
using SapphTools.Snmp.Asn1;

namespace SapphTools.Snmp;
public class Result {
    public required string Protocol { get; init; }
    public string Action { get; set; } = "Get";
    public Exception? Exception { get; set; }
    public SnmpExceptionCode ExceptionCode { get; set; } = SnmpExceptionCode.None;
    public ResultStep Step { get; set; } = ResultStep.Initialized;
    public IAsn1Structure? ParsedStructure { get; set; }
    public List<IAsn1Structure>? WalkedStructures { get; set; }
    public List<VarBinding> VarBindings { get; init; } = [];
}
public enum ResultStep {
    Initialized                  = 0,
    SnmpV2RequestSent            = 1,
    SnmpV2ResponseReceived       = 2,
    SnmpV2ResponseParsed         = 3,
    SnmpV2VarBindingsAttached    = 4,
    SnmpV3DiscoRequestSent      = 10,
    SnmpV3DiscoResponseReceived = 11,
    SnmpV3DiscoResponseParsed   = 12,
    SnmpV3DiscoveryComplete     = 13,
    SnmpV3RequestSent           = 14,
    SnmpV3ResponseReceived      = 15,
    SnmpV3AuthPassed            = 16,
    SnmpV3ResponseParsed        = 17,
    SnmpV3VarBindingsAttached   = 18
}