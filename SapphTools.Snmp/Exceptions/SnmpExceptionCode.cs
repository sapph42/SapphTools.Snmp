namespace SapphTools.Snmp.Exceptions;

public enum SnmpExceptionCode {
    None,
    UnsupportedSecurityModel,
    UnsupportedNoAuthPriv,
    InvalidAuthenticationParameterLength,
    AuthenticationFailed,
    DecryptionFailed,
    UnsupportedPrivacyProtocol,
    InvalidPrivacyParameterLength,
    InvalidAuthoritativeEngineId,
    InvalidEngineBoots,
    PacketOutsideTimeWindow,
    InvalidRequestId,
    MaximumMessageSizeExceeded,
    InvalidIAgentParameters,
    RequestTimedOut,
    NoDataReceived,
    InvalidSecurityName,
    ReportOnNoReports,
    OidValueTypeChanged,
    InvalidOid,
    NetworkError,
    ParsingError
}
