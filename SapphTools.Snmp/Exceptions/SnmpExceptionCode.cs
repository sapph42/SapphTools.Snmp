namespace SapphTools.Snmp.Exceptions;

public enum SnmpExceptionCodes {
    /// <summary>
    /// No error
    /// </summary>
    None = 0,
    /// <summary>
    /// Security model specified in the packet is not supported
    /// </summary>
    UnsupportedSecurityModel = 1,
    /// <summary>
    /// Privacy enabled without authentication combination in a packet is not supported.
    /// </summary>
    UnsupportedNoAuthPriv = 2,
    /// <summary>
    /// Invalid length of the authentication parameter field. Expected length is 12 bytes when authentication is
    /// enabled. Same length is used for both MD5 and SHA-1 authentication protocols.
    /// </summary>
    InvalidAuthenticationParameterLength = 3,
    /// <summary>
    /// Authentication of the received packet failed.
    /// </summary>
    AuthenticationFailed = 4,
    /// <summary>
    /// Privacy protocol requested is not supported.
    /// </summary>
    UnsupportedPrivacyProtocol = 5,
    /// <summary>
    /// Invalid length of the privacy parameter field. Expected length depends on the privacy protocol. This exception
    /// can be raised when privacy packet contents are invalidly set by agent or if wrong privacy protocol is set in the
    /// packet class definition.
    /// </summary>
    InvalidPrivacyParameterLength = 6,
    /// <summary>
    /// Authoritative engine id is invalid.
    /// </summary>
    InvalidAuthoritativeEngineId = 7,
    /// <summary>
    /// Engine boots value is invalid
    /// </summary>
    InvalidEngineBoots = 8,
    /// <summary>
    /// Received packet is outside the time window acceptable. Packet failed timeliness check.
    /// </summary>
    PacketOutsideTimeWindow = 9,
    /// <summary>
    /// Invalid request id in the packet.
    /// </summary>
    InvalidRequestId = 10,
    /// <summary>
    /// SNMP version 3 maximum message size exceeded. Packet that was encoded will exceed maximum message
    /// size acceptable in this transaction.
    /// </summary>
    MaximumMessageSizeExceeded = 11,
    /// <summary>
    /// UdpTarget request cannot be processed because IAgentParameters does not contain required information
    /// </summary>
    InvalidIAgentParameters = 12,
    /// <summary>
    /// Reply to a request was not received within the timeout period
    /// </summary>
    RequestTimedOut = 13,
    /// <summary>
    /// Null data received on request.
    /// </summary>
    NoDataReceived = 14,
    /// <summary>
    /// Security name (user name) in the reply does not match the name sent in request.
    /// </summary>
    InvalidSecurityName = 15,
    /// <summary>
    /// Report packet was received when Reportable flag was set to false (we notified the peer that we do
    /// not receive report packets).
    /// </summary>
    ReportOnNoReports = 16,
    /// <summary>
    /// Oid value type returned by an earlier operation does not match the value type returned by a subsequent entry.
    /// </summary>
    OidValueTypeChanged = 17,
    /// <summary>
    /// Specified Oid is invalid
    /// </summary>
    InvalidOid = 18,
    NetworkError = 19
}
