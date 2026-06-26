using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using SnmpSharpNet8.Pdu;
using SnmpSharpNet8.Security;
using System.Formats.Asn1;
using System.Net;

namespace SnmpSharpNet8.Messages;

public class SnmpV3Request : Request {
    private bool _didDiscovery = false;
    private int _messageId = 0;
    private ushort _maxSize = ushort.MaxValue - 28;
    private OctetStringRaw _msgAuthoritativeEngineID = new([]);
    private Integer _msgAuthoritativeEngineBoots = new(0);
    private Integer _msgAuthoritativeEngineTime = new(0);
    internal OctetStringRaw _msgUserName = new([]);
    private OctetStringRaw _msgAuthenticationParameters = new(new byte[12]);
    private OctetStringRaw _msgPrivacyParameters = new([]);

    internal Credential? AuthCred;
    internal Credential? PrivCred;
    internal MsgFlags Flags = MsgFlags.None;

    public override Integer Version => new([0x3]);
    public override IRequestPdu Pdu { get; init; } = new SnmpPdu([], new Asn1Tag(UniversalTagNumber.Null), 0, 0, 0, []);
    public required ScopedPdu ScopedPdu { get; init; }
    internal SnmpV3Request(IPAddress ip, int port, int timeout, int retries, MsgFlags flags) : base(ip, port, timeout, retries) {
        Flags = flags;
    }
    public SnmpAsn1Structure? Get() {
        SnmpAsn1Structure? resp = null;
        if (!_didDiscovery) {
            resp = Discover();
        }
        return resp;
    }
    public SnmpAsn1Structure? Discover() {
        ReadOnlySpan<byte> package = Construct();
        _socket.Send(package);
        Span<byte> response = stackalloc byte[ushort.MaxValue];
        var bytesRead = _socket.Receive(response);
        response = response[..bytesRead];
        _didDiscovery = true;
        return Parser.ParseSnmp(response);
    }
    public override ReadOnlySpan<byte> Construct() {
        if (_msgAuthoritativeEngineID.Value == "" | _msgAuthoritativeEngineBoots.Value == 0 | _msgAuthoritativeEngineTime.Value == 0) {
            _didDiscovery = false;
        }
        Sequence msgGlobalData = BuildMsgGlobalData();
        Sequence usmSecurityParameters = BuildUsmSecurityParameters();
        OctetStringRaw msgSecurityParameters = new(usmSecurityParameters.Construct());
        ReadOnlySpan<byte> pduBytes = ScopedPdu.ConstructRequest();
        int reqId;
        byte[] payload;
        if (!_didDiscovery) {
            ScopedPdu pdu = ScopedPdu.DiscoveryScopedPdu(out reqId);
            Sequence message = new([]);
            message.AddChild(Version);
            message.AddChild(msgGlobalData);
            message.AddChild(msgSecurityParameters);
            message.AddChild(pdu);
            payload = [
                ..Version.Construct(),
                ..msgGlobalData.Construct(),
                ..msgSecurityParameters.Construct(),
                   ..pduBytes
            ];
            return (byte[])[
                0x30,
                ..IDataType.EncodeLength(payload.Length),
                ..payload
            ];
        } else {
            reqId = (int)Math.Clamp(ScopedPdu.RequestPdu.RequestId, 0, int.MaxValue);
        }
        // Empty return and commented code below is temporary state for targeted testing of discovery request construction.
        // Once testing confirms valid contstruction, return will be removed, and commented code will be restored and worked on
        return Span<byte>.Empty;
        //byte[] request;
        //if ((Flags & MsgFlags.Priv) == MsgFlags.Priv && _didDiscovery) {
        //    pduBytes = SomeCryptoCall(pduBytes, otherThings, out byte[] msgPrivacyParameters);
        //    _msgPrivacyParameters = new OctetStringRaw(msgPrivacyParameters);
        //    OctetStringRaw cypherPdu = new(pduBytes);
        //    pduBytes = [.. cypherPdu.Construct()];
        //}

        //payload = [
        //    ..Version.Construct(),
        //    ..msgGlobalData.Construct(),
        //    ..msgSecurityParameters.Construct(),
        //    ..pduBytes
        //];
        //request = [
        //    0x30,
        //    ..IDataType.EncodeLength(payload.Length),
        //    ..payload
        //];
        //// CHECK FLAGS - HASH HERE 
        //if ((Flags & MsgFlags.Auth) == MsgFlags.Auth && _didDiscovery) {
        //    _msgAuthenticationParameters = new(SomeHashCall(request));
        //    msgSecurityParameters = new(usmSecurityParameters.Construct());
        //    payload = [
        //        ..Version.Construct(),
        //        ..msgGlobalData.Construct(),
        //        ..msgSecurityParameters.Construct(),
        //        ..pduBytes
        //    ];
        //    return (byte[])[
        //        0x30,
        //        ..IDataType.EncodeLength(payload.Length),
        //        ..payload
        //    ];
        //} else {
        //    return request;
        //}
    }
    private Sequence BuildMsgGlobalData() {
        _messageId = Random.Shared.Next();
        Integer messageId = new(_messageId);
        Integer maxMsgSize = new(_maxSize);
        OctetStringRaw flags = new(_didDiscovery ? [(byte)Flags] : [0x4]);
        Integer secModel = new(3);
        Sequence msgGlobalData = new([]);
        msgGlobalData.AddChild(messageId);
        msgGlobalData.AddChild(maxMsgSize);
        msgGlobalData.AddChild(flags);
        msgGlobalData.AddChild(secModel);
        return msgGlobalData;
    }
    private Sequence BuildUsmSecurityParameters() {
        Sequence usmSecurityParameters = new([]);
        if (_didDiscovery) {
            usmSecurityParameters.AddChild(_msgAuthoritativeEngineID);
            usmSecurityParameters.AddChild(_msgAuthoritativeEngineTime);
            usmSecurityParameters.AddChild(_msgUserName);
            usmSecurityParameters.AddChild(_msgAuthenticationParameters);
            usmSecurityParameters.AddChild(_msgPrivacyParameters);
        } else {
            usmSecurityParameters.AddChild(OctetStringRaw.Empty);
            usmSecurityParameters.AddChild(new Integer(0));
            usmSecurityParameters.AddChild(OctetStringRaw.Empty);
            usmSecurityParameters.AddChild(OctetStringRaw.Empty);
            usmSecurityParameters.AddChild(OctetStringRaw.Empty);
        }
        return usmSecurityParameters;
    }
}
/* SNMP REQUEST AND RESPONSE STRUCTURE - TEMPORARY REFERENCE, DO NOT INCLUDE IN COMMIT COMMENTS 
 *  
 * DISCOVERY
 * - SEQUENCE snmpv3Message
 *  - LENGTH
 *  - INTEGER msgVersion
 *  - SEQUENCE msgGlobalData
 *   - LENGTH
 *   - INTEGER msgID (random from originator ex: 0x170DD8AF)
 *   - INTEGER maxSize (65507?)
 *   - OCTETSTRING msgFlags (1 byte) (Always 0x04 for discovery)
 *   - INTEGER msgSecurityModel (3)
 *  - OCTETSTRING msgSecurityParameters
 *   - SEQUENCE - UsmSecurityParameters
 *    - OCTETSTRING msgAuthoritativeEngineID (Empty for discovery)
 *    - INTEGER msgAuthoritativeEngineBoots (0 for discovery)
 *    - INTEGER msgAuthoritativeEngineTime (0 for discovery)
 *    - OCTETSTRING msgUserName (Empty for discovery)
 *    - OCTETSTRING msgAuthenticationParameters (Empty for discovery)
 *    - OCTETSTRING msgPrivacyParameters (Empty for discovery)
 *  - SEQUENCE scopedPdu
 *   - OCTETSTRING contextEngineId (Empty for discovery)
 *   - OCTETSTRING contextName (Empty for discovery)
 *   - PDU - GetRequest A0
 *    - INTEGER requestId (random from originator)
 *    - INTEGER errorStatus (0 for send)
 *    - INTEGER errorIndex (0 for send)
 *    - SEQUENCE varBindList (empty for discovery)
 *    
 * DISCOVERY RESPONSE
 * - SEQUENCE snmpv3Message
 *  - LENGTH
 *  - INTEGER msgVersion
 *  - SEQUENCE msgGlobalData
 *   - LENGTH
 *   - INTEGER msgID (match from request 0x170DD8AF)
 *   - INTEGER maxSize (1472)
 *   - OCTETSTRING msgFlags (1 byte) (0x0)
 *   - INTEGER msgSecurityModel (3)
 *  - OCTETSTRING msgSecurityParameters
 *   - SEQUENCE - UsmSecurityParameters
 *    - OCTETSTRING msgAuthoritativeEngineID (Store for real requests)
 *    - INTEGER msgAuthoritativeEngineBoots (Store for real requests)
 *    - INTEGER msgAuthoritativeEngineTime (Store for real requests)
 *    - OCTETSTRING msgUserName (Empty for discovery response)
 *    - OCTETSTRING msgAuthenticationParameters (Empty for discovery response)
 *    - OCTETSTRING msgPrivacyParameters (Empty for discovery response)
 *  - SEQUENCE scopedPdu
 *   - OCTETSTRING contextEngineId => msgAuthoritativeEngineID
 *   - OCTETSTRING contextName (Empty for discovery response)
 *   - PDU - Report A8
 *    - INTEGER requestId (match from request)
 *    - INTEGER errorStatus 
 *    - INTEGER errorIndex 
 *    - SEQUENCE varBindList
 *     - SEQUENCE varBind
 *      - OID (likely 1.3.6.1.6.3.15.1.1.4.0)
 *      - Value (likely Counter32)
 *      
 * REAL REQUEST
 * - SEQUENCE snmpv3Message
 *  - LENGTH
 *  - INTEGER msgVersion
 *  - SEQUENCE msgGlobalData
 *   - LENGTH
 *   - INTEGER msgID (random from originator ex: 0x170DD8B0)
 *   - INTEGER maxSize (65507 again)
 *   - OCTETSTRING msgFlags (1 byte) 
 *   - INTEGER msgSecurityModel (3)
 *  - OCTETSTRING msgSecurityParameters
 *   - SEQUENCE - UsmSecurityParameters
 *    - OCTETSTRING msgAuthoritativeEngineID => from discovery
 *    - INTEGER msgAuthoritativeEngineBoots => from discovery
 *    - INTEGER msgAuthoritativeEngineTime => from discovery
 *    - OCTETSTRING msgUserName => user provided
 *    - OCTETSTRING msgAuthenticationParameters HMAC truncated 12 bytes
 *    - OCTETSTRING msgPrivacyParameters priv salt/IV 8 bytes
 *  - OCTETSTRING encryptedPDU
 *  
 * REAL RESPONSE
 * - SEQUENCE snmpv3Message
 *  - LENGTH
 *  - INTEGER msgVersion
 *  - SEQUENCE msgGlobalData
 *   - LENGTH
 *   - INTEGER msgID (random from originator ex: 0x170DD8B0)
 *   - INTEGER maxSize (65507 again)
 *   - OCTETSTRING msgFlags (1 byte) 
 *   - INTEGER msgSecurityModel (3)
 *  - OCTETSTRING msgSecurityParameters
 *   - SEQUENCE - UsmSecurityParameters
 *    - OCTETSTRING msgAuthoritativeEngineID => from discovery
 *    - INTEGER msgAuthoritativeEngineBoots => from discovery
 *    - INTEGER msgAuthoritativeEngineTime => from discovery
 *    - OCTETSTRING msgUserName => user provided
 *    - OCTETSTRING msgAuthenticationParameters HMAC truncated 12 bytes
 *    - OCTETSTRING msgPrivacyParameters priv salt/IV 8 bytes
 *  - OCTETSTRING encryptedPDU
 */
