using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using System.Net;
using System.Formats.Asn1;
using SnmpSharpNet8.Pdu;

namespace SnmpSharpNet8.Messages;

public class SnmpV3Request : Request {
    private bool _didDiscovery = false;
    private int _messageId = 0;
    private ushort _maxSize = ushort.MaxValue - 28;
    private OctetStringRaw _msgAuthoritativeEngineID = new([]);
    private Integer _msgAuthoritativeEngineBoots = new(0);
    private Integer _msgAuthoritativeEngineTime = new(0);
    private OctetStringRaw _msgUserName = new([]);
    private OctetStringRaw _msgAuthenticationParameters = new(new byte[12]);
    private OctetStringRaw _msgPrivacyParameters = new([]);

    public override Integer Version => new([0x3]);
    public MsgFlags Flags { get; set; } = MsgFlags.None;
    public override IRequestPdu Pdu { get; init; } = new SnmpPdu([], new Asn1Tag(UniversalTagNumber.Null), 0, 0, 0, []);
    public required ScopedPdu ScopedPdu { get; init; }
    public override ReadOnlySpan<byte> Construct() {
        Sequence msgGlobalData = BuildMsgGlobalData();
        Sequence usmSecurityParameters = BuildUsmSecurityParameters();
        OctetStringRaw msgSecurityParameters = new(usmSecurityParameters.Construct());

        byte[] pduBytes = ScopedPdu.ConstructRequest();
        if ((Flags & MsgFlags.Priv) == MsgFlags.Priv && _didDiscovery) {
            pduBytes = SomeCryptoCall(pduBytes, otherThings, out byte [] msgPrivacyParameters);
            _msgPrivacyParameters = new OctetStringRaw(msgPrivacyParameters);
            OctetStringRaw cypherPdu = new(pduBytes);
            pduBytes = [..cypherPdu.Construct()];
        }
        
        byte[] payload = [
            ..Version.Construct(),
            ..msgGlobalData.Construct(),
            ..msgSecurityParameters.Construct(),
            ..pduBytes
        ];
        byte[] request = [
            0x30,
            ..IDataType.EncodeLength(payload.Length),
            ..payload
        ];
        // CHECK FLAGS - HASH HERE 
        if ((Flags & MsgFlags.Auth) == MsgFlags.Auth && _didDiscovery) {
            _msgAuthenticationParameters = new(SomeHashCall(request));
            msgSecurityParameters = new(usmSecurityParameters.Construct());
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
            return request;
        }
    }
    internal SnmpV3Request(IPAddress target, int port, int timeout, int retries) : base(target, port, timeout, retries) { }
    internal void Discover(bool force = false) {
        if (_didDiscovery && !force) {
            return;
        }
    }
    private Sequence BuildMsgGlobalData() {
        _messageId = Random.Shared.Next();
        Integer messageId = new(_messageId);
        Integer maxMsgSize = new(_maxSize);
        OctetStringRaw flags = new([(byte)Flags]);
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
        usmSecurityParameters.AddChild(_msgAuthoritativeEngineID);
        usmSecurityParameters.AddChild(_msgAuthoritativeEngineTime);
        usmSecurityParameters.AddChild(_msgUserName);
        usmSecurityParameters.AddChild(_msgAuthenticationParameters);
        usmSecurityParameters.AddChild(_msgPrivacyParameters);
        return usmSecurityParameters;
    }
}
/*
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
