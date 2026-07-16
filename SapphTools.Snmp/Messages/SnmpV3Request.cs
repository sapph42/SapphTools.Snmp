using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using SapphTools.Snmp.Pdu;
using SapphTools.Snmp.Security;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;

namespace SapphTools.Snmp.Messages;

public class SnmpV3Request : Request {
    private bool _didDiscovery;
    private int _messageId;
    private readonly ushort _maxSize = ushort.MaxValue - 28;
    private OctetStringRaw _msgAuthoritativeEngineID = new([]);
    private Integer _msgAuthoritativeEngineBoots = new(0);
    private Integer _msgAuthoritativeEngineTime = new(0);
    internal OctetStringRaw _msgUserName = new([]);
    private OctetStringRaw _msgAuthenticationParameters = new([]);
    private OctetStringRaw _msgPrivacyParameters = new([]);
    internal OctetStringRaw _contextName = new([]);

    internal Authentication? AuthAlgo;
    internal Privacy? PrivAlgo;
    internal Credential? AuthCred;
    internal Credential? PrivCred;
    internal MsgFlags Flags = MsgFlags.None;
    internal Stopwatch EngineTimeMod = new();

    public override Integer Version => new([0x3]);
    public required ScopedPdu ScopedPdu { get; init; }

    internal SnmpV3Request(IPAddress ip, int port, int timeout, int retries, MsgFlags flags) : base(ip, port, timeout, retries) {
        Flags = flags;
        _ = Random.Shared.Next();
    }
    public SnmpV3Asn1Structure? Get(string[] oids) => InternalGet(oids, null, null, null, null);
    public SnmpV3Asn1Structure? Get(string[] oids, Authentication auth, Credential authCred) =>
        InternalGet(oids, auth, null, authCred, null);
    public SnmpV3Asn1Structure? Get(string[] oids, Authentication auth, Privacy priv, Credential authCred, Credential privCred) =>
        InternalGet(oids, auth, priv, authCred, privCred);
    private SnmpV3Asn1Structure? InternalGet(string[] oids, Authentication? auth, Privacy? priv, Credential? authCred, Credential? privCred) {
        AuthCred ??= authCred;
        PrivCred ??= privCred;
        AuthAlgo ??= auth;
        PrivAlgo ??= priv;
        Flags = AuthAlgo is null
            ? MsgFlags.None
            : PrivAlgo is null
                ? MsgFlags.AuthNoPrivRep
                : MsgFlags.AuthPrivRep;
        CancellationTokenSource cts;
        if (!_didDiscovery) {
            cts = new(Timeout * _retries);
            SnmpV3Asn1Structure? resp = Discover(cts.Token);
            if (resp is null) {
                if (cts.IsCancellationRequested) {
                    throw new SnmpNetworkException(
                        SnmpExceptionCode.RequestTimedOut,
                        "Did not recieve a proper response within the alloted timeout window."
                    );
                } else {
                    throw new SnmpDecodingException(
                        sysException: new AsnContentException("Unable to parse SNMP Discovery response")
                    );
                }
            }
        }
        cts = new(Timeout * _retries);
        ReadOnlySpan<byte> package = Construct(oids, out long requestId);
        return Send(package, requestId, false, cts.Token);
    }
    private SnmpV3Asn1Structure? Send(ReadOnlySpan<byte> package, long requestId, bool disco, CancellationToken token) {
        int sent;
        Span<byte> response = stackalloc byte[ushort.MaxValue];
        SnmpV3Asn1Structure? resp = null;
        int retry = 0;
        while (resp is null && !token.IsCancellationRequested && retry < _retries) {
            try {
                retry++;
                sent = _socket.Send(package);
                if (sent != package.Length) {
                    throw new SnmpNetworkException(msg: "Number of bytes sent by socket does not match request length.");
                }
#if UNSAFEVERBOSE
                Debug.WriteLine("");
                Debug.WriteLine("");
                Debug.WriteLine($"{(disco ? "Discovery " : "Request   ")}Package Sent [{package.Length:D3}]: {string.Join(' ', package.ToArray().Select(b => Convert.ToHexString([b])))}");
                Debug.WriteLine($"Waiting for response, receive timeout: {_socket.ReceiveTimeout}, retry {retry - 1}");
#endif
                int bytesRead = 0;
                try {
                    bytesRead = _socket.Receive(response);
                } catch (SocketException se) when (se.ErrorCode == 10060) { }
                if (bytesRead == 0) {
                    continue;
                }
                response = response[..bytesRead];
#if UNSAFEVERBOSE
                Debug.WriteLine("");
                Debug.WriteLine("");
                Debug.WriteLine($"{(disco ? "Discovery " : "Request   ")}Package Recv [{response.Length:D3}]: {string.Join(' ', response.ToArray().Select(b => Convert.ToHexString([b])))}");
#endif
                if (disco) {
                    resp = (SnmpV3Asn1Structure)Parser.ParseSnmp(response);
                } else {
                    resp = (SnmpV3Asn1Structure)Parser.ParseSnmp(response, AuthAlgo, PrivAlgo, AuthCred, PrivCred);
                }

                if (resp.MsgGlobalData.MsgId.Value != _messageId) {
                    resp = null;
                    continue;
                }
                _msgAuthoritativeEngineTime = resp.UsmSecurityParameters.MsgAuthoritativeEngineTime;
                EngineTimeMod.Restart();
            } catch (Exception ex) {
                resp = null;
                throw new SnmpDecodingException(msg: "Error parsing SNMP response.", sysException: ex);
            }
        }
        if (resp is null) {
            throw new SnmpNetworkException(
                SnmpExceptionCode.RequestTimedOut, 
                "Failed to receive any response within the timeout and retry parameters.");
        }
        return resp;
    }
    public SnmpV3Asn1Structure? Discover(CancellationToken token) {
        ReadOnlySpan<byte> package = Construct([], out long requestId);
        SnmpV3Asn1Structure? resp = Send(package, requestId, true, token);
        if (resp is not null) {
            EngineTimeMod.Start();
            _msgAuthoritativeEngineID = resp.UsmSecurityParameters.MsgAuthoritativeEngineID;
            _msgAuthoritativeEngineBoots = resp.UsmSecurityParameters.MsgAuthoritativeEngineBoots;
            _msgAuthoritativeEngineTime = resp.UsmSecurityParameters.MsgAuthoritativeEngineTime;
            _msgAuthenticationParameters = new(new string('\0', AuthAlgo?.AuthHeaderLength ?? 0));
            _msgPrivacyParameters = new(new string('\0', PrivAlgo?.PrivacyParametersLength ?? 0));
            _didDiscovery = true;
        }
        return resp;
    }
    public override ReadOnlySpan<byte> Construct(string[] oids, out long requestId) {
        if (_msgAuthoritativeEngineID.Value == "" | _msgAuthoritativeEngineBoots.Value == 0 | _msgAuthoritativeEngineTime.Value == 0) {
            _didDiscovery = false;
        }
        ReadOnlySpan<byte> spdu;
        if (!_didDiscovery) {
            ScopedPdu pdu = ScopedPdu.DiscoveryScopedPdu(out requestId);
            pdu.Encrypted = false;
            spdu = pdu.Construct();
            return BuildRequest(spdu);
        }
        List<VarBinding> vbs = [];
        Asn1Null nullVal = new();
        foreach (string oid in oids) {
            ObjectIdentifier oidNode = new(new OidStruct(oid));
            VarBinding vb = new([], oidNode, nullVal);
            vbs.Add(vb);
        }
        SnmpPdu innerPdu = SnmpPdu.Build(
            new Asn1Tag(TagClass.ContextSpecific, 0, true),
            vbs
        );
        requestId = innerPdu.RequestId;
        ScopedPdu scopedPdu = new(_msgAuthoritativeEngineID, _contextName, innerPdu) {
            Encrypted = false
        };
        spdu = scopedPdu.Construct();
        byte[] request;
        if (PrivAlgo is not null && PrivCred is not null && AuthAlgo is not null && AuthCred is not null) {
            spdu = PrivCred.Encrypt(
                spdu,
                _msgAuthoritativeEngineID.Raw,
                _msgAuthoritativeEngineBoots.Value,
                _msgAuthoritativeEngineTime.Value,
                PrivAlgo,
                out byte[] privParams);
            _msgPrivacyParameters = new(privParams);
            OctetStringRaw encryptedPdu = new(spdu);
            request = BuildRequest(encryptedPdu.Construct());
            _msgAuthenticationParameters = new(
                AuthCred.GenerateHash(request, _msgAuthoritativeEngineID.Raw, AuthAlgo)
            );
            request = BuildRequest(encryptedPdu.Construct(), true);
        } else if (AuthAlgo is not null && AuthCred is not null) {
            request = BuildRequest(spdu);
            _msgAuthenticationParameters = new(
                AuthCred.GenerateHash(request, _msgAuthoritativeEngineID.Raw, AuthAlgo)
            );
            request = BuildRequest(spdu, true);
        } else {
            request = BuildRequest(spdu);
        }
        return request;
    }
    private byte[] BuildRequest(ReadOnlySpan<byte> spdu, bool retainMessageId = false) {
        return [
            0x30,
            ..IDataType.EncodeLength(BuildPayload(spdu, out byte[] payload, retainMessageId)),
            ..payload
        ];
    }
    private int BuildPayload(ReadOnlySpan<byte> spdu, out byte[] payload, bool retainMessageId = false) {
        payload = [
            ..Version.Construct(),
            ..BuildMsgGlobalData(retainMessageId).Construct(),
            ..new OctetStringRaw(BuildUsmSecurityParameters().Construct()).Construct(),
            ..spdu
        ];
        return payload.Length;
    }
    private MsgGlobalData BuildMsgGlobalData(bool retainMessageId = false) {
        if (!retainMessageId) {
            _messageId = Random.Shared.Next();
        }
        Integer messageId = new(_messageId);
        Integer maxMsgSize = new(_maxSize);
        OctetStringRaw flags = new(_didDiscovery ? [(byte)Flags] : [0x4]);
        Integer secModel = new(3);
        return new MsgGlobalData(messageId, maxMsgSize, flags, secModel);
    }
    private UsmSecurityParameters BuildUsmSecurityParameters() {
        return _didDiscovery
            ? new(
                _msgAuthoritativeEngineID,
                _msgAuthoritativeEngineBoots,
                BuildAuthoritativeEngineTime(),
                _msgUserName,
                _msgAuthenticationParameters,
                _msgPrivacyParameters)
            : new(
                OctetStringRaw.Empty,
                new Integer(0),
                new Integer(0),
                OctetStringRaw.Empty,
                OctetStringRaw.Empty,
                OctetStringRaw.Empty);
    }
    private Integer BuildAuthoritativeEngineTime() {
        if (_msgAuthoritativeEngineTime.Value == 0) {
            return _msgAuthoritativeEngineTime;
        }
        return new Integer(_msgAuthoritativeEngineTime.Value + Convert.ToInt64(EngineTimeMod.Elapsed.TotalSeconds));
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
