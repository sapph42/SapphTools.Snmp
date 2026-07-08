using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using SnmpSharpNet8.Pdu;
using SnmpSharpNet8.Security;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;

namespace SnmpSharpNet8.Messages;

public abstract class Request : ISnmpRequest, IDisposable {
    protected Socket _socket;
    protected bool _socketDisposed;
    protected IPEndPoint _peerEndPoint;
    protected int _requestId;
    protected int _retries = 1;

    public abstract Integer Version { get; }
    public abstract IRequestPdu Pdu { get; init; }
    public IPAddress Target { get; init; }

    protected Request(IPAddress target, int port, int timeout, int retries) {
        Target = target;
        _peerEndPoint = new(target, port);
        _socket = new(target.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        IPEndPoint localEndPoint = new(IPAddress.Any, 0);
        _socket.Bind(localEndPoint);
        _socket.ReceiveTimeout = timeout;
        _retries = retries;
    }

    public static SnmpV2cRequest CreateV2(string ip, string community, string[] oids, int port = 161, int timeout = 0, int retries = 0)
        => CreateV2c(ip, community, oids, port, timeout, retries);

    public static SnmpV2cRequest CreateV2c(string ip, string community, string[] oids, int port = 161, int timeout = 0, int retries = 0) {
        IPAddress ipAddress = IPAddress.Parse(ip);
        OctetStringRaw communityOS = new(community);
        Asn1Tag requestTag = new(TagClass.ContextSpecific, 0);
        int requestId = new Random((int)DateTime.Now.Ticks).Next();
        List<VarBinding> vbs = [];
        Asn1Null nullVal = new();
        foreach (string oid in oids) {
            ObjectIdentifier oidNode = new(new OidStruct(oid));
            VarBinding vb = new([], oidNode, nullVal);
            vbs.Add(vb);
        }
        SnmpPdu pdu = new([], requestTag, requestId, 0, 0, vbs);
        return new(ipAddress, port, timeout, retries) {
            Community = communityOS,
            Pdu = pdu,
        };
    }
    public static SnmpV3Request CreateV3(
        string ip,
        string userName,
        string contextEngineId = "",
        int port = 161,
        int timeout = 0,
        int retries = 0
    ) => CreateV3Internal(ip, null, null, userName, contextEngineId, port, timeout, retries);
    public static SnmpV3Request CreateV3(
        string ip,
        AuthenticationDigest digest,
        string userName,
        string contextEngineId = "",
        int port = 161,
        int timeout = 0,
        int retries = 0
    ) => CreateV3Internal(ip, digest, null, userName, contextEngineId, port, timeout, retries);
    public static SnmpV3Request CreateV3(
        string ip,
        AuthenticationDigest digest,
        PrivacyProtocol privacy,
        string userName,
        string contextEngineId = "",
        int port = 161,
        int timeout = 0,
        int retries = 0
    ) => CreateV3Internal(ip, digest, privacy, userName, contextEngineId, port, timeout, retries);
    private static SnmpV3Request CreateV3Internal(
        string ip,
        AuthenticationDigest? digest,
        PrivacyProtocol? privacy,
        string userName,
        string contextEngineId = "",
        int port = 161,
        int timeout = 0,
        int retries = 0
    ) {
        MsgFlags flags;
        Authentication? authProvider = null;
        Privacy? privacyProvider = null;
        if (digest is null && privacy is null) {
            flags = MsgFlags.NoAuthNoPrivRep;
        } else if (digest is null) {
            throw new UnreachableException();
        } else if (privacy is null) {
            flags = MsgFlags.AuthNoPrivRep;
            authProvider = new(digest.Value);
        } else {
            flags = MsgFlags.AuthPrivRep;
            authProvider = new(digest.Value);
            privacyProvider = new(privacy.Value, authProvider);
        }
        digest ??= AuthenticationDigest.None;
        privacy ??= PrivacyProtocol.None;
        IPAddress ipAddress = IPAddress.Parse(ip);
        Credential? authCred = null;
        Credential? privCred = null;
        if (digest != AuthenticationDigest.None) {
            authCred = new(null, "Enter authSecret:", userName);
        }
        if (privacy != PrivacyProtocol.None) {
            privCred = new(null, "Enter privSecret:", userName);
        }
        Asn1Tag requestTag = new(TagClass.ContextSpecific, 0, true);
        int requestId = Random.Shared.Next();
        List<VarBinding> vbs = [];
        SnmpPdu pdu = new([], requestTag, requestId, 0, 0, vbs);
        ScopedPdu sPdu = new(
            new(contextEngineId),
            new(string.Empty),
            pdu
        );
        return new(ipAddress, port, timeout, retries, flags) {
            ScopedPdu = sPdu,
            AuthCred = authCred,
            PrivCred = privCred,
            _msgUserName = new(userName),
            AuthAlgo = authProvider,
            PrivAlgo = privacyProvider
        };
    }
    public abstract ReadOnlySpan<byte> Construct(string[] oids, out long requestId);

    public void Dispose() {
        _socket.Dispose();
        GC.SuppressFinalize(this);
    }
}
