using SapphTools.Asn1.DataTypes;
using SapphTools.Snmp.Asn1;
using SapphTools.Snmp.Memory;
using SapphTools.Snmp.Pdu;
using SapphTools.Snmp.Security;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;

namespace SapphTools.Snmp.Messages;

public abstract class Request : ISnmpRequest, IDisposable {
    protected Socket _socket;
    protected bool _socketDisposed;
    protected IPEndPoint _peerEndPoint;
    protected int _requestId;
    protected int _retries = 1;
    protected ObjectIdentifier? _LastReceivedDuringWalk;

    public abstract Integer Version { get; }
    public IPAddress Target { get; init; }
    public int Port { get; init; }
    public int Timeout { get; set; } = 5000;

    protected Request(IPAddress target, int port, int timeout, int retries) {
        Target = target;
        Port = port;
        Timeout = timeout;
        _peerEndPoint = new(Target, Port);
        _socket = new(Target.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        _socket.Bind(new IPEndPoint(IPAddress.Any, 0));
        _socket.ReceiveTimeout = Timeout / 2;
        _socket.SendTimeout = Timeout / 2;
        _socket.Connect(_peerEndPoint);
#if NOTRACE
        _socket.ReceiveTimeout = -1;
        _socket.SendTimeout = -1;
        Timeout = int.MaxValue;
#endif
        _retries = retries;
    }
    public static SnmpV1Request CreateV1(string ip, string community, int port = 161, int timeout = 0, int retries = 0) {
        IPAddress ipAddress = IPAddress.Parse(ip);
        OctetStringRaw communityOS = new(community);
        Asn1Tag requestTag = new(TagClass.ContextSpecific, 0);
        int requestId = new Random((int)DateTime.Now.Ticks).Next();
        List<VarBinding> vbs = [];
        Asn1Null nullVal = new();
        SnmpPdu pdu = new([], requestTag, requestId, 0, 0, vbs);
        return new(ipAddress, port, timeout, retries) {
            Community = communityOS
        };
    }
    public static SnmpV2cRequest CreateV2(string ip, string community, int port = 161, int timeout = 0, int retries = 0)
        => CreateV2c(ip, community, port, timeout, retries);

    public static SnmpV2cRequest CreateV2c(string ip, string community, int port = 161, int timeout = 0, int retries = 0) {
        IPAddress ipAddress = IPAddress.Parse(ip);
        OctetStringRaw communityOS = new(community);
        Asn1Tag requestTag = new(TagClass.ContextSpecific, 0);
        int requestId = new Random((int)DateTime.Now.Ticks).Next();
        List<VarBinding> vbs = [];
        Asn1Null nullVal = new();
        SnmpPdu pdu = new([], requestTag, requestId, 0, 0, vbs);
        return new(ipAddress, port, timeout, retries) {
            Community = communityOS
        };
    }
    public static SnmpV3Request CreateV3(
        string ip,
        string userName,
        string contextName = "",
        int port = 161,
        int timeout = 0,
        int retries = 0
    ) => CreateV3Internal(ip, null, null, userName, contextName, port, timeout, retries);
    public static SnmpV3Request CreateV3(
        string ip,
        AuthenticationDigest digest,
        string userName,
        string contextName = "",
        int port = 161,
        int timeout = 0,
        int retries = 0
    ) => CreateV3Internal(ip, digest, null, userName, contextName, port, timeout, retries);
    public static SnmpV3Request CreateV3(
        string ip,
        AuthenticationDigest digest,
        PrivacyProtocol privacy,
        string userName,
        string contextName = "",
        int port = 161,
        int timeout = 0,
        int retries = 0
    ) => CreateV3Internal(ip, digest, privacy, userName, contextName, port, timeout, retries);
    public static SnmpV3Request CreateV3(
        string ip,
        AuthenticationDigest digest,
        Credential authCred,
        string userName,
        string contextName = "",
        int port = 161,
        int timeout = 0,
        int retries = 0
    ) => CreateV3Internal(ip, digest, null, userName, contextName, port, timeout, retries, authCred, null);
    public static SnmpV3Request CreateV3(
        string ip,
        AuthenticationDigest digest,
        PrivacyProtocol privacy,
        Credential authCred,
        Credential privCred,
        string userName,
        string contextName = "",
        int port = 161,
        int timeout = 0,
        int retries = 0
    ) => CreateV3Internal(ip, digest, privacy, userName, contextName, port, timeout, retries, authCred, privCred);
    private static SnmpV3Request CreateV3Internal(
        string ip,
        AuthenticationDigest? digest,
        PrivacyProtocol? privacy,
        string userName,
        string contextName = "",
        int port = 161,
        int timeout = 0,
        int retries = 0,
        Credential? authCred = null,
        Credential? privCred = null
    ) {
        MsgFlags flags;
        Authentication? authProvider = null;
        Privacy? privacyProvider = null;
        digest ??= AuthenticationDigest.None;
        privacy ??= PrivacyProtocol.None;
        if (digest != AuthenticationDigest.None) {
            authCred ??= new(null, "Enter authSecret:", userName);
            if (authCred.Equals(SafeMemoryHandle.Zero)) {
                digest = AuthenticationDigest.None;
            }
        }
        if (privacy != PrivacyProtocol.None) {
            privCred ??= new(null, "Enter privSecret:", userName);
            if (privCred.Equals(SafeMemoryHandle.Zero)) {
                privacy = PrivacyProtocol.None;
            }
        }
        if (digest is AuthenticationDigest.None && privacy is PrivacyProtocol.None) {
            flags = MsgFlags.NoAuthNoPrivRep;
        } else if (digest is AuthenticationDigest.None) {
            throw new SnmpArgumentException(
                SnmpExceptionCode.UnsupportedNoAuthPriv,
                "Cannot set PrivacyProtocol with AuthenticationDigest null or None.",
                nameof(digest)
            );
        } else if (privacy is PrivacyProtocol.None) {
            flags = MsgFlags.AuthNoPrivRep;
            authProvider = new(digest.Value);
        } else {
            flags = MsgFlags.AuthPrivRep;
            authProvider = new(digest.Value);
            privacyProvider = new(privacy.Value, authProvider);
        }
        IPAddress ipAddress = IPAddress.Parse(ip);
        Asn1Tag requestTag = new(TagClass.ContextSpecific, 0, true);
        int requestId = Random.Shared.Next();
        List<VarBinding> vbs = [];
        SnmpPdu pdu = new([], requestTag, requestId, 0, 0, vbs);
        ScopedPdu sPdu = new(
            new(string.Empty),
            new(contextName),
            pdu
        );
        return new(ipAddress, port, timeout, retries, flags) {
            ScopedPdu = sPdu,
            AuthCred = authCred,
            PrivCred = privCred,
            _msgUserName = new(userName),
            AuthAlgo = authProvider,
            PrivAlgo = privacyProvider,
            _contextName = new(contextName)
        };
    }
    public abstract ReadOnlySpan<byte> Construct(string[] oids, GeneralRequestType type, out long requestId);
    public void RefreshSocket() {
        try {
            _socket?.Dispose();
        } catch { }
        try {
            _socket = new(Target.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            _socket.Bind(new IPEndPoint(IPAddress.Any, 0));
            _socket.ReceiveTimeout = Timeout / 2;
            _socket.SendTimeout = Timeout / 2;
            _socket.Connect(_peerEndPoint);
        } catch { }
    }

    public void Dispose() {
        _socket?.Dispose();
        GC.SuppressFinalize(this);
    }
}
