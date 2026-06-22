using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using SnmpSharpNet8.Exceptions;
using SnmpSharpNet8.Requests;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;


namespace SnmpSharpNet8.Types; 
public abstract class Request : ISnmpRequest {
    protected Socket _socket;
    protected bool _socketDisposed = false;
    protected IPEndPoint _peerEndPoint;
    protected int _requestId = 0;
    protected int _retries = 1;
    public abstract Integer Version { get; }
    public abstract IRequestPdu Pdu { get; init; }
    public IPAddress Target { get; init; }

    protected Request(IPAddress target, int port, int timeout, int retries) { 
        Target = target;
        _peerEndPoint = new(target, port);
        _socket = new(target.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        IPEndPoint ipEndPoint = new(target, 0);
        _socket.Bind(ipEndPoint);
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

    public static SnmpV3Request CreateV3(string ip, AuthenticationDigest digest, PrivacyProtocol privacy, string userName, string contextEngineId = "") {
        IPAddress ipAddress = IPAddress.Parse(ip);
        OctetStringRaw securityName = new(userName);
        MsgFlags flags = MsgFlags.Reportable;
        //Requires import of Credential class from EAMC Tools installer codebase
        Credential authCred;
        Credential privCred;
        if (digest != AuthenticationDigest.None) {
            flags |= MsgFlags.Auth;
            authCred = new();
        }
        if (privacy != PrivacyProtocol.None) {
            flags |= MsgFlags.Priv;
            privCred = new();
        }
        //Logic incomplete
    }


    public abstract ReadOnlySpan<byte> Construct();
    public SnmpAsn1Structure? Send() {
        //needs type check and possible pre-send Discovery
        ReadOnlySpan<byte> requestBytes = Construct();
        int recv = 0;
        int retry = 0;
        Span<byte> inBuffer = stackalloc byte[64 * 1024];
        while (true) {
            try {
                _socket.SendTo(requestBytes, _peerEndPoint);
                recv = _socket.Receive(inBuffer);
            } catch (SocketException se) {
                recv = se.ErrorCode switch {
                    10040 => 0, // Packet too large
                    10060 => 0, // Timeout
                    _ => throw new SnmpException(SnmpExceptionCodes.NetworkError, se.SocketErrorCode.ToString(), se)
                };
            }
            if (recv > 0) {
                return Parser.ParseSnmp(inBuffer);
            } else {
                if (++retry > _retries) {
                    throw new SnmpException(SnmpExceptionCodes.RequestTimedOut, "Request has reached maximum retries.");
                }
            }
        }
    }
}
