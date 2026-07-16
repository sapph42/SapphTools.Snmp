using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using SapphTools.Snmp.Pdu;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;

namespace SapphTools.Snmp.Messages;

public class SnmpV2cRequest : Request {
    public override Integer Version => new([0x1]);
    public required OctetStringRaw Community { get; init; }
    internal SnmpV2cRequest(IPAddress target, int port, int timeout, int retries) : base(target, port, timeout, retries) { 
    }

    public SnmpV2Asn1Structure? Get(string[] oids) {
        CancellationTokenSource cts;
        cts = new(Timeout * _retries);
        ReadOnlySpan<byte> package = Construct(oids, out long messageId);
        return Send(package, messageId, cts.Token);
    }
    private SnmpV2Asn1Structure? Send(ReadOnlySpan<byte> package, long messageId, CancellationToken token) {
        int sent;
        Span<byte> response = stackalloc byte[ushort.MaxValue];
        SnmpV2Asn1Structure? resp = null;
        int retry = 0;
        while (resp is null && !token.IsCancellationRequested && retry < _retries) {
            try {
                retry++;
                sent = _socket.Send(package);
                if (sent != package.Length) {
                    throw new SnmpNetworkException(msg: "Number of bytes sent by socket does not match request length.");
                }
                int bytesRead = 0;
                try {
                    bytesRead = _socket.Receive(response);
                } catch (SocketException se) when (se.ErrorCode == 10060) { }
                if (bytesRead == 0) {
                    continue;
                }
                response = response[..bytesRead];
                resp = (SnmpV2Asn1Structure)Parser.ParseSnmp(response);
                if (resp.Pdu.RequestId != _requestId) {
                    resp = null;
                    continue;
                }
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
    public override ReadOnlySpan<byte> Construct(string[] oids, out long requestId) {
        List<VarBinding> vbs = [];
        Asn1Null nullVal = new();
        foreach (string oid in oids) {
            ObjectIdentifier oidNode = new(new OidStruct(oid));
            VarBinding vb = new([], oidNode, nullVal);
            vbs.Add(vb);
        }
        SnmpPdu pdu = SnmpPdu.Build(
            new Asn1Tag(TagClass.ContextSpecific, 0, true),
            vbs
        );
        requestId = pdu.RequestId;
        return BuildRequest(pdu.Construct());
    }
    private byte[] BuildRequest(ReadOnlySpan<byte> pdu) {
        return [
            0x30,
            ..IDataType.EncodeLength(BuildPayload(pdu, out byte[] payload)),
            ..payload
        ];
    }
    private int BuildPayload(ReadOnlySpan<byte> pdu, out byte[] payload) {
        payload = [
            ..Version.Construct(),
            ..Community.Construct(),
            ..pdu
        ];
        return payload.Length;
    }
}
public class SnmpV2Request : SnmpV2cRequest {
    internal SnmpV2Request(IPAddress target, int port, int timeout, int retries) : base(target, port, timeout, retries) { }
}