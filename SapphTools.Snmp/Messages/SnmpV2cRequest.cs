using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using SapphTools.Snmp.Asn1;
using SapphTools.Snmp.Pdu;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace SapphTools.Snmp.Messages;

public class SnmpV2cRequest : Request {
    public override Integer Version => new([0x1]);
    public required OctetStringRaw Community { get; init; }
    internal SnmpV2cRequest(
            IPAddress target,
            int port,
            int timeout,
            int retries) :
        base(target, port, timeout, retries) { }

    public virtual SnmpV2Asn1Structure? Get(string[] oids) {
        CancellationTokenSource cts;
        cts = new(Timeout * _retries);
        ReadOnlySpan<byte> package = Construct(oids, GeneralRequestType.GetRequest, out long requestId);
        return Send(package, requestId, cts.Token);
    }
    public virtual SnmpV2Asn1Structure? GetNext(string[] oids) {
        CancellationTokenSource cts;
        cts = new(Timeout * _retries);
        ReadOnlySpan<byte> package = Construct(oids, GeneralRequestType.GetNextRequest, out long requestId);
        return Send(package, requestId, cts.Token);
    }
    public virtual List<SnmpV2Asn1Structure> Walk(string ancestorOid) {
        List<SnmpV2Asn1Structure> tree = [];
        CancellationTokenSource cts;
        string oid = ancestorOid;
        SnmpV2Asn1Structure? resp;
        do {
            cts = new(Timeout * _retries);
            ReadOnlySpan<byte> package = Construct([oid], GeneralRequestType.GetNextRequest, out long requestId);
            resp = Send(package, requestId, cts.Token);
            if (resp is not null &&
                    resp.Pdu.ErrorStatus == 0 &&
                    resp.Pdu.VarBindings.Any() &&
                    resp.Pdu.VarBindings[0] is VarBinding vb &&
                    vb.Bound is not (EndOfMibView or NoSuchObject or NoSuchInstance) &&
                    vb.Name.Value.Value is string oidStr &&
                    oidStr.StartsWith(ancestorOid + '.') &&
                    !oidStr.Equals(oid, StringComparison.OrdinalIgnoreCase)
            ) {
                oid = oidStr;
                tree.Add(resp);
            } else {
                resp = null;
            }
        } while (resp is not null);
        return tree;
    }
    protected virtual SnmpV2Asn1Structure? Send(ReadOnlySpan<byte> package, long requestId, CancellationToken token) {
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
#if DEBUG
                Debug.WriteLine("");
                Debug.WriteLine("");
                Debug.WriteLine($"Request Package Sent            [{package.Length:D3}]: {string.Join(' ', package.ToArray().Select(b => Convert.ToHexString([b])))}");
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
#if DEBUG
                Debug.WriteLine("");
                Debug.WriteLine("");
                Debug.WriteLine($"Request Package Recv            [{response.Length:D3}]: {string.Join(' ', response.ToArray().Select(b => Convert.ToHexString([b])))}");
#endif
                resp = (SnmpV2Asn1Structure)Parser.ParseSnmp(response);
                if (resp.Pdu.RequestId != requestId) {
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
    public override ReadOnlySpan<byte> Construct(string[] oids, GeneralRequestType type, out long requestId) {
        List<VarBinding> vbs = [];
        Asn1Null nullVal = new();
        foreach (string oid in oids) {
            ObjectIdentifier oidNode = new(new OidStruct(oid));
            VarBinding vb = new([], oidNode, nullVal);
            vbs.Add(vb);
        }
        SnmpPdu pdu = SnmpPdu.Build(
            type.ToTag(),
            vbs
        );
        requestId = pdu.RequestId;
        return BuildRequest(pdu.Construct());
    }
    protected byte[] BuildRequest(ReadOnlySpan<byte> pdu) {
        return [
            0x30,
            ..IDataType.EncodeLength(BuildPayload(pdu, out byte[] payload)),
            ..payload
        ];
    }
    protected int BuildPayload(ReadOnlySpan<byte> pdu, out byte[] payload) {
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