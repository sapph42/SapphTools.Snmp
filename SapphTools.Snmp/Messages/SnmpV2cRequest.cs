using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using SapphTools.Snmp.Asn1;
using SapphTools.Snmp.Pdu;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

namespace SapphTools.Snmp.Messages;

public class SnmpV2cRequest : Request {
    private readonly Result _result = new() {
        Protocol = "SNMPv2c"
    };
    public override Integer Version => new([0x1]);
    public required OctetStringRaw Community { get; init; }
    internal SnmpV2cRequest(
            IPAddress target,
            int port,
            int timeout,
            int retries) :
        base(target, port, timeout, retries) { }

    public virtual Result Get(string[] oids) {
        _result.Action = "Get";
        CancellationTokenSource cts;
        cts = new(Timeout * _retries);
        ReadOnlySpan<byte> package = Construct(oids, GeneralRequestType.GetRequest, out long requestId);
        _ = Send(package, requestId, cts.Token);
        return _result;
    }
    public virtual Result GetNext(string[] oids) {
        _result.Action = "GetNext";
        CancellationTokenSource cts;
        cts = new(Timeout * _retries);
        ReadOnlySpan<byte> package = Construct(oids, GeneralRequestType.GetNextRequest, out long requestId);
        _ = Send(package, requestId, cts.Token);
        return _result;
    }
    public virtual Result GetBulk(string[] singleOids, string[] walkedOids, int maxRepetitions) {
        _result.Action = "GetBulk";
        CancellationTokenSource cts;
        cts = new(Timeout * _retries);
        ReadOnlySpan<byte> package = Construct(singleOids, walkedOids, maxRepetitions, out long requestId);
        _ = Send(package, requestId, cts.Token);
        return _result;
    }
    public virtual Result Walk(string ancestorOid) {
        _result.Action = "Walk";
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
        foreach (SnmpV2Asn1Structure leaf in tree) {
            foreach (VarBinding vb in leaf.Pdu.VarBindings) {
                _result.VarBindings.Add(vb);
    }
        }
        _result.Step = ResultStep.SnmpV2VarBindingsAttached;
        return _result;
    }
    protected virtual SnmpV2Asn1Structure? Send(ReadOnlySpan<byte> package, long requestId, CancellationToken token) {
        int sent;
        Span<byte> response = stackalloc byte[ushort.MaxValue];
        SnmpV2Asn1Structure? resp = null;
        int retry = 0;
        while (resp is null && !token.IsCancellationRequested && retry < _retries) {
            _result.ExceptionCode = SnmpExceptionCode.None;
            try {
                retry++;
                try {
                sent = _socket.Send(package);
                    _result.Step = ResultStep.SnmpV2RequestSent;
                } catch (SocketException) {
                    RefreshSocket();
                    sent = _socket.Send(package);
                    _result.Step = ResultStep.SnmpV2RequestSent;
                }
                if (sent != package.Length) {
                    _result.Exception = new SnmpNetworkException(msg: "Number of bytes sent by socket does not match request length.");
                    return null;
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
                } catch (SocketException se) when (se.ErrorCode == 10060) {
                    _result.ExceptionCode = SnmpExceptionCode.RequestTimedOut;
                }
                if (bytesRead == 0) {
                    _result.ExceptionCode = SnmpExceptionCode.NoDataReceived;
                    continue;
                }
                _result.Step = ResultStep.SnmpV2ResponseReceived;
                response = response[..bytesRead];
#if DEBUG
                Debug.WriteLine("");
                Debug.WriteLine("");
                Debug.WriteLine($"Request Package Recv            [{response.Length:D3}]: {string.Join(' ', response.ToArray().Select(b => Convert.ToHexString([b])))}");
#endif
                resp = (SnmpV2Asn1Structure)Parser.ParseSnmp(response);
                if (resp.Pdu.RequestId != requestId) {
                    _result.Step = ResultStep.SnmpV2ResponseParsed;
                    _result.ExceptionCode = SnmpExceptionCode.InvalidRequestId;
                    resp = null;
                    continue;
                }
                _result.ExceptionCode = SnmpExceptionCode.None;
                _result.Step = ResultStep.SnmpV2ResponseParsed;
                if (_result.Action == "Walk") {
                    _result.WalkedStructures ??= [];
                    _result.WalkedStructures.Add(resp);
                } else {
                    _result.ParsedStructure = resp;
                    foreach (VarBinding vb in resp.Pdu.VarBindings) {
                        _result.VarBindings.Add(vb);
                    }
                    _result.Step = ResultStep.SnmpV2VarBindingsAttached;
                }
            } catch (Exception ex) {
                _result.Exception = new SnmpDecodingException(msg: "Error parsing SNMP response.", sysException: ex);
            }
        }
        if (_result.Step < ResultStep.SnmpV2ResponseReceived) {
            _result.ExceptionCode = SnmpExceptionCode.NoDataReceived;
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
    public ReadOnlySpan<byte> Construct(string[] singleOids, string[] walkedOids, int maxRepetitions, out long requestId) {
        List<VarBinding> vbs = [];
        Asn1Null nullVal = new();
        foreach (string oid in singleOids) {
            ObjectIdentifier oidNode = new(new OidStruct(oid));
            VarBinding vb = new([], oidNode, nullVal);
            vbs.Add(vb);
        }
        foreach (string oid in walkedOids) {
            ObjectIdentifier oidNode = new(new OidStruct(oid));
            VarBinding vb = new([], oidNode, nullVal);
            vbs.Add(vb);
        }
        BulkRequestPdu pdu = BulkRequestPdu.Build(
            vbs,
            singleOids.Length,
            maxRepetitions
        );
        requestId = pdu.RequestId;
        return BuildRequest(pdu.Construct());
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