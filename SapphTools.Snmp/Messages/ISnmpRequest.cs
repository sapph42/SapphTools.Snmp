using SapphTools.Asn1.DataTypes;

namespace SapphTools.Snmp.Messages;

public interface ISnmpRequest {
    Integer Version { get; }
    ReadOnlySpan<byte> Construct(string[] oids, out long requestId);
}
