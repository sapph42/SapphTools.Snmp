using SapphTools.Asn1.DataTypes;

namespace SnmpSharpNet8.Messages;

public interface ISnmpRequest {
    Integer Version { get; }
    ReadOnlySpan<byte> Construct(string[] oids, out long requestId);
}
