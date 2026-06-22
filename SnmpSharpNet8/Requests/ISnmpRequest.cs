using SapphTools.Asn1.DataTypes;

namespace SnmpSharpNet8.Requests;

public interface ISnmpRequest {
    Integer Version { get; }
    ReadOnlySpan<byte> Construct();
}
