using SapphTools.Asn1.DataTypes;

namespace SnmpSharpNet8.Request;

public interface ISnmpRequest {
    Integer Version { get; }
}
