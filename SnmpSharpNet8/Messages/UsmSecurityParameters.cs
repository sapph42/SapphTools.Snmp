using SapphTools.Asn1.DataTypes;

namespace SnmpSharpNet8.Messages; 
public class UsmSecurityParameters : Sequence {
    public OctetStringRaw MsgAuthoritativeEngineID => (OctetStringRaw)Items[0];
    public Integer MsgAuthoritativeEngineBoots => (Integer)Items[1];
    public Integer MsgAuthoritativeEngineTime => (Integer)Items[2];
    public OctetStringRaw MsgUserName => (OctetStringRaw)Items[3];
    public OctetStringRaw MsgAuthenticationParameters => (OctetStringRaw)Items[4];
    public OctetStringRaw MsgPrivacyParameters => (OctetStringRaw)Items[5];
    public UsmSecurityParameters(ReadOnlySpan<byte> raw) : base(raw) {
        if (Items.Count != 6) {
            throw new ArgumentException($"UsmSecurityParameters expects a SEQUENCE of 6 items exactly. Actual: {Items.Count}");
        }
    }
}
