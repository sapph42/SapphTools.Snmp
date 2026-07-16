using SapphTools.Asn1.DataTypes;

namespace SapphTools.Snmp.Messages;

public class UsmSecurityParameters : Sequence {
    public OctetStringRaw MsgAuthoritativeEngineID => (OctetStringRaw)Items[0];
    public Integer MsgAuthoritativeEngineBoots => (Integer)Items[1];
    public Integer MsgAuthoritativeEngineTime => (Integer)Items[2];
    public OctetStringRaw MsgUserName => (OctetStringRaw)Items[3];
    public OctetStringRaw MsgAuthenticationParameters => (OctetStringRaw)Items[4];
    public OctetStringRaw MsgPrivacyParameters => (OctetStringRaw)Items[5];
    public UsmSecurityParameters(ReadOnlySpan<byte> raw) : base(raw) {
        if (Items.Count != 6) {
            throw new SnmpDecodingException(
                msg: $"UsmSecurityParameters expects a SEQUENCE of 6 items exactly. Actual: {Items.Count}");
        }
    }
    public UsmSecurityParameters(
            OctetStringRaw engineId,
            Integer boots,
            Integer time,
            OctetStringRaw userName,
            OctetStringRaw authParams,
            OctetStringRaw privParams) : base([]) {
        AddChild(engineId);
        AddChild(boots);
        AddChild(time);
        AddChild(userName);
        AddChild(authParams);
        AddChild(privParams);
    }
    public int GetAuthParamsPos(int lengthCount) {
        int pos = 0;
        pos += 1; //Usm Sequence type byte
        pos += lengthCount; //Usm Sequence length byte count
        pos += MsgAuthoritativeEngineID.Construct().Length;
        pos += MsgAuthoritativeEngineBoots.Construct().Length;
        pos += MsgAuthoritativeEngineTime.Construct().Length;
        pos += MsgUserName.Construct().Length;
        pos += 2; //MsgAuthenticationParameters TLV T+L bytes
        return pos;
    }
}
