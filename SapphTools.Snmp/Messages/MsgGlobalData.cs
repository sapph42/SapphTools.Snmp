using SapphTools.Asn1.DataTypes;

namespace SnmpSharpNet8.Messages;

public class MsgGlobalData : Sequence {
    public Integer MsgId => (Integer)Items[0];
    public Integer MaxSize => (Integer)Items[1];
    public OctetStringRaw MsgFlags => (OctetStringRaw)Items[2];
    public Integer MsgSecurityModel => (Integer)Items[3];
    public MsgGlobalData(ReadOnlySpan<byte> raw) : base(raw) {
        if (Items.Count != 4) {
            throw new ArgumentException($"MsgGlobalData expects a SEQUENCE of 4 items exactly. Actual: {Items.Count}");
        }
    }
    public MsgGlobalData(Integer msgId, Integer maxSize, OctetStringRaw flags, Integer secModel) : base([]) {
        AddChild(msgId);
        AddChild(maxSize);
        AddChild(flags);
        AddChild(secModel);
    }
}
