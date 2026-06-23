namespace SnmpSharpNet8.Messages;

[Flags]
public enum MsgFlags : byte {
    None       = 0x0,
    Auth       = 0x1,
    Priv       = 0x2,
    Reportable = 0x4,
}
