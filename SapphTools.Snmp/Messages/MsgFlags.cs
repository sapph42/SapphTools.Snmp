namespace SnmpSharpNet8.Messages;

internal enum MsgFlags : byte {
    None            = 0x0,
    AuthNoPrivNoRep = 0x1,
    AuthPrivNoRep   = 0x3,
    NoAuthNoPrivRep = 0x4,
    AuthNoPrivRep   = 0x5,
    AuthPrivRep     = 0x7
}
