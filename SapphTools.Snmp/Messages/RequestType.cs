using System.Formats.Asn1;

namespace SapphTools.Snmp.Messages;

internal enum V1RequestType {
    GetRequest     = 0,
    GetNextRequest = 1,
    GetResponse    = 2,
    SetRequest     = 3,
    v1Trap         = 4
}
internal enum V2RequestType {
    GetRequest     = 0,
    GetNextRequest = 1,
    GetResponse    = 2,
    SetRequest     = 3,
    GetBulkRequest = 5,
    InformRequest  = 6,
    v2Trap         = 7,
    Report         = 8
}
public enum GeneralRequestType {
    GetRequest     = 0,
    GetNextRequest = 1,
    GetResponse    = 2,
    SetRequest     = 3,
    v1Trap         = 4,
    GetBulkRequest = 5,
    InformRequest  = 6,
    v2Trap         = 7,
    Report         = 8
}
internal static class RequestType {
    public static Asn1Tag ToTag(this V1RequestType type) => new(TagClass.ContextSpecific, (int)type, true);
    public static Asn1Tag ToTag(this V2RequestType type) => new(TagClass.ContextSpecific, (int)type, true);
    public static Asn1Tag ToTag(this GeneralRequestType type) => new(TagClass.ContextSpecific, (int)type, true);
}