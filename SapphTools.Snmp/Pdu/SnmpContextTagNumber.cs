namespace SapphTools.Snmp.Pdu;
public enum SnmpContextTagNumber {
    GetRequest     = 0,
    GetNextRequest = 1,
    GetResponse    = 2,
    SetRequest     = 3,
    GetBulkRequest = 5,
    InformRequest  = 6,
    SnmpV2Trap     = 7,
    Report         = 8
}
