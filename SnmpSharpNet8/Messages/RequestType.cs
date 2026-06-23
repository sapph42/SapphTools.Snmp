using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SnmpSharpNet8.Messages; 

public enum V1RequestType {
    GetRequest     = 0,
    GetNextRequest = 1,
    GetResponse    = 2,
    SetRequest     = 3,
    v1Trap         = 4
}
public enum V2RequestType {
    GetRequest     = 0,
    GetNextRequest = 1,
    GetResponse    = 2,
    SetRequest     = 3,
    GetBulkRequest = 5,
    InformRequest  = 6,
    v2Trap         = 7,
    Report         = 8
}
