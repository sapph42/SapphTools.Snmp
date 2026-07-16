// This file is part of SNMP#NET8.
// 
// SNMP#NET8 is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// SNMP#NET8 is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with SNMP#NET8.  If not, see <http://www.gnu.org/licenses/>.
// 
namespace SnmpSharpNet8.Exceptions;
/// <summary>
/// SNMP generic exception. Thrown every time SNMP specific error is encountered.
/// </summary>
[Serializable]
public class SnmpException : Exception {
    /// <summary>
    /// Error code. Provides a finer grained information about why the exception happened. This can be useful to
    /// the process handling the error to determine how critical the error that occured is and what followup actions
    /// to take.
    /// </summary>
    protected SnmpExceptionCodes _errorCode;
    /// <summary>
    /// Get/Set error code associated with the exception
    /// </summary>
    public SnmpExceptionCodes ErrorCode {
        get { return _errorCode; }
        set { _errorCode = value; }
    }

    /// <summary>
    /// Constructor.
    /// </summary>
    public SnmpException() : base() { }
    /// <summary>
    /// Standard constructor
    /// </summary>
    /// <param name="msg">SNMP Exception message</param>
    public SnmpException(string msg) : base(msg) { }
    public SnmpException(string msg, Exception ex) : base(msg, ex) { }
    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="errorCode">Error code associated with the exception</param>
    /// <param name="msg">Error message</param>
    public SnmpException(SnmpExceptionCodes errorCode, string msg) : base(msg) {
        _errorCode = errorCode;
    }
    public SnmpException(SnmpExceptionCodes errorCode, string msg, Exception ex) : base(msg, ex) {
        _errorCode = errorCode;
    }
    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="errorCode">Error code associated with the exception</param>
    /// <param name="msg">Error message</param>
    public SnmpException(int errorCode, string msg) : base(msg) {
        _errorCode = (SnmpExceptionCodes)errorCode;
    }
    public SnmpException(int errorCode, string msg, Exception ex) : base(msg, ex) {
        _errorCode = (SnmpExceptionCodes)errorCode;
    }
}
