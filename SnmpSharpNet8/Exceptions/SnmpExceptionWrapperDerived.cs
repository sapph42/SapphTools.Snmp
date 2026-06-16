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
/// <summary>SNMP network exception</summary>
/// <remarks>
/// Exception thrown when network error was encountered. Network errors include host, network unreachable, connection refused, etc.
/// 
/// One network exception that is not covered by this exception is request timeout.
/// </remarks>
/// <summary>
/// Standard constructor
/// </summary>
/// <param name="msg">Error message</param>
/// <param name="sysException">System exception that caused the error</param>
public class SnmpNetworkException(string msg, Exception? sysException = null) : SnmpExceptionWrapper(msg, sysException) { }

/// <summary>
/// Privacy encryption or decryption exception
/// </summary>
/// <remarks>
/// Exception thrown when errors were encountered related to the privacy protocol encryption and decryption operations.
/// 
/// Use ParentException field to get the causing error details.
/// </remarks>
/// <summary>
/// Standard constructor
/// </summary>
/// <param name="msg">Error message</param>
/// <param name="sysException">System exception that caused the error</param>
public class SnmpPrivacyException(string msg, Exception? sysException = null) : SnmpExceptionWrapper(msg, sysException) { }