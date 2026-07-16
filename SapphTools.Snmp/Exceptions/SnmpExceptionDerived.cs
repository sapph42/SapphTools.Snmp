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
/// Exception of this type is thrown when SNMP version 3 packet containing authentication information
/// has failed authentication check.
/// </summary>
/// <remarks>
/// Standard constructor.
/// </remarks>
/// <param name="msg">Error message</param>
public class SnmpAuthenticationException(string msg) : SnmpException(msg) { }
/// <summary>
/// Exception thrown on failure to decode BER encoded information.
/// </summary>
/// <remarks>
/// standard constructor
/// </remarks>
/// <param name="msg">exception message</param>
public class SnmpDecodingException(string msg) : SnmpException(msg) { }
/// <summary>
/// Exception thrown when specific PDU type was expected and a different type was received.
/// </summary>
/// <remarks>
/// Constructor
/// </remarks>
/// <param name="msg">Error message</param>
public class SnmpInvalidPduTypeException(string msg) : SnmpException(msg) { }
/// <summary>
/// Exception thrown when invalid SNMP version was encountered in the packet
/// </summary>
/// <remarks>
/// Standard constructor
/// </remarks>
/// <param name="msg">Exception error message</param>
public class SnmpInvalidVersionException(string msg) : SnmpException(msg) { }