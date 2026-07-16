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
/// Standard constructor
/// </summary>
/// <param name="msg">Error message</param>
/// <param name="sysException">System exception that caused the error</param>
public abstract class SnmpExceptionWrapper(string msg, Exception? sysException = null) : SnmpException(msg) {
    protected Exception? _systemException = sysException;
    /// <summary>
    /// Return system exception that caused raising of this Exception error.
    /// </summary>
    public Exception? SystemException => _systemException;
}
