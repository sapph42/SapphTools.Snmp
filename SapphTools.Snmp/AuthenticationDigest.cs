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
namespace SapphTools.Snmp;
/// <summary>
/// Enumeration of available authentication digests
/// </summary>
public enum AuthenticationDigest {
    /// <summary>
    /// Authentication hash method none. Used when authentication is disabled.
    /// </summary>
    None = 0,
    /// <summary>
    /// Authentication protocol is HMAC-MD5.
    /// </summary>
    MD5,
    /// <summary>
    /// Authentication protocol is HMAC-SHA1.
    /// </summary>
    SHA1,
    /// <summary>
    /// Authentication protocol is HMAC-SHA256.
    /// </summary>
    SHA256,
    /// <summary>
    /// Authentication protocol is HMAC-SHA384.
    /// </summary>
    SHA384,
    /// <summary>
    /// Authentication protocol is HMAC-SHA512.
    /// </summary>
    SHA512
}
