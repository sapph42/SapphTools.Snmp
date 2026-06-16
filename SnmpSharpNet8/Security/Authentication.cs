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
namespace SnmpSharpNet8.Security;
/// <summary>Authentication helper class</summary>
/// <remarks>
/// Helper class to make dealing with multiple (if 2 qualifies as multiple) authentication protocols in a
/// transparent way.
/// 
/// Calling class keeps the authentication protocol selection (as defined on the agent) in an integer
/// variable that can have 3 values: <see cref="AuthenticationDigests.None"/>, <see cref="AuthenticationDigests.MD5"/>, or
/// <see cref="AuthenticationDigests.SHA1"/>. Using <see cref="Authentication.GetInstance"/>, calling method can
/// get authentication protocol implementation class instance cast as <see cref="IAuthenticationDigest"/> interface
/// and perform authentication operations (either authenticate outgoing packets to verify authentication of incoming packets)
/// without needing to further care about which authentication protocol is used.
/// 
/// Example of how to use this class:
/// <code>
/// IAuthenticationDigest authenticationImplementation = Authentication.GetInstance(AuthenticationDigests.MD5);
/// authenticationImplementation.authenticateIncomingMsg(...);
/// authenticationImplementation.authenticateOutgoingMsg(...);
/// </code>
/// </remarks>
public sealed class Authentication {
}
