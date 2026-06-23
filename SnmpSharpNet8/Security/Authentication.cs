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
using SnmpSharpNet8.Exceptions;
using SnmpSharpNet8.Types;
using System.Security.Cryptography;

namespace SnmpSharpNet8.Security;
/// <summary>
/// Authentication digest interface. Interface defines authentication methods
/// for incoming and outgoing requests.
/// </summary>
public class Authentication {
    private readonly int authenticationLength;
    private readonly HashAlgorithmName _hashName;

    public int AuthHeaderLength { get; }
    public string Name { get; }

    public Authentication(AuthenticationDigest algo) {
        (_hashName, AuthHeaderLength) = algo switch {
            AuthenticationDigest.MD5 => (HashAlgorithmName.MD5, 12),
            AuthenticationDigest.SHA1 => (HashAlgorithmName.SHA1, 12),
            AuthenticationDigest.SHA256 => (HashAlgorithmName.SHA256, 24),
            AuthenticationDigest.SHA384 => (HashAlgorithmName.SHA384, 32),
            AuthenticationDigest.SHA512 => (HashAlgorithmName.SHA512, 48),
            _ => throw new ArgumentOutOfRangeException(nameof(algo))
        };
        Name = $"HMAC-{_hashName.Name}";
    }
    public byte[] Authenticate(byte[] password, byte[] engineId, byte[] wholeMessage) {
        byte[] key = PasswordToKey(password, engineId);
        using IncrementalHash hmac = IncrementalHash.CreateHMAC(_hashName, key);
        hmac.AppendData(wholeMessage);
        byte[] full = hmac.GetHashAndReset();
        return full[..AuthHeaderLength];
    }

    public bool AuthenticateIncomingMsg(
            byte[] authenticationSecret,
            byte[] engineId,
            byte[] authenticationParameters,   // the digest extracted from the received message
            byte[] wholeMessage) {              // MUST already have the auth field zeroed
        byte[] authKey = PasswordToKey(authenticationSecret, engineId);

        using var hmac = IncrementalHash.CreateHMAC(_hashName, authKey);
        hmac.AppendData(wholeMessage);
        byte[] computed = hmac.GetHashAndReset();

        return CryptographicOperations.FixedTimeEquals(
            computed.AsSpan(0, AuthHeaderLength),
            authenticationParameters.AsSpan(0, AuthHeaderLength));
    }

    public byte[] PasswordToKey(byte[] password, byte[] engineId) {
        using var inc = IncrementalHash.CreateHash(_hashName);
        byte[] buf = new byte[64];
        int produced = 0;
        while (produced < 1048576) {
            for (int i = 0; i < 64; i++)
                buf[i] = password[(produced + i) % password.Length];
            inc.AppendData(buf);
            produced += 64;
        }
        byte[] ku = inc.GetHashAndReset();
        inc.AppendData(ku);
        inc.AppendData(engineId);
        inc.AppendData(ku);
        return inc.GetHashAndReset();           // localized key
    }
}
