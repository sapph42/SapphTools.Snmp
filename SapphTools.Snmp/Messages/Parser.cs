using SapphTools.Asn1;
using SapphTools.Asn1.DataTypes;
using SapphTools.Snmp.Asn1;
using SapphTools.Snmp.Pdu;
using SapphTools.Snmp.Security;
using System.Formats.Asn1;
using System.Security.Cryptography;
using static SapphTools.Asn1.Asn1;
using static SapphTools.Asn1.Parser;

namespace SapphTools.Snmp.Messages;

public static class Parser {
    public static IAsn1Structure ParseSnmp(Span<byte> rawSpan, Authentication? auth = null, Privacy? priv = null, Credential? authCred = null, Credential? privCred = null) =>
        ParseSnmp(raw: [.. rawSpan], auth, priv, authCred, privCred);
    public static IAsn1Structure ParseSnmp(byte[] raw, Authentication? auth = null, Privacy? priv = null, Credential? authCred = null, Credential? privCred = null) {
        ReadOnlySpan<byte> span = raw;

        Asn1Tag msgTag = ReadTag(span);
        Expect(msgTag, TagClass.Universal, (int)UniversalTagNumber.Sequence, "SNMP message");
        IDataType.GetLength(span, out int msgLen, out int msgStart);
        ReadOnlySpan<byte> msgTlv = span[..(msgStart + msgLen)];

        int pos = msgStart;
        long version = ReadInteger(span, ref pos, "version");

        if (version == 1) {
            SnmpPdu pdu = ParseSnmpv2(span, pos, out string community);
            return new SnmpV2Asn1Structure {
                Raw = msgTlv,
                Version = version,
                Community = community,
                Pdu = pdu
            };
        } else {
            return version == 3
                ? (IAsn1Structure)ParseSnmpv3(span, pos, auth, priv, authCred, privCred)
                : throw new NotSupportedException($"Only versions 1 (v2c) and 3 (v3) are supported. Actual version parsed: {version}");
        }
    }
    private static SnmpPdu ParseSnmpv2(ReadOnlySpan<byte> body, int pos, out string community) {
        community = ReadOctetString(body, ref pos, "community");

        ReadOnlySpan<byte> pduRest = body[pos..];
        Asn1Tag pduTag = ReadTag(pduRest);
        if (pduTag.TagClass != TagClass.ContextSpecific || !pduTag.IsConstructed) {
            throw new SnmpDecodingException(
                msg: $"Expected context-constructed PDU tag, got {Describe(pduTag)} " +
                $"({GetBlock(pduRest)})");
        }

        IDataType.GetLength(pduRest, out int pduLen, out int pduStart);
        ReadOnlySpan<byte> pduBody = pduRest.Slice(pduStart, pduLen);
        ReadOnlySpan<byte> pduTlv = pduRest[..(pduStart + pduLen)];

        return ParsePdu(pduTlv, pduTag, pduBody);
    }
    private static SnmpV3Asn1Structure ParseSnmpv3(ReadOnlySpan<byte> body, int pos, Authentication? auth, Privacy? priv, Credential? authCred, Credential? privCred) {
        Span<byte> authCheckBody = new byte[body.Length];
        body.CopyTo(authCheckBody);
        Asn1Tag headerDataTag = ReadTag(body[pos..]);
        Expect(headerDataTag, TagClass.Universal, (int)UniversalTagNumber.Sequence, "msgGlobalData");
        IDataType.GetLength(body[pos..], out int headerDataLength, out int headerDataBodyIndex);
        pos += headerDataBodyIndex;
        MsgGlobalData msgGlobalData = new(body.Slice(pos, headerDataLength));
        pos += headerDataLength;

        Asn1Tag paramEnvTag = ReadTag(body[pos..]);
        Expect(paramEnvTag, TagClass.Universal, (int)UniversalTagNumber.OctetString, "msgSecurityParameters");
        IDataType.GetLength(body[pos..], out int paramEnvLength, out int paramEnvIndex);
        pos += paramEnvIndex;
        int usmLengthCount = paramEnvIndex - 1;
        int usmIndex = pos;
        OctetStringRaw paramEnv = new(body.Slice(pos, paramEnvLength));
        pos += paramEnvLength;

        Asn1Tag secParamTag = ReadTag(paramEnv.Raw);
        Expect(secParamTag, TagClass.Universal, (int)UniversalTagNumber.Sequence, "UsmSecurityParameters");
        IDataType.GetLength(paramEnv.Raw, out int _, out int secParamIndex);
        UsmSecurityParameters secParams = new(paramEnv.Raw[secParamIndex..]);
        ReadOnlySpan<byte> authParams = secParams.MsgAuthenticationParameters.Raw;

        Sequence scopedPduSeq;
        OctetStringRaw? cryptEnv = null;
        ReadOnlySpan<byte> authMessage;
        Asn1Tag scopedPduTag = ReadTag(body[pos..]);
        if (auth is not null && authCred is not null && secParams.MsgAuthenticationParameters.Raw.Length > 0) {
            int authPos = usmIndex + secParams.GetAuthParamsPos(usmLengthCount);
            Span<byte> authCheck = new byte[authParams.Length];
            authCheckBody.Slice(authPos, authParams.Length).CopyTo(authCheck);
            authCheckBody.Slice(authPos, authParams.Length).Clear();
            if (!authCheck.SequenceEqual(authParams)) {
                throw new SnmpAuthenticationException(msg: "Calculated msgAuthenticatedParameters position failed");
            }
            if (!authCred.Authenticate(authParams, authCheckBody, auth)) {
                throw new SnmpPrivacyException(null, new AuthenticationTagMismatchException());
            }
        }
        if (priv is not null &&
                privCred is not null &&
                scopedPduTag.HasSameClassAndValue(OctetStringRaw.Tag) &&
                 secParams.MsgPrivacyParameters.Raw.Length > 0) {
            Expect(scopedPduTag, TagClass.Universal, (int)UniversalTagNumber.OctetString, "Encrypted ScopedPDU Envelope");
            IDataType.GetLength(body[pos..], out int cryptEnvLength, out int cryptEnvIndex);
            pos += cryptEnvIndex;
            authMessage = body.Slice(pos, cryptEnvLength);
            cryptEnv = new(authMessage);
            ReadOnlySpan<byte> decryptedBytes = privCred.Decrypt(
                [..authMessage],
                (int)secParams.MsgAuthoritativeEngineBoots.Value,
                (int)secParams.MsgAuthoritativeEngineTime.Value,
                priv,
                [.. secParams.MsgPrivacyParameters.Raw]);

            int scopedPos = 0;
            Asn1Tag scopedPduPayloadTag = ReadTag(decryptedBytes[scopedPos..]);
            Expect(scopedPduPayloadTag, TagClass.Universal, (int)UniversalTagNumber.Sequence, "scopedPdu");
            IDataType.GetLength(decryptedBytes[scopedPos..], out int scopedPduLength, out int scopedPduIndex);
            scopedPos += scopedPduIndex;
            scopedPduSeq = new(decryptedBytes.Slice(scopedPos, scopedPduLength));
        } else {
            Expect(scopedPduTag, TagClass.Universal, (int)UniversalTagNumber.Sequence, "scopedPdu");
            IDataType.GetLength(body[pos..], out int scopedPduLength, out int scopedPduIndex);
            pos += scopedPduIndex;
            authMessage = body.Slice(pos, scopedPduLength);
            scopedPduSeq = new(authMessage);
        }
        if (!ScopedPdu.TryConvert(scopedPduSeq, out ScopedPdu? scopedPdu)) {
            throw new SnmpDecodingException(msg: "Invalid ScopedPdu structure");
        }
        return new() {
            MsgGlobalData = msgGlobalData,
            MsgSecurityParametersEnvelope = paramEnv,
            UsmSecurityParameters = secParams,
            ScopedPduEnvelope = cryptEnv,
            ScopedPdu = scopedPdu
        };
    }

    private static SnmpPdu ParsePdu(ReadOnlySpan<byte> pduTlv, Asn1Tag pduTag,
                                    ReadOnlySpan<byte> pduBody) {
        int pos = 0;
        long requestId = ReadInteger(pduBody, ref pos, "request-id");
        int errorStat = (int)ReadInteger(pduBody, ref pos, "error-status");
        int errorIndex = (int)ReadInteger(pduBody, ref pos, "error-index");

        ReadOnlySpan<byte> vbListRest = pduBody[pos..];
        Asn1Tag vbListTag = ReadTag(vbListRest);
        Expect(vbListTag, TagClass.Universal, (int)UniversalTagNumber.Sequence, "VarBindList");
        IDataType.GetLength(vbListRest, out int vbListLen, out int vbListStart);
        ReadOnlySpan<byte> vbList = vbListRest.Slice(vbListStart, vbListLen);

        List<VarBinding> bindings = [];
        int vbPos = 0;
        while (vbPos < vbList.Length) {
            ReadOnlySpan<byte> vbRest = vbList[vbPos..];
            IDataType.GetLength(vbRest, out int vbLen, out int vbIdx);
            int vbConsumed = vbIdx + vbLen;
            bindings.Add(ParseVarBind(vbRest[..vbConsumed]));
            vbPos += vbConsumed;
        }
        return new SnmpPdu(pduTlv, pduTag, requestId, errorStat, errorIndex, bindings);
    }
    private static VarBinding ParseVarBind(ReadOnlySpan<byte> vbTlv) {
        Asn1Tag seqTag = ReadTag(vbTlv);
        Expect(seqTag, TagClass.Universal, (int)UniversalTagNumber.Sequence, "VarBind");
        IDataType.GetLength(vbTlv, out int len, out int start);
        ReadOnlySpan<byte> content = vbTlv.Slice(start, len);

        int pos = 0;

        ReadOnlySpan<byte> oidRest = content[pos..];
        Asn1Tag oidTag = ReadTag(oidRest);
        Expect(oidTag, TagClass.Universal, (int)UniversalTagNumber.ObjectIdentifier, "VarBind name");
        IDataType.GetLength(oidRest, out int oidLen, out int oidStart);
        ObjectIdentifier name = new(oidRest.Slice(oidStart, oidLen));   // content-only ctor
        pos += oidStart + oidLen;

        ReadOnlySpan<byte> valRest = content[pos..];
        Asn1Tag valTag = ReadTag(valRest);
        IDataType.GetLength(valRest, out int valLen, out int valStart);
        byte[] valPayload = [.. valRest.Slice(valStart, valLen)];
        Asn1Tag key = new(valTag.TagClass, valTag.TagValue, isConstructed: false);
        IDataType bound = DataTypeRegistry.Factories.TryGetValue(key, out Func<byte[], IDataType>? factory)
            ? factory(valPayload)
            : new Unknown(valRest.Slice(valStart, valLen));

        return new VarBinding(vbTlv, name, bound);
    }
}
/*SAMPLE ERROR RESPONSE - USE TO BUILD ERROR HANDLING
 * 
 * 13:47:43:025	Discovery Package Sent: 30 42 02 01 03 30 11 02 04 03 C6 2C 7D 02 03 00 FF E3 04 01 04 02 01 03 04 10 30 0E 04 00 02 01 00 02 01 00 04 00 04 00 04 00 30 18 04 00 04 00 A0 12 02 08 3E 49 7F BD F4 EE ED 4F 02 01 00 02 01 00 30 00
13:47:43:025	Discovery Package Recv: 30 64 02 01 03 30 10 02 04 03 C6 2C 7D 02 02 05 C0 04 01 00 02 01 03 04 1D 30 1B 04 0B 80 00 1F 88 03 BC 0F F3 F1 94 D6 02 01 16 02 03 36 42 0E 04 00 04 00 04 00 30 2E 04 0B 80 00 1F 88 03 BC 0F F3 F1 94 D6 04 00 A8 1D 02 01 00 02 01 00 02 01 00 30 12 30 10 06 0A 2B 06 01 06 03 0F 01 01 04 00 41 02 00 C7
13:47:43:025	Request   Package Sent: 30 81 82 02 01 03 30 11 02 04 6D 0B 33 F7 02 03 00 FF E3 04 01 07 02 01 03 04 3B 30 39 04 0B 80 00 1F 88 03 BC 0F F3 F1 94 D6 02 01 16 02 03 36 42 0E 04 0A 45 69 73 65 6E 68 6F 77 65 72 04 0C 00 00 00 00 00 00 00 00 00 00 00 00 04 08 00 00 00 00 09 A9 EC 59 04 2D 99 99 FA D3 BD 00 A6 89 93 7D CC 4B E4 94 99 91 78 E4 17 0F 69 A9 93 F1 F6 34 9E 50 86 9C 6B A2 7D DA 80 40 95 91 5A 55 47 E0 7B 30 B2
13:47:43:328	Request   Package Recv: 30 6D 02 01 03 30 10 02 04 6D 0B 33 F7 02 02 05 C0 04 01 00 02 01 03 04 27 30 25 04 0B 80 00 1F 88 03 BC 0F F3 F1 94 D6 02 01 16 02 03 36 42 0E 04 0A 45 69 73 65 6E 68 6F 77 65 72 04 00 04 00 30 2D 04 0B 80 00 1F 88 03 BC 0F F3 F1 94 D6 04 00 A8 1C 02 01 00 02 01 00 02 01 00 30 11 30 0F 06 0A 2B 06 01 06 03 0F 01 01 05 00 41 01 03
*/
