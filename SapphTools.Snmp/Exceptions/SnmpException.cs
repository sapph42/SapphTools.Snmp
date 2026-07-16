namespace SapphTools.Snmp.Exceptions;

[Serializable]
public class SnmpException(
        SnmpExceptionCode? errorCode = SnmpExceptionCode.None,
        string? msg = null,
        Exception? ex = null) :
    Exception(
        msg ?? ex?.ToString(),
        ex) {

    protected SnmpExceptionCode _errorCode = errorCode ?? SnmpExceptionCode.None;
    public SnmpExceptionCode ErrorCode {
        get => _errorCode;
        set => _errorCode = value;
    }
    public SnmpException(int errorCode, string? msg = null, Exception? ex = null) :
        this((SnmpExceptionCode)errorCode, msg, ex) { }
}
public class SnmpArgumentException(
        SnmpExceptionCode? errorCode = null,
        string? msg = null,
        string? paramName = null,
        Exception? sysException = null) : 
    SnmpException(errorCode, $"{msg} (Parameter '{paramName}')", sysException) {
}
public class SnmpAuthenticationException(
        SnmpExceptionCode errorCode = SnmpExceptionCode.AuthenticationFailed,
        string? msg = null,
        Exception? sysException = null) :
    SnmpException(errorCode, msg, sysException) { }
public class SnmpDecodingException(
        SnmpExceptionCode errorCode = SnmpExceptionCode.ParsingError,
        string? msg = null,
        Exception? sysException = null) :
    SnmpException(errorCode, msg, sysException) { }
public class SnmpInvalidVersionException(
        string? msg = null,
        Exception? sysException = null) :
    SnmpException(null, msg, sysException) { }
public class SnmpNetworkException(
        SnmpExceptionCode errorCode = SnmpExceptionCode.NetworkError,
        string? msg = null,
        Exception? sysException = null) :
    SnmpException(errorCode, msg, sysException) { }
public class SnmpPrivacyException(string? msg, Exception? sysException = null) :
    SnmpException(SnmpExceptionCode.InvalidPrivacyParameterLength, msg, sysException) { }