namespace SapphTools.Snmp.Exceptions;
public class SnmpErrorStatusException : SnmpException {
    protected int _errorIndex;
    public SnmpExceptionCode ErrorStatus {
        get => _errorCode;
        set => _errorCode = value;
    }
    public int ErrorIndex {
        get => _errorIndex;
        set => _errorIndex = value;
    }
    public override string Message =>
        string.Format("{0}> ErrorStatus {1} ErrorIndex {2}", base.Message, _errorCode, _errorIndex);

    public SnmpErrorStatusException(
            int index,
            SnmpExceptionCode? errorCode = SnmpExceptionCode.None,
            string? msg = null,
            Exception? ex = null) :
    base(errorCode, msg, ex) {
        _errorIndex = index;
    }
    public SnmpErrorStatusException(
            int index,
            int errorCode,
            string? msg = null,
            Exception? ex = null) :
    this(index, (SnmpExceptionCode)errorCode, msg, ex) { }
}