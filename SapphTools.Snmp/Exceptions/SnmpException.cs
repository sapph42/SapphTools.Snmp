namespace SapphTools.Snmp.Exceptions;

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
