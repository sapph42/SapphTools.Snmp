namespace SnmpSharpNet8.Security;

public class PrivacyAES192 : PrivacyAES {

    public override string Name => "AES192";

    public PrivacyAES192(Authentication auth) : base(24, auth) { }
}