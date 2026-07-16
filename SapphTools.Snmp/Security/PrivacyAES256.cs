namespace SnmpSharpNet8.Security;

public class PrivacyAES256 : PrivacyAES {

    public override string Name => "AES256";

    public PrivacyAES256(Authentication auth) : base(32, auth) { }
}