namespace SapphTools.Snmp.Security;

public class PrivacyAES128 : PrivacyAES {

    public override string Name => "AES128";

    public PrivacyAES128(Authentication auth) : base(16, auth) { }
}
