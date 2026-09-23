import java.security.MessageDigest;
import javax.crypto.Cipher;

public class weakcrypto_case_neg {
    public void hashers() throws Exception {
        MessageDigest a = MessageDigest.getInstance("sha-256");
        MessageDigest b = MessageDigest.getInstance("SHA3-256");
        MessageDigest c = MessageDigest.getInstance("md5sum-like-name");
    }
    public void ciphers() throws Exception {
        Cipher a = Cipher.getInstance("AES/GCM/NoPadding");
        Cipher b = Cipher.getInstance("ChaCha20-Poly1305");
    }
    public void paddings() throws Exception {
        Cipher a = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }
}
