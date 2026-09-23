import java.security.MessageDigest;
import javax.crypto.Cipher;

public class weakcrypto_case_pos {
    public void hashers() throws Exception {
        MessageDigest a = MessageDigest.getInstance("md5");
        MessageDigest b = MessageDigest.getInstance("Sha1");
        MessageDigest c = MessageDigest.getInstance("sha-1");
        MessageDigest d = MessageDigest.getInstance("Md2");
    }
    public void ciphers() throws Exception {
        Cipher a = Cipher.getInstance("rc4");
        Cipher b = Cipher.getInstance("blowfish");
        Cipher c = Cipher.getInstance("des/CBC/PKCS5Padding");
        Cipher d = Cipher.getInstance("arcfour");
    }
    public void paddings() throws Exception {
        Cipher a = Cipher.getInstance("rsa/ECB/PKCS1Padding");
        Cipher b = Cipher.getInstance("rsa");
    }
}
