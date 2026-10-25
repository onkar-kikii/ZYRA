import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class AuthUtil {
    private static final SecureRandom RANDOM = new SecureRandom();

    public static String hashPassword(String password) throws Exception {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);

        byte[] hash = derive(password, salt, 210000);

        return "pbkdf2-sha1:210000:"
                + Base64.getEncoder().encodeToString(salt)
                + ":"
                + Base64.getEncoder().encodeToString(hash);
    }

    public static boolean verifyPassword(
            String password, String storedHash) throws Exception {

        String[] parts = storedHash.split(":");

        if (parts.length != 4 || !parts[0].equals("pbkdf2-sha1")) {
            return false;
        }

        int iterations = Integer.parseInt(parts[1]);

        if (iterations < 100000 || iterations > 1000000) {
            return false;
        }

        byte[] salt = Base64.getDecoder().decode(parts[2]);
        byte[] expected = Base64.getDecoder().decode(parts[3]);
        byte[] actual = derive(password, salt, iterations);

        return MessageDigest.isEqual(expected, actual);
    }

    private static byte[] derive(
            String password, byte[] salt, int iterations) throws Exception {

        PBEKeySpec spec = new PBEKeySpec(
                password.toCharArray(), salt, iterations, 256);

        try {
            return SecretKeyFactory
                    .getInstance("PBKDF2WithHmacSHA1")
                    .generateSecret(spec)
                    .getEncoded();
        } finally {
            spec.clearPassword();
        }
    }
}
