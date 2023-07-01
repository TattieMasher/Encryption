import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

public class Encro {
    private static final String AES_ALGORITHM = "AES";
    private static final String KEY_HASH_ALGORITHM = "SHA-256";
    private static final String CIPHER_TRANSFORMATION = "AES/ECB/PKCS5Padding";

    public static String generateKey() throws Exception {
        // Generate a random, secure key
        byte[] keyBytes = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(keyBytes);

        // Encode the key's bytes as a base64 string
        return Base64.getEncoder().encodeToString(keyBytes);
    }

    public static String encrypt(String input, String key) throws Exception {
        // Generate a secret key from the provided key string
        byte[] keyBytes = getKeyBytes(key);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, AES_ALGORITHM);

        // Create an AES cipher and initialize it with the secret key
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Encrypt the input string
        byte[] encryptedBytes = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));

        // Encode the encrypted bytes as a base64 string
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public static String decrypt(String input, String key) throws Exception {
        // Generate a secret key from the provided key string
        byte[] keyBytes = getKeyBytes(key);
        SecretKeySpec secretKey = new SecretKeySpec(keyBytes, AES_ALGORITHM);

        // Create an AES cipher and initialize it with the secret key
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        // Decode the base64 input string into bytes
        byte[] encryptedBytes = Base64.getDecoder().decode(input);

        // Decrypt the input bytes
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Return the decrypted string
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static byte[] getKeyBytes(String key) throws Exception {
        // Generate a secret key from the provided key string using SHA-256
        return MessageDigest.getInstance(KEY_HASH_ALGORITHM)
                .digest(key.getBytes(StandardCharsets.UTF_8));
    }
}