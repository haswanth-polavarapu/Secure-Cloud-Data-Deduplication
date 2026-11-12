
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class SecureCloudDeduplication {

    private static final String STORAGE_DIR = "cloud-storage";
    private static final int NONCE_LENGTH = 12;

    private final SecureRandom random = new SecureRandom();
    private final Map<String, StoredFile> fileIndex = new HashMap<>();

    // Demonstration key: kept only in memory.
    private SecretKeySpec masterKey = generateKey();

    private static class StoredFile {
        byte[] contentNonce;
        byte[] wrappedKey;
        byte[] keyNonce;

        StoredFile(byte[] contentNonce, byte[] wrappedKey,
                   byte[] keyNonce) {
            this.contentNonce = contentNonce;
            this.wrappedKey = wrappedKey;
            this.keyNonce = keyNonce;
        }
    }

    private static class EncryptedData {
        byte[] ciphertext;
        byte[] nonce;

        EncryptedData(byte[] ciphertext, byte[] nonce) {
            this.ciphertext = ciphertext;
            this.nonce = nonce;
        }
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }

    private SecretKeySpec generateKey() {
        byte[] key = new byte[16];
        new SecureRandom().nextBytes(key);
        return new SecretKeySpec(key, "AES");
    }

    private EncryptedData encrypt(byte[] data, SecretKeySpec key)
            throws Exception {
        byte[] nonce = randomBytes(NONCE_LENGTH);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, nonce));

        return new EncryptedData(cipher.doFinal(data), nonce);
    }

    private byte[] decrypt(byte[] ciphertext, byte[] nonce,
                           SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key,
                new GCMParameterSpec(128, nonce));

        return cipher.doFinal(ciphertext);
    }

    private String calculateHash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);

        StringBuilder result = new StringBuilder();
        for (byte b : hash) {
            result.append(String.format("%02x", b & 0xff));
        }
        return result.toString();
    }

    public String upload(String content) throws Exception {
        byte[] data = content.getBytes(StandardCharsets.UTF_8);
        String fileId = calculateHash(data);

        // Check whether identical content already exists.
        if (fileIndex.containsKey(fileId)) {
            System.out.println("Duplicate detected. No new copy stored.");
            return fileId;
        }

        Files.createDirectories(Paths.get(STORAGE_DIR));

        // Generate a separate encryption key for this file.
        SecretKeySpec dataKey = generateKey();

        // Encrypt the file content.
        EncryptedData encryptedContent = encrypt(data, dataKey);

        // Encrypt (wrap) the data key using the master key.
        EncryptedData encryptedKey =
                encrypt(dataKey.getEncoded(), masterKey);

        // Store only encrypted content on disk.
        Path filePath = Paths.get(STORAGE_DIR, fileId + ".bin");
        Files.write(filePath, encryptedContent.ciphertext);

        // Keep the encryption metadata in memory.
        fileIndex.put(fileId, new StoredFile(
                encryptedContent.nonce,
                encryptedKey.ciphertext,
                encryptedKey.nonce
        ));

        System.out.println("File encrypted and stored: " + fileId);
        return fileId;
    }

    public String download(String fileId) throws Exception {
        StoredFile storedFile = fileIndex.get(fileId);

        if (storedFile == null) {
            throw new IllegalArgumentException(
                    "File not found in the current session.");
        }

        Path filePath = Paths.get(STORAGE_DIR, fileId + ".bin");
        byte[] encryptedContent = Files.readAllBytes(filePath);

        // Recover the data key using the master key.
        byte[] rawKey = decrypt(
                storedFile.wrappedKey,
                storedFile.keyNonce,
                masterKey
        );

        SecretKeySpec dataKey = new SecretKeySpec(rawKey, "AES");

        // Decrypt the stored content.
        byte[] originalData = decrypt(
                encryptedContent,
                storedFile.contentNonce,
                dataKey
        );

        // Verify the recovered content.
        if (!calculateHash(originalData).equals(fileId)) {
            throw new SecurityException("Data integrity check failed.");
        }

        return new String(originalData, StandardCharsets.UTF_8);
    }

    public void rotateMasterKey() throws Exception {
        SecretKeySpec newMasterKey = generateKey();

        // Re-wrap each data key. File content is not re-encrypted.
        for (StoredFile storedFile : fileIndex.values()) {
            byte[] rawKey = decrypt(
                    storedFile.wrappedKey,
                    storedFile.keyNonce,
                    masterKey
            );

            EncryptedData newWrappedKey = encrypt(
                    rawKey, newMasterKey
            );

            storedFile.wrappedKey = newWrappedKey.ciphertext;
            storedFile.keyNonce = newWrappedKey.nonce;
        }

        masterKey = newMasterKey;
        System.out.println("Master key rotated successfully.");
    }

    public static void main(String[] args) throws Exception {
        SecureCloudDeduplication system =
                new SecureCloudDeduplication();

        String firstId = system.upload(
                "This is a secure cloud storage demonstration."
        );

        // Same content: duplicate should not be stored again.
        system.upload(
                "This is a secure cloud storage demonstration."
        );

        System.out.println("Downloaded: " + system.download(firstId));

        system.rotateMasterKey();

        System.out.println("After key rotation: "
                + system.download(firstId));
    }
}
