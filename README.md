
# Secure Cloud Data De-duplication with Efficient Re-Encryption

## Project Overview
This project demonstrates secure cloud storage using data deduplication, AES encryption, and efficient encryption key rotation.

## Technologies Used
- Java
- AES-GCM Encryption
- SHA-256 Hashing
- Java Cryptography Architecture (JCA)

## Key Features
- Detects duplicate content using SHA-256 hashing.
- Encrypts file content using AES-GCM.
- Uses separate encryption keys for individual files.
- Supports master-key rotation by re-encrypting stored data keys.
- Verifies data integrity after decryption.

## How It Works
1. User uploads file content.
2. SHA-256 generates a unique content hash.
3. Duplicate content is detected.
4. New content is encrypted using AES-GCM.
5. Encrypted content is stored locally.
6. Data keys are re-wrapped when the master key changes.

## Important Limitations
This is an educational prototype, not a production cloud storage service.

File metadata and the master key are stored in memory and are lost when the application exits. Persistent storage, authentication, access control, and production key management are not implemented.

## Source Code
See SecureCloudDeduplication.java.

