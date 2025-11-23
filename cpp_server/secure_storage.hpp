#ifndef SECURE_STORAGE_HPP
#define SECURE_STORAGE_HPP

#include <string>
#include <vector>
#include <mutex>
#include <openssl/evp.h>
#include <openssl/rand.h>

class SecureStorage {
public:
    SecureStorage(const std::string& key_path);
    ~SecureStorage();

    // Encrypts plaintext using AES-256-GCM.
    // Returns: IV (12 bytes) + Ciphertext + Tag (16 bytes)
    std::string Encrypt(const std::string& plaintext);

    // Decrypts data. Expects: IV (12 bytes) + Ciphertext + Tag (16 bytes)
    std::string Decrypt(const std::string& ciphertext_blob);

    // Encrypts a file from src path to dst path using AES-256-GCM (Streaming).
    // Format: [IV 12b][Ciphertext...][Tag 16b]
    void EncryptFile(const std::string& src_path, const std::string& dst_path);

    // Decrypts a file from src path to dst path (Streaming).
    void DecryptFile(const std::string& src_path, const std::string& dst_path);

    // Generates a new random 256-bit key.
    static std::vector<unsigned char> GenerateKey();

    // Saves a key to disk securely.
    static void SaveKey(const std::string& path, const std::vector<unsigned char>& key);

    // Helper to re-key the instance
    void SetKey(const std::vector<unsigned char>& new_key);

    // Getter for the current key (needed by DBManager for rotation)
    const unsigned char* GetKey() const { return key_; }

private:
    std::string key_path_;
    mutable std::mutex mutex_;
    unsigned char key_[32]; // AES-256 key

    void LoadKey();
};

#endif // SECURE_STORAGE_HPP
