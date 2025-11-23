#include "secure_storage.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <cstring>
#include <filesystem>

// AES-256-GCM Constants
constexpr int KEY_SIZE = 32;
constexpr int IV_SIZE = 12;
constexpr int TAG_SIZE = 16;

SecureStorage::SecureStorage(const std::string& key_path)
    : key_path_(key_path) {
    LoadKey();
}

SecureStorage::~SecureStorage() {
    // Securely zero out the key in memory
    OPENSSL_cleanse(key_, sizeof(key_));
}

void SecureStorage::LoadKey() {
    std::ifstream key_file(key_path_, std::ios::binary);
    if (key_file.is_open()) {
        key_file.read(reinterpret_cast<char*>(key_), KEY_SIZE);
        if (key_file.gcount() != KEY_SIZE) {
            throw std::runtime_error("Corrupted key file.");
        }
    } else {
        // Generate new key
        std::cout << "Generating new encryption key..." << std::endl;
        if (RAND_bytes(key_, KEY_SIZE) != 1) {
            throw std::runtime_error("Failed to generate random key.");
        }
        // Save key
        std::ofstream out_file(key_path_, std::ios::binary);
        out_file.write(reinterpret_cast<const char*>(key_), KEY_SIZE);
        // Set restricted permissions (simplistic approach for this env)
        std::filesystem::permissions(key_path_,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace);
    }
}

std::string SecureStorage::Encrypt(const std::string& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to generate IV");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptInit failed");
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key_, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptInit key/iv failed");
    }

    int outlen;
    std::string ciphertext(plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_gcm()), '\0');

    if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &outlen,
                          reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptUpdate failed");
    }
    int final_len = outlen;

    if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[final_len]), &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptFinal failed");
    }
    final_len += outlen;
    ciphertext.resize(final_len);

    unsigned char tag[TAG_SIZE];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get tag");
    }

    EVP_CIPHER_CTX_free(ctx);

    // Format: IV + Ciphertext + Tag
    std::string blob;
    blob.reserve(IV_SIZE + ciphertext.size() + TAG_SIZE);
    blob.append(reinterpret_cast<const char*>(iv), IV_SIZE);
    blob.append(ciphertext);
    blob.append(reinterpret_cast<const char*>(tag), TAG_SIZE);
    return blob;
}

std::string SecureStorage::Decrypt(const std::string& blob) {
    if (blob.size() < IV_SIZE + TAG_SIZE) {
        throw std::runtime_error("Invalid ciphertext length");
    }

    const unsigned char* iv = reinterpret_cast<const unsigned char*>(blob.data());
    const unsigned char* tag = reinterpret_cast<const unsigned char*>(blob.data() + blob.size() - TAG_SIZE);
    const unsigned char* ciphertext = reinterpret_cast<const unsigned char*>(blob.data() + IV_SIZE);
    int ciphertext_len = blob.size() - IV_SIZE - TAG_SIZE;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create cipher context");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptInit failed");
    }

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key_, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptInit key/iv failed");
    }

    int outlen;
    std::string plaintext(ciphertext_len, '\0');

    if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &outlen,
                          ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptUpdate failed");
    }
    int final_len = outlen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, const_cast<unsigned char*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set expected tag");
    }

    int ret = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[final_len]), &outlen);

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        final_len += outlen;
        plaintext.resize(final_len);
        return plaintext;
    } else {
        throw std::runtime_error("Decryption failed: Integrity check failed (Tag mismatch)");
    }
}

void SecureStorage::EncryptFile(const std::string& src_path, const std::string& dst_path) {
    std::ifstream infile(src_path, std::ios::binary);
    std::ofstream outfile(dst_path, std::ios::binary);
    if (!infile || !outfile) throw std::runtime_error("File open failed");

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, IV_SIZE) != 1) throw std::runtime_error("IV Gen failed");

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key_, iv);

    // Write IV first
    outfile.write(reinterpret_cast<char*>(iv), IV_SIZE);

    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int outlen;

    while (infile.read(reinterpret_cast<char*>(inbuf), sizeof(inbuf))) {
        EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, infile.gcount());
        outfile.write(reinterpret_cast<char*>(outbuf), outlen);
    }
    // Handle last block
    if (infile.gcount() > 0) {
        EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, infile.gcount());
        outfile.write(reinterpret_cast<char*>(outbuf), outlen);
    }

    EVP_EncryptFinal_ex(ctx, outbuf, &outlen);
    outfile.write(reinterpret_cast<char*>(outbuf), outlen);

    unsigned char tag[TAG_SIZE];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag);
    outfile.write(reinterpret_cast<char*>(tag), TAG_SIZE);

    EVP_CIPHER_CTX_free(ctx);
}

void SecureStorage::DecryptFile(const std::string& src_path, const std::string& dst_path) {
    std::ifstream infile(src_path, std::ios::binary);
    std::ofstream outfile(dst_path, std::ios::binary);
    if (!infile || !outfile) throw std::runtime_error("File open failed");

    // Read IV
    unsigned char iv[IV_SIZE];
    infile.read(reinterpret_cast<char*>(iv), IV_SIZE);

    // Calculate ciphertext length (File size - IV - Tag)
    infile.seekg(0, std::ios::end);
    size_t file_size = infile.tellg();
    if (file_size < IV_SIZE + TAG_SIZE) throw std::runtime_error("File too small");
    size_t cipher_len = file_size - IV_SIZE - TAG_SIZE;

    // Read Tag from end
    unsigned char tag[TAG_SIZE];
    infile.seekg(-TAG_SIZE, std::ios::end);
    infile.read(reinterpret_cast<char*>(tag), TAG_SIZE);

    // Reset to start of ciphertext
    infile.seekg(IV_SIZE, std::ios::beg);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key_, iv);

    unsigned char inbuf[4096];
    unsigned char outbuf[4096 + EVP_MAX_BLOCK_LENGTH];
    int outlen;
    size_t processed = 0;

    while (processed < cipher_len) {
        size_t to_read = std::min(sizeof(inbuf), cipher_len - processed);
        infile.read(reinterpret_cast<char*>(inbuf), to_read);

        EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, to_read);
        outfile.write(reinterpret_cast<char*>(outbuf), outlen);
        processed += to_read;
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag);
    int ret = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    outfile.write(reinterpret_cast<char*>(outbuf), outlen);

    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) throw std::runtime_error("File decryption failed (Tag mismatch)");
}

std::vector<unsigned char> SecureStorage::GenerateKey() {
    std::vector<unsigned char> key(KEY_SIZE);
    if (RAND_bytes(key.data(), KEY_SIZE) != 1) {
        throw std::runtime_error("Failed to generate new random key.");
    }
    return key;
}

void SecureStorage::SaveKey(const std::string& path, const std::vector<unsigned char>& key) {
    std::ofstream key_file(path, std::ios::binary | std::ios::trunc);
    if (!key_file.is_open()) {
         throw std::runtime_error("Failed to open key file for writing.");
    }
    key_file.write(reinterpret_cast<const char*>(key.data()), KEY_SIZE);
    // Set strict permissions (0600) in a real environment
    std::filesystem::permissions(path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace);
    key_file.close();
}

void SecureStorage::SetKey(const std::vector<unsigned char>& new_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (new_key.size() != KEY_SIZE) throw std::invalid_argument("Invalid key size");
    std::memcpy(key_, new_key.data(), KEY_SIZE);
}
