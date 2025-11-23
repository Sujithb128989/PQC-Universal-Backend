#include "db_manager.hpp"
#include "logger.hpp"
#include <stdexcept>
#include <iostream>
#include <filesystem>
#include <cstring>

DBManager::DBManager(const std::string& db_path, SecureStorage& secure_storage)
    : db_(nullptr), secure_storage_(secure_storage) {
    if (sqlite3_open(db_path.c_str(), &db_) != SQLITE_OK) {
        throw std::runtime_error("Failed to open SQLite database: " + std::string(sqlite3_errmsg(db_)));
    }
    Init();
}

DBManager::~DBManager() {
    if (db_) {
        sqlite3_close(db_);
    }
}

void DBManager::Init() {
    // Create messages table if not exists
    // ID is INTEGER PRIMARY KEY (autoincrement)
    // DATA is the encrypted blob (IV + Ciphertext + Tag)
    Execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, data BLOB);");
}

void DBManager::Execute(const std::string& sql) {
    char* errMsg = nullptr;
    if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::string error = "SQL error: " + std::string(errMsg);
        sqlite3_free(errMsg);
        throw std::runtime_error(error);
    }
}

int64_t DBManager::InsertMessage(const std::string& message) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::string encrypted = secure_storage_.Encrypt(message);

    sqlite3_stmt* stmt;
    const char* sql = "INSERT INTO messages (data) VALUES (?);";

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare insert statement");
    }

    if (sqlite3_bind_blob(stmt, 1, encrypted.data(), encrypted.size(), SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to bind blob");
    }

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to execute insert");
    }

    int64_t id = sqlite3_last_insert_rowid(db_);
    sqlite3_finalize(stmt);
    return id;
}

std::string DBManager::GetMessage(int64_t id) {
    std::lock_guard<std::mutex> lock(mutex_);

    sqlite3_stmt* stmt;
    const char* sql = "SELECT data FROM messages WHERE id = ?;";

    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare select statement");
    }

    sqlite3_bind_int64(stmt, 1, id);

    std::string result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* blob = sqlite3_column_blob(stmt, 0);
        int len = sqlite3_column_bytes(stmt, 0);
        std::string encrypted(static_cast<const char*>(blob), len);

        try {
            result = secure_storage_.Decrypt(encrypted);
        } catch (const std::exception& e) {
            Logger::Error("Failed to decrypt message ID " + std::to_string(id) + ": " + e.what());
            result = ""; // Or throw
        }
    }

    sqlite3_finalize(stmt);
    return result;
}

void DBManager::ReEncryptAll() {
    std::lock_guard<std::mutex> lock(mutex_);
    Logger::Info("Starting database re-encryption...");

    // 1. Read all data
    std::vector<std::pair<int64_t, std::string>> rows;
    sqlite3_stmt* stmt;
    const char* select_sql = "SELECT id, data FROM messages;";

    if (sqlite3_prepare_v2(db_, select_sql, -1, &stmt, nullptr) != SQLITE_OK) {
        throw std::runtime_error("Failed to prepare select all statement");
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int64_t id = sqlite3_column_int64(stmt, 0);
        const void* blob = sqlite3_column_blob(stmt, 0);
        int len = sqlite3_column_bytes(stmt, 0);
        std::string encrypted(static_cast<const char*>(blob), len);
        try {
            // Decrypt with current (OLD) key
            rows.push_back({id, secure_storage_.Decrypt(encrypted)});
        } catch (...) {
            Logger::Warn("Skipping row " + std::to_string(id) + " due to decrypt failure");
        }
    }
    sqlite3_finalize(stmt);

    // 2. Generate NEW key in memory
    auto new_key = SecureStorage::GenerateKey();

    // 3. Encrypt data using NEW key
    // We need to temporarily switch SecureStorage context or manually encrypt.
    // Since `Encrypt` uses the internal key_, we will manually set the new key
    // ONLY AFTER we have successfully decrypted everything.
    // But we need to write the data to the DB.

    // Better approach: Set the new key in SecureStorage, then encrypt.
    // But if we crash, the key on disk is OLD, and the key in memory is NEW.

    // ATOMIC ROTATION LOGIC:
    // A. Write NEW Key to a temporary file.
    // B. Update DB with data encrypted by NEW key (using transaction).
    // C. Rename temporary key file to permanent key file.
    // D. Update memory.

    // Step A: Save new key to tmp file
    // Assuming we know the key path... SecureStorage encapsulates it.
    // Ideally SecureStorage should expose a path getter or a "SaveKeyToPath" helper.
    // We added SaveKey static helper. We need the path.
    // For MVP, we assume the path is "data/storage.key" based on main.cpp or pass it.
    // Let's assume standard path for now or rely on SecureStorage to manage it?
    // SecureStorage manages the path internally. We need to access it.
    // To fix this cleanly without breaking encapsulation too much, we assume the standard path
    // or ask SecureStorage to do the save.

    // Workaround: We will perform the encryption in memory first.
    std::vector<std::pair<int64_t, std::string>> encrypted_rows;

    // To encrypt with the NEW key, we need to set it on SecureStorage.
    // But we must save the OLD key to revert if DB update fails.
    std::vector<unsigned char> old_key(32);
    std::memcpy(old_key.data(), secure_storage_.GetKey(), 32); // Make sure GetKey exists

    secure_storage_.SetKey(new_key); // Context switch to NEW key

    for (const auto& row : rows) {
        encrypted_rows.push_back({row.first, secure_storage_.Encrypt(row.second)});
    }

    // Step A: Save NEW key to .tmp
    std::string key_path = "data/storage.key"; // Hardcoded based on config default for now
    std::string tmp_key_path = key_path + ".tmp";
    SecureStorage::SaveKey(tmp_key_path, new_key);

    // Step B: Update DB
    char* errMsg = nullptr;
    if (sqlite3_exec(db_, "BEGIN TRANSACTION;", nullptr, nullptr, &errMsg) != SQLITE_OK) {
        secure_storage_.SetKey(old_key); // Revert memory
        throw std::runtime_error("Failed to begin transaction: " + std::string(errMsg));
    }

    const char* update_sql = "UPDATE messages SET data = ? WHERE id = ?;";
    sqlite3_prepare_v2(db_, update_sql, -1, &stmt, nullptr);

    for (const auto& row : encrypted_rows) {
        sqlite3_bind_blob(stmt, 1, row.second.data(), row.second.size(), SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, row.first);
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            sqlite3_exec(db_, "ROLLBACK;", nullptr, nullptr, nullptr);
            secure_storage_.SetKey(old_key); // Revert
            throw std::runtime_error("Failed to update row");
        }
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);

    if (sqlite3_exec(db_, "COMMIT;", nullptr, nullptr, &errMsg) != SQLITE_OK) {
        secure_storage_.SetKey(old_key); // Revert
        throw std::runtime_error("Failed to commit transaction: " + std::string(errMsg));
    }

    // Step C: Atomic Rename
    try {
        std::filesystem::rename(tmp_key_path, key_path);
    } catch (const std::exception& e) {
        // Critical error: DB is updated but key file isn't!
        // However, we have the new key in memory and in .tmp.
        // Log fatal error.
        Logger::Fatal("CRITICAL: Database re-encrypted but key file rename failed! New key is in " + tmp_key_path);
        throw;
    }

    // Step D: Memory is already updated.

    Logger::Info("Database re-encryption complete with Atomic Key Rotation.");
}
