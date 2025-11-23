#ifndef DB_MANAGER_HPP
#define DB_MANAGER_HPP

#include <string>
#include <vector>
#include <mutex>
#include <sqlite3.h>
#include "secure_storage.hpp"

class DBManager {
public:
    DBManager(const std::string& db_path, SecureStorage& secure_storage);
    ~DBManager();

    // Inserts an encrypted message and returns its ID
    int64_t InsertMessage(const std::string& message);

    // Retrieves a decrypted message by ID
    std::string GetMessage(int64_t id);

    // Re-encrypts all data with the current key in SecureStorage
    void ReEncryptAll();

private:
    sqlite3* db_;
    SecureStorage& secure_storage_;
    std::mutex mutex_;

    void Init();
    void Execute(const std::string& sql);
};

#endif // DB_MANAGER_HPP
