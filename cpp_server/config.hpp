#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <string>
#include <nlohmann/json.hpp>

class Config {
public:
    struct ServerConfig {
        std::string address = "0.0.0.0:50051";
        std::string storage_path = "data/storage.bin";
        std::string key_path = "data/storage.key";
        std::string log_level = "INFO";
        std::string http_api_key = "changeme"; // Simple API Key for HTTP Gateway

        // S3 Configuration
        std::string s3_endpoint = ""; // e.g., "s3.amazonaws.com" or "localhost:9000"
        std::string s3_bucket = "";
        std::string s3_access_key = "";
        std::string s3_secret_key = "";
        std::string s3_region = "us-east-1";
        bool use_s3 = false;
    };

    static Config& Instance();

    void Load(const std::string& path);
    const ServerConfig& Get() const;

private:
    Config() = default;
    ServerConfig config_;
};

#endif // CONFIG_HPP
