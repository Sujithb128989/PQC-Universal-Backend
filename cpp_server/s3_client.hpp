#ifndef S3_CLIENT_HPP
#define S3_CLIENT_HPP

#include <string>
#include "config.hpp"

class S3Client {
public:
    S3Client(const Config::ServerConfig& config);
    ~S3Client();

    // Uploads a file from local path to S3 bucket
    bool UploadFile(const std::string& local_path, const std::string& s3_key);

    // Downloads a file from S3 bucket to local path
    bool DownloadFile(const std::string& s3_key, const std::string& local_path);

private:
    std::string endpoint_;
    std::string bucket_;
    std::string access_key_;
    std::string secret_key_;
    std::string region_;

    // Generates AWS Signature V4 headers
    // Returns a map of headers or modifies curl headers directly
    // For simplicity in MVP, we will implement a basic header signer inside the Put/Get methods.
};

#endif // S3_CLIENT_HPP
