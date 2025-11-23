#include "http_gateway.hpp"
#include "httplib.h"
#include "logger.hpp"
#include "config.hpp"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

void RunHTTPServer(DBManager& db_manager, int port) {
    httplib::Server svr;

    // Middleware for CORS and Auth
    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, X-API-Key");

        if (req.method == "OPTIONS") {
            res.status = 204;
            return httplib::Server::HandlerResponse::Handled;
        }

        // Check Auth for API routes
        if (req.path.find("/api/") == 0) {
            const auto& config = Config::Instance().Get();
            // Enforce auth if key is set (default "changeme" implies open dev mode, but let's enforce checks)
            if (config.http_api_key != "changeme") {
                if (!req.has_header("X-API-Key") || req.get_header_value("X-API-Key") != config.http_api_key) {
                    res.status = 401;
                    res.set_content("{\"error\": \"Unauthorized\"}", "application/json");
                    return httplib::Server::HandlerResponse::Handled;
                }
            }
        }

        return httplib::Server::HandlerResponse::Unhandled;
    });

    // Serve static files from /app/www
    svr.set_mount_point("/", "/app/www");

    // GET /health (Public)
    svr.Get("/health", [](const httplib::Request&, httplib::Response& res) {
        json j;
        j["status"] = "SERVING";
        res.set_content(j.dump(), "application/json");
    });

    // POST /api/store
    svr.Post("/api/store", [&](const httplib::Request& req, httplib::Response& res) {
        try {
            auto j = json::parse(req.body);
            if (!j.contains("message")) {
                res.status = 400;
                res.set_content("{\"error\": \"Missing 'message' field\"}", "application/json");
                return;
            }
            std::string message = j["message"];
            int64_t id = db_manager.InsertMessage(message);

            json response;
            response["id"] = id;
            res.set_content(response.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            json err;
            err["error"] = e.what();
            res.set_content(err.dump(), "application/json");
        }
    });

    // GET /api/retrieve?id=...
    svr.Get("/api/retrieve", [&](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_param("id")) {
            res.status = 400;
            res.set_content("{\"error\": \"Missing 'id' parameter\"}", "application/json");
            return;
        }

        try {
            int64_t id = std::stoll(req.get_param_value("id"));
            std::string message = db_manager.GetMessage(id);

            if (message.empty()) {
                res.status = 404;
                res.set_content("{\"error\": \"Message not found\"}", "application/json");
                return;
            }

            json response;
            response["message"] = message;
            res.set_content(response.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            json err;
            err["error"] = e.what();
            res.set_content(err.dump(), "application/json");
        }
    });

    Logger::Info("HTTP Gateway listening on port " + std::to_string(port));
    svr.listen("0.0.0.0", port);
}
