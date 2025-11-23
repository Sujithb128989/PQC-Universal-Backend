#ifndef HTTP_GATEWAY_HPP
#define HTTP_GATEWAY_HPP

#include "db_manager.hpp"

// Starts the HTTP server in a blocking loop (intended to be run in a thread)
void RunHTTPServer(DBManager& db_manager, int port);

#endif // HTTP_GATEWAY_HPP
