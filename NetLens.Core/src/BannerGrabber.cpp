// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#include "BannerGrabber.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <algorithm>
#include <sstream>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

namespace netlens::internal {

std::string BannerGrabber::grabBanner(const std::string& ip, uint16_t port, uint32_t timeout_ms) {
    // Clamp timeout
    if (timeout_ms < MIN_BANNER_TIMEOUT_MS) timeout_ms = MIN_BANNER_TIMEOUT_MS;
    if (timeout_ms > MAX_BANNER_TIMEOUT_MS) timeout_ms = MAX_BANNER_TIMEOUT_MS;

    // Create socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return "";
    }

    // Set timeout
    DWORD timeout = timeout_ms;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));

    // Setup target address
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        closesocket(sock);
        return "";
    }

    // Connect
    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return "";
    }

    std::string banner;
    char buffer[MAX_BANNER_SIZE];

    // Protocol-specific banner grabbing
    switch (port) {
        case 22: // SSH
        case 21: // FTP
        case 25: // SMTP
            // These services send banner first
            {
                int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (received > 0) {
                    buffer[received] = '\0';
                    banner = std::string(buffer, received);
                    // Extract first line
                    size_t newline = banner.find_first_of("\r\n");
                    if (newline != std::string::npos) {
                        banner = banner.substr(0, newline);
                    }
                }
            }
            break;

        case 80: // HTTP
        case 8000:
        case 8080:
        case 8443:
            // HTTP - send request first
            {
                const char* request = "GET / HTTP/1.0\r\nHost: scan\r\nUser-Agent: NetLens/1.0\r\n\r\n";
                send(sock, request, static_cast<int>(std::strlen(request)), 0);

                int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (received > 0) {
                    buffer[received] = '\0';
                    std::string response(buffer, received);
                    
                    // Parse HTTP response
                    std::istringstream iss(response);
                    std::string http_version, status_code;
                    iss >> http_version >> status_code;

                    banner = http_version + " " + status_code;

                    // Look for Server header
                    size_t server_pos = response.find("Server:");
                    if (server_pos == std::string::npos) {
                        server_pos = response.find("server:");
                    }
                    if (server_pos != std::string::npos) {
                        size_t line_end = response.find("\r\n", server_pos);
                        if (line_end != std::string::npos) {
                            std::string server_line = response.substr(server_pos + 7, line_end - server_pos - 7);
                            // Trim whitespace
                            server_line.erase(0, server_line.find_first_not_of(" \t"));
                            server_line.erase(server_line.find_last_not_of(" \t\r\n") + 1);
                            if (!server_line.empty()) {
                                banner += " (" + server_line + ")";
                            }
                        }
                    }
                }
            }
            break;

        case 443: // HTTPS
            banner = "HTTPS (TLS)";
            break;

        default:
            // Try to read any data
            {
                int received = recv(sock, buffer, sizeof(buffer) - 1, 0);
                if (received > 0) {
                    buffer[received] = '\0';
                    banner = std::string(buffer, received);
                    // Limit length
                    if (banner.length() > 100) {
                        banner = banner.substr(0, 100) + "...";
                    }
                    // Extract first line
                    size_t newline = banner.find_first_of("\r\n");
                    if (newline != std::string::npos) {
                        banner = banner.substr(0, newline);
                    }
                }
            }
            break;
    }

    closesocket(sock);
    return banner;
}

} // namespace netlens::internal
