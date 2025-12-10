// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#include "TcpScanner.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdexcept>

#pragma comment(lib, "ws2_32.lib")

namespace netlens::internal {

WinsockInitializer::WinsockInitializer() : m_initialized(false) {
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result == 0) {
        m_initialized = true;
    }
}

WinsockInitializer::~WinsockInitializer() {
    if (m_initialized) {
        WSACleanup();
    }
}

uint32_t TcpScanner::clampTimeout(uint32_t timeout_ms) {
    if (timeout_ms < MIN_TIMEOUT_MS) return MIN_TIMEOUT_MS;
    if (timeout_ms > MAX_TIMEOUT_MS) return MAX_TIMEOUT_MS;
    return timeout_ms;
}

bool TcpScanner::isPortOpen(const std::string& ip, uint16_t port, uint32_t timeout_ms) {
    timeout_ms = clampTimeout(timeout_ms);

    // Create socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return false;
    }

    // Set socket to non-blocking mode for timeout control
    u_long mode = 1;
    if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
        closesocket(sock);
        return false;
    }

    // Setup target address
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) {
        closesocket(sock);
        return false;
    }

    // Attempt connection (will return immediately due to non-blocking)
    int connectResult = connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    
    if (connectResult == SOCKET_ERROR) {
        int error = WSAGetLastError();
        
        // WSAEWOULDBLOCK is expected for non-blocking connect
        if (error != WSAEWOULDBLOCK) {
            closesocket(sock);
            return false;
        }

        // Use select to wait for connection with timeout
        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(sock, &writeSet);

        fd_set exceptSet;
        FD_ZERO(&exceptSet);
        FD_SET(sock, &exceptSet);

        timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;

        int selectResult = select(0, nullptr, &writeSet, &exceptSet, &timeout);

        if (selectResult == SOCKET_ERROR || selectResult == 0) {
            // Error or timeout
            closesocket(sock);
            return false;
        }

        // Check if connection succeeded or failed
        if (FD_ISSET(sock, &exceptSet)) {
            // Connection failed
            closesocket(sock);
            return false;
        }

        if (!FD_ISSET(sock, &writeSet)) {
            // Connection not ready
            closesocket(sock);
            return false;
        }

        // Verify the connection actually succeeded
        int optval;
        int optlen = sizeof(optval);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&optval), &optlen) == SOCKET_ERROR) {
            closesocket(sock);
            return false;
        }

        if (optval != 0) {
            // Connection failed
            closesocket(sock);
            return false;
        }
    }

    // Connection successful
    closesocket(sock);
    return true;
}

} // namespace netlens::internal
