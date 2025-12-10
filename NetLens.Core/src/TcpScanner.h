// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#pragma once

#include <string>
#include <cstdint>

namespace netlens::internal {

/// <summary>
/// RAII wrapper for Winsock initialization/cleanup.
/// </summary>
class WinsockInitializer {
public:
    WinsockInitializer();
    ~WinsockInitializer();

    WinsockInitializer(const WinsockInitializer&) = delete;
    WinsockInitializer& operator=(const WinsockInitializer&) = delete;

    bool isInitialized() const { return m_initialized; }

private:
    bool m_initialized;
};

/// <summary>
/// Performs a single TCP connection attempt to check if a port is open.
/// </summary>
class TcpScanner {
public:
    /// <summary>
    /// Attempts to connect to a specific IP and port with a timeout.
    /// </summary>
    /// <param name="ip">Target IPv4 address</param>
    /// <param name="port">Target TCP port</param>
    /// <param name="timeout_ms">Connection timeout in milliseconds</param>
    /// <returns>True if the port is open (connection successful), false otherwise</returns>
    static bool isPortOpen(const std::string& ip, uint16_t port, uint32_t timeout_ms);

private:
    static constexpr uint32_t MIN_TIMEOUT_MS = 50;
    static constexpr uint32_t MAX_TIMEOUT_MS = 30000;
    static constexpr uint32_t DEFAULT_TIMEOUT_MS = 1000;

    static uint32_t clampTimeout(uint32_t timeout_ms);
};

} // namespace netlens::internal
