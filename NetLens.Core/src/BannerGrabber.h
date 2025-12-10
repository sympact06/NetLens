// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#pragma once

#include <string>
#include <cstdint>

namespace netlens::internal {

/// <summary>
/// Service-specific banner grabbing for common protocols.
/// </summary>
class BannerGrabber {
public:
    /// <summary>
    /// Attempts to grab a service banner from a target host:port.
    /// Creates a new connection, grabs banner, and closes.
    /// </summary>
    /// <param name="ip">Target IP address</param>
    /// <param name="port">Target port number</param>
    /// <param name="timeout_ms">Operation timeout in milliseconds</param>
    /// <returns>Banner string if successful, empty string otherwise</returns>
    static std::string grabBanner(const std::string& ip, 
                                   uint16_t port, 
                                   uint32_t timeout_ms);

private:
    static constexpr size_t MAX_BANNER_SIZE = 1024;
    static constexpr uint32_t MIN_BANNER_TIMEOUT_MS = 100;
    static constexpr uint32_t MAX_BANNER_TIMEOUT_MS = 5000;
};

} // namespace netlens::internal
