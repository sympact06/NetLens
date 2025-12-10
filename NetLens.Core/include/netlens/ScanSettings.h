// NetLens - Modern Windows Network Scanner
// Copyright (c) 2025 Olivier Flentge
// Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).
// See the LICENSE file in the project root for details.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace netlens {

/// <summary>
/// Configuration settings for a network scan operation.
/// </summary>
struct ScanSettings {
    /// <summary>
    /// Starting IP address for the scan range (e.g., "192.168.1.1").
    /// </summary>
    std::string start_ip;

    /// <summary>
    /// Ending IP address for the scan range (e.g., "192.168.1.254").
    /// </summary>
    std::string end_ip;

    /// <summary>
    /// List of ports to scan on each host.
    /// </summary>
    std::vector<uint16_t> ports;

    /// <summary>
    /// Connection timeout in milliseconds.
    /// </summary>
    uint32_t timeout_ms;

    /// <summary>
    /// Maximum number of concurrent scan operations.
    /// </summary>
    uint32_t max_concurrency;

    ScanSettings()
        : start_ip()
        , end_ip()
        , ports()
        , timeout_ms(1000)
        , max_concurrency(100) {}
};

} // namespace netlens
